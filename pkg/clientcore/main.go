// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package clientcore

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/bschaatsbergen/dnsdialer"
	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/transport/v4"
	"github.com/pion/turn/v5"
	"github.com/xtaci/smux"
)

type getCredsFunc func(ctx context.Context, link string, streamID int) (string, string, string, error)

type directNet struct{}

type directDialer struct {
	*net.Dialer
}

type directListenConfig struct {
	*net.ListenConfig
}

// Global state trackers
var (
	activeLocalPeer      atomic.Value
	globalCaptchaLockout atomic.Int64
	connectedStreams     atomic.Int32
	globalAppCancel      context.CancelFunc
	handshakeSem         = make(chan struct{}, 3)
	isDebug              bool
	manualCaptcha        bool
	autoCaptchaSliderPOC bool
	captchaSolverVersion string
)

func debugf(format string, v ...any) {
	if isDebug {
		log.Printf(format, v...)
	}
}

type captchaSolveMode int

const (
	captchaSolveModeAuto captchaSolveMode = iota
	captchaSolveModeSliderPOC
	captchaSolveModeManual
)

func captchaSolveModeForAttempt(attempt int, manualOnly bool, enableSliderPOC bool) (captchaSolveMode, bool) {
	if manualOnly {
		return captchaSolveModeManual, attempt == 0
	}

	switch attempt {
	case 0:
		return captchaSolveModeAuto, true
	case 1:
		if enableSliderPOC {
			return captchaSolveModeSliderPOC, true
		}
		return captchaSolveModeManual, true
	case 2:
		if enableSliderPOC {
			return captchaSolveModeManual, true
		}
	}

	return 0, false
}

func captchaSolveModeLabel(mode captchaSolveMode) string {
	switch mode {
	case captchaSolveModeAuto:
		return "auto captcha"
	case captchaSolveModeSliderPOC:
		return "auto captcha slider POC"
	case captchaSolveModeManual:
		return "manual captcha"
	default:
		return "captcha"
	}
}

type UDPPacket struct {
	Data []byte
	N    int
}

var packetPool = sync.Pool{
	New: func() any { return &UDPPacket{Data: make([]byte, 2048)} },
}

type throughputStats struct {
	tx atomic.Uint64
	rx atomic.Uint64
}

func (s *throughputStats) addTx(n int) {
	if n > 0 {
		s.tx.Add(uint64(n))
	}
}

func (s *throughputStats) addRx(n int) {
	if n > 0 {
		s.rx.Add(uint64(n))
	}
}

func (s *throughputStats) logEvery(ctx context.Context, label, txName, rxName string) {
	if !isDebug {
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var prevTx, prevRx uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tx := s.tx.Load()
			rx := s.rx.Load()
			deltaTx := tx - prevTx
			deltaRx := rx - prevRx
			prevTx = tx
			prevRx = rx

			if deltaTx == 0 && deltaRx == 0 {
				continue
			}

			debugf(
				"%s throughput: %s=%s %s=%s total_%s=%s total_%s=%s",
				label,
				txName,
				formatBitsPerSecond(deltaTx, 5*time.Second),
				rxName,
				formatBitsPerSecond(deltaRx, 5*time.Second),
				txName,
				formatByteCount(tx),
				rxName,
				formatByteCount(rx),
			)
		}
	}
}

func formatBitsPerSecond(bytes uint64, interval time.Duration) string {
	if interval <= 0 {
		interval = time.Second
	}

	bps := float64(bytes*8) / interval.Seconds()
	if bps >= 1_000_000 {
		return fmt.Sprintf("%.2f Mbit/s", bps/1_000_000)
	}
	if bps >= 1_000 {
		return fmt.Sprintf("%.1f kbit/s", bps/1_000)
	}
	return fmt.Sprintf("%.0f bit/s", bps)
}

func formatByteCount(bytes uint64) string {
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.2f MiB", float64(bytes)/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%.1f KiB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%d B", bytes)
}

type countingConn struct {
	net.Conn
	stats *throughputStats
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.stats.addRx(n)
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.stats.addTx(n)
	return n, err
}

func newDirectNet() transport.Net {
	return directNet{}
}

func (directNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func (directNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.ListenUDP(network, locAddr)
}

func (directNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	return directTCPListener{listener}, nil
}

func (directNet) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func (directNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}

func (directNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
}

func (directNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	return net.ResolveIPAddr(network, address)
}

func (directNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr(network, address)
}

func (directNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr(network, address)
}

func (directNet) Interfaces() ([]*transport.Interface, error) {
	return nil, transport.ErrNotSupported
}

func (directNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: index=%d", transport.ErrInterfaceNotFound, index)
}

func (directNet) InterfaceByName(name string) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: %s", transport.ErrInterfaceNotFound, name)
}

func (directNet) CreateDialer(dialer *net.Dialer) transport.Dialer {
	return directDialer{Dialer: dialer}
}

func (directNet) CreateListenConfig(listenerConfig *net.ListenConfig) transport.ListenConfig {
	return directListenConfig{ListenConfig: listenerConfig}
}

func (d directDialer) Dial(network, address string) (net.Conn, error) {
	return d.Dialer.Dial(network, address)
}

func (d directListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return d.ListenConfig.Listen(ctx, network, address)
}

func (d directListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return d.ListenConfig.ListenPacket(ctx, network, address)
}

type directTCPListener struct {
	*net.TCPListener
}

func (l directTCPListener) AcceptTCP() (transport.TCPConn, error) {
	return l.TCPListener.AcceptTCP()
}

// region Helper: HTTP Headers Injection

// applyBrowserProfile applies consistent User-Agent and Client Hints to bypass WAFs
func applyBrowserProfile(req *http.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

func generateBrowserFp(profile Profile) string {
	// Fallback logic for generating a fingerprint if no saved profile is available.
	// This uses a simple MD5 hash of UA and a fixed resolution.
	data := profile.UserAgent + profile.SecChUa + "1536x864x24"
	h := md5.Sum([]byte(data))
	return hex.EncodeToString(h[:])
}

/*
func generateFakeCursor() string {
	startX := 600 + rand.Intn(400)
	startY := 300 + rand.Intn(200)
	startTime := time.Now().UnixMilli() - int64(rand.Intn(2000)+1000)
	var points []string
	for i := 0; i < 15+rand.Intn(10); i++ {
		startX += rand.Intn(15) - 5
		startY += rand.Intn(15) + 2
		startTime += int64(rand.Intn(40) + 10)
		points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, startX, startY, startTime))
	}
	return "[" + strings.Join(points, ",") + "]"
}

// generateCheckboxCursor simulates a mouse moving from a random starting position
// towards the VK captcha checkbox area, decelerating as it approaches the target.
// This looks more like a real click than either a stationary cursor or pure random jitter.
func generateCheckboxCursor() string {
	type point struct {
		X int   `json:"x"`
		Y int   `json:"y"`
		T int64 `json:"t"`
	}

	// Target is roughly where VK renders the checkbox
	targetX := 290 + rand.Intn(20) - 10
	targetY := 437 + rand.Intn(10) - 5

	// Starting position: somewhere to the upper-right of the checkbox
	startX := targetX + 200 + rand.Intn(300)
	startY := targetY - 80 - rand.Intn(120)

	steps := 14 + rand.Intn(6)
	startTime := time.Now().Add(-time.Duration(400+rand.Intn(600)) * time.Millisecond).UnixMilli()

	points := make([]point, 0, steps)
	for i := 0; i < steps; i++ {
		// Ease-out: fast at start, slow near target
		t := float64(i) / float64(steps-1)
		ease := 1 - (1-t)*(1-t)
		x := startX + int(float64(targetX-startX)*ease) + rand.Intn(5) - 2
		y := startY + int(float64(targetY-startY)*ease) + rand.Intn(5) - 2
		dt := int64(15 + rand.Intn(25) + int(20*t)) // slower near target
		startTime += dt
		points = append(points, point{X: x, Y: y, T: startTime})
	}

	data, err := json.Marshal(points)
	if err != nil {
		return "[]"
	}
	return string(data)
}
*/

func getCustomNetDialer() net.Dialer {
	return net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				dnsServers := []string{"77.88.8.8:53", "77.88.8.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"}
				var lastErr error
				for _, dns := range dnsServers {
					conn, err := d.DialContext(ctx, "udp", dns)
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				return nil, lastErr
			},
		},
	}
}

// endregion

// region Automatic Captcha Solver & Authentication

type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectURI             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string
	CaptchaAttempt          string
}

func parseVKErrorCode(value interface{}) (int, bool) {
	switch v := value.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case json.Number:
		n, err := v.Int64()
		return int(n), err == nil
	case string:
		n, err := strconv.Atoi(v)
		return n, err == nil
	default:
		return 0, false
	}
}

func parseVKString(value interface{}) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, v != ""
	case float64:
		return fmt.Sprintf("%.0f", v), true
	case int:
		return strconv.Itoa(v), true
	case json.Number:
		return v.String(), v.String() != ""
	default:
		return "", false
	}
}

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	// Extract error_code
	code, ok := parseVKErrorCode(errData["error_code"])
	if !ok {
		log.Printf("missing error_code in captcha error data")
		return nil
	}

	// Extract captcha_sid
	captchaSid, _ := parseVKString(errData["captcha_sid"])
	if captchaSid == "" {
		log.Printf("captcha_sid not present in captcha error data")
	}

	// Extract captcha_img
	captchaImg, _ := parseVKString(errData["captcha_img"])
	if captchaImg == "" {
		log.Printf("captcha_img not present in captcha error data")
	}

	// Extract error_msg
	errorMsg, _ := parseVKString(errData["error_msg"])
	if errorMsg == "" {
		log.Printf("error_msg not present in captcha error data")
	}

	// Extract redirect_uri
	RedirectURI, _ := parseVKString(errData["redirect_uri"])

	// Extract session token
	var sessionToken string
	if RedirectURI != "" {
		if parsed, err := neturl.Parse(RedirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		} else {
			log.Printf("failed to parse redirect_uri: %v", err)
			return nil
		}
	}
	// Fallback to top-level session_token field if not in redirect_uri
	if sessionToken == "" {
		if st, stOk := errData["session_token"].(string); stOk {
			sessionToken = st
		}
	}
	if RedirectURI == "" && captchaImg == "" {
		log.Printf("missing redirect_uri and captcha_img in captcha error data")
		return nil
	}
	if RedirectURI != "" && sessionToken == "" {
		log.Printf("missing session_token in captcha redirect_uri")
		return nil
	}

	// Extract is_sound_captcha_available
	isSound, ok := errData["is_sound_captcha_available"].(bool)
	if !ok {
		isSound = false
	}

	// Extract captcha_ts
	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	// Extract captcha_attempt
	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	// Build VkCaptchaError
	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectURI:             RedirectURI,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && ((e.RedirectURI != "" && e.SessionToken != "") || e.CaptchaImg != "")
}

func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile Profile, useSliderPOC bool) (string, error) {
	if useSliderPOC {
		log.Printf("[STREAM %d] [Captcha] Solving captcha with slider POC...", streamID)
	} else {
		log.Printf("[STREAM %d] [Captcha] Solving captcha...", streamID)
	}

	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri for auto-solve")
	}
	if captchaErr.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri for auto-solve")
	}

	// Try to load saved profile from disk
	var savedProfile *SavedProfile
	if sp, err := LoadProfileFromDisk(); err == nil {
		log.Printf("[STREAM %d] [Captcha] Using saved real browser profile", streamID)
		savedProfile = sp
		profile = sp.Profile // Use saved headers/UA
	}

	if !useSliderPOC && !strings.EqualFold(captchaSolverVersion, "v1") {
		successToken, v2Err := solveVkCaptchaV2(ctx, captchaErr, streamID, client, profile, savedProfile)
		if v2Err == nil {
			log.Printf("[STREAM %d] [Captcha] v2 solver succeeded", streamID)
			return successToken, nil
		}
		if errors.Is(v2Err, errCaptchaV2RateLimit) {
			return "", v2Err
		}
		log.Printf("[STREAM %d] [Captcha] v2 solver failed, falling back to legacy solver: %v", streamID, v2Err)
	}

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	log.Printf("[STREAM %d] [Captcha] PoW input: %s, difficulty: %d", streamID, bootstrap.PowInput, bootstrap.Difficulty)

	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	log.Printf("[STREAM %d] [Captcha] PoW solved: hash=%s", streamID, hash)

	var successToken string
	if useSliderPOC {
		successToken, err = callCaptchaNotRobotWithSliderPOC(
			ctx,
			captchaErr.SessionToken,
			hash,
			streamID,
			client,
			profile,
			bootstrap.Settings,
			savedProfile, // Pass savedProfile if available
		)
	} else {
		successToken, err = callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, streamID, client, profile, savedProfile)
	}
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	log.Printf("[STREAM %d] [Captcha] Success! Got success_token", streamID)
	return successToken, nil
}

func fetchCaptchaBootstrap(ctx context.Context, redirectURI string, client tlsclient.HttpClient, profile Profile) (*captchaBootstrap, error) {
	parsedURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Hostname()

	req, err := fhttp.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return nil, err
	}

	req.Host = domain
	applyBrowserProfileFhttp(req, profile)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseCaptchaBootstrapHTML(string(body))
}

func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}
	return ""
}

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash string, streamID int, client tlsclient.HttpClient, profile Profile, savedProfile *SavedProfile) (string, error) {
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		parsedURL, err := neturl.Parse(reqURL)
		if err != nil {
			return nil, fmt.Errorf("parse request URL: %w", err)
		}
		domain := parsedURL.Hostname()

		req, err := fhttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}

		req.Host = domain
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://api.vk.ru")
		req.Header.Set("Referer", fmt.Sprintf("https://api.vk.ru/not_robot_captcha?domain=vk.com&session_token=%s&variant=popup&blank=1", sessionToken))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(httpResp.Body)

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	adFpBytes := make([]byte, 16)
	for i := range adFpBytes {
		adFpBytes[i] = byte(rand.Intn(256))
	}
	adFp := base64.RawURLEncoding.EncodeToString(adFpBytes)[:21]

	baseParams := fmt.Sprintf("session_token=%s&domain=vk.com&adFp=%s&access_token=", neturl.QueryEscape(sessionToken), neturl.QueryEscape(adFp))

	log.Printf("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	if _, err := vkReq("captchaNotRobot.settings", baseParams); err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}

	time.Sleep(200 * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 2/4: componentDone", streamID)
	browserFp := generateBrowserFp(profile)
	deviceJSON := buildCaptchaDeviceJSON(profile)
	if savedProfile != nil {
		browserFp = savedProfile.BrowserFp
		deviceJSON = savedProfile.DeviceJSON
	}
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, neturl.QueryEscape(deviceJSON))

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}

	time.Sleep(200 * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 3/4: check", streamID)
	// The real browser sends an empty array for cursor on the first check.
	cursorJSON := "[]"
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	// The real browser sends a static SHA-256 hash for debug_info.
	// We use the exact one captured from the real browser's session.
	debugInfo := "f3ef768dab7a20f574c6461f34e4257894d2a3c30a53d8727a3edaf7ab70847d"

	connectionRtt := "[250,250,250,250,250]"
	connectionDownlink := "[1.45,1.45,1.45,1.45,1.45]"

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON), neturl.QueryEscape("[]"), neturl.QueryEscape(connectionRtt),
		neturl.QueryEscape(connectionDownlink),
		browserFp, hash, answer, debugInfo,
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}
	status, ok := respObj["status"].(string)
	if !ok || status != "OK" {
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found")
	}

	time.Sleep(200 * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 4/4: endSession", streamID)
	_, err = vkReq("captchaNotRobot.endSession", baseParams)
	if err != nil {
		log.Printf("[STREAM %d] [Captcha] Warning: endSession failed: %v", streamID, err)
	}

	return successToken, nil
}

// endregion

// region VK Credentials Layer

type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

var vkCredentialsList = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"},  // VK_WEB_APP_ID
	{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"},  // VK_MVK_APP_ID
	{ClientID: "52461373", ClientSecret: "o557NLIkAErNhakXrQ7A"}, // VK_WEB_VKVIDEO_APP_ID
	{ClientID: "52649896", ClientSecret: "WStp4ihWG4l3nmXZgIbC"}, // VK_MVK_VKVIDEO_APP_ID
	{ClientID: "51781872", ClientSecret: "IjjCNl4L4Tf5QZEXIHKK"}, // VK_ID_AUTH_APP
}

type TurnCredentials struct {
	Username    string
	Password    string
	ServerAddrs []string
	ExpiresAt   time.Time
	Link        string
}

type StreamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.RWMutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
	turnServerCooldown = 30 * time.Second
)

var streamsPerCache = 10

func getCacheID(streamID int) int {
	return streamID / streamsPerCache
}

func vkDelayRandom(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

var streamServerOffsets sync.Map // map[int]*atomic.Uint64
var turnServerCooldowns sync.Map // map[string]*atomic.Int64

func streamServerOffset(streamID int) *atomic.Uint64 {
	v, _ := streamServerOffsets.LoadOrStore(streamID, &atomic.Uint64{})
	offset, ok := v.(*atomic.Uint64)
	if !ok {
		panic(fmt.Sprintf("unexpected streamServerOffsets value type: %T", v))
	}
	return offset
}

func turnServerCooldownUntil(addr string) *atomic.Int64 {
	v, _ := turnServerCooldowns.LoadOrStore(addr, &atomic.Int64{})
	until, ok := v.(*atomic.Int64)
	if !ok {
		panic(fmt.Sprintf("unexpected turnServerCooldowns value type: %T", v))
	}
	return until
}

func getStreamServerOffset(streamID int) uint64 {
	return streamServerOffset(streamID).Load()
}

func rotateStreamServer(streamID int) uint64 {
	return streamServerOffset(streamID).Add(1)
}

func pickStreamServerAddr(streamID int, addrs []string) string {
	start := (uint64(streamID) + getStreamServerOffset(streamID)) % uint64(len(addrs))
	for i := uint64(0); i < uint64(len(addrs)); i++ {
		idx := (start + i) % uint64(len(addrs))
		addr := addrs[idx]
		if isTURNServerAvailable(addr) {
			return addr
		}
	}
	return addrs[start]
}

func markTURNServerCooldown(addr string) {
	turnServerCooldownUntil(addr).Store(time.Now().Add(turnServerCooldown).UnixNano())
}

func isTURNServerAvailable(addr string) bool {
	v, ok := turnServerCooldowns.Load(addr)
	if !ok {
		return true
	}
	until, ok := v.(*atomic.Int64)
	if !ok {
		panic(fmt.Sprintf("unexpected turnServerCooldowns value type: %T", v))
	}
	return time.Now().UnixNano() >= until.Load()
}

func getStreamCache(streamID int) *StreamCredentialsCache {
	cacheID := getCacheID(streamID)

	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[cacheID]
	credentialsStore.mu.RUnlock()

	if exists {
		return cache
	}

	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	if cache, exists = credentialsStore.caches[cacheID]; exists {
		return cache
	}

	cache = &StreamCredentialsCache{}
	credentialsStore.caches[cacheID] = cache
	return cache
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "invalid credential") ||
		strings.Contains(errStr, "stale nonce")
}

func handleAuthError(streamID int) bool {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	now := time.Now().Unix()

	if now-cache.lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}

	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)

	log.Printf("[STREAM %d] Auth error (cache=%d, count=%d/%d)", streamID, cacheID, count, maxCacheErrors)

	if count >= maxCacheErrors {
		log.Printf("[VK Auth] Multiple auth errors detected (%d), invalidating cache %d for stream %d...", count, cacheID, streamID)
		cache.invalidate(streamID)
		return true
	}
	return false
}

func (c *StreamCredentialsCache) invalidate(streamID int) {
	c.mutex.Lock()
	c.creds = TurnCredentials{}
	c.mutex.Unlock()

	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)

	log.Printf("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
}

func getVkCredsCached(ctx context.Context, link string, streamID int, dialer *dnsdialer.Dialer) (string, string, string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.RLock()
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) && len(cache.creds.ServerAddrs) > 0 {
		expires := time.Until(cache.creds.ExpiresAt)
		u, p := cache.creds.Username, cache.creds.Password
		addr := pickStreamServerAddr(streamID, cache.creds.ServerAddrs)
		cache.mutex.RUnlock()
		if isDebug {
			log.Printf("[STREAM %d] [VK Auth] Using cached credentials (cache=%d, expires in %v, server=%s)", streamID, cacheID, expires, addr)
		}
		return u, p, addr, nil
	}
	cache.mutex.RUnlock()

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Double-check inside lock
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) && len(cache.creds.ServerAddrs) > 0 {
		addr := pickStreamServerAddr(streamID, cache.creds.ServerAddrs)
		return cache.creds.Username, cache.creds.Password, addr, nil
	}

	user, pass, addrs, err := fetchVkCredsSerialized(ctx, link, streamID, dialer)
	if err != nil {
		return "", "", "", err
	}

	cache.creds = TurnCredentials{Username: user, Password: pass, ServerAddrs: addrs, ExpiresAt: time.Now().Add(credentialLifetime - cacheSafetyMargin), Link: link}
	addr := pickStreamServerAddr(streamID, addrs)
	return user, pass, addr, nil
}

var (
	vkRequestMu           sync.Mutex
	globalLastVkFetchTime time.Time
)

func fetchVkCredsSerialized(ctx context.Context, link string, streamID int, dialer *dnsdialer.Dialer) (string, string, []string, error) {
	vkRequestMu.Lock()
	defer vkRequestMu.Unlock()

	// Ensure a minimum cooldown between credential requests to avoid VK rate limits
	minInterval := 3*time.Second + time.Duration(rand.Intn(3000))*time.Millisecond
	elapsed := time.Since(globalLastVkFetchTime)

	if !globalLastVkFetchTime.IsZero() && elapsed < minInterval {
		wait := minInterval - elapsed
		log.Printf("[STREAM %d] [VK Auth] Throttling: waiting %v to prevent rate limit...", streamID, wait.Truncate(time.Millisecond))
		select {
		case <-ctx.Done():
			return "", "", nil, ctx.Err()
		case <-time.After(wait):
		}
	}

	defer func() {
		globalLastVkFetchTime = time.Now()
	}()

	return fetchVkCreds(ctx, link, streamID, dialer)
}

func fetchVkCreds(ctx context.Context, link string, streamID int, dialer *dnsdialer.Dialer) (string, string, []string, error) {
	// Check Global Lockout to prevent API bans
	if time.Now().Unix() < globalCaptchaLockout.Load() {
		return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active")
	}

	var lastErr error
	jar := tlsclient.NewCookieJar()

	for _, creds := range vkCredentialsList {
		log.Printf("[STREAM %d] [VK Auth] Trying credentials: client_id=%s", streamID, creds.ClientID)

		user, pass, addrs, err := getTokenChain(ctx, link, streamID, creds, dialer, jar)

		if err == nil {
			log.Printf("[STREAM %d] [VK Auth] Success with client_id=%s", streamID, creds.ClientID)
			return user, pass, addrs, nil
		}

		lastErr = err
		log.Printf("[STREAM %d] [VK Auth] Failed with client_id=%s: %v", streamID, creds.ClientID, err)

		// Hard abort on captcha/fatal conditions instead of trying next creds
		if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") || strings.Contains(err.Error(), "FATAL_CAPTCHA") {
			return "", "", nil, err
		}

		if strings.Contains(err.Error(), "error_code:29") || strings.Contains(err.Error(), "error_code: 29") || strings.Contains(err.Error(), "Rate limit") {
			log.Printf("[STREAM %d] [VK Auth] Rate limit detected, trying next credentials...", streamID)
		}
	}

	return "", "", nil, fmt.Errorf("all VK credentials failed: %w", lastErr)
}

func getTokenChain(ctx context.Context, link string, streamID int, creds VKCredentials, dialer *dnsdialer.Dialer, jar tlsclient.CookieJar) (string, string, []string, error) {
	profile := Profile{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Not(A:Brand";v="99", "Google Chrome";v="146", "Chromium";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithDialer(getCustomNetDialer()),
	)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to initialize tls_client: %w", err)
	}

	name := generateName()
	escapedName := neturl.QueryEscape(name)

	log.Printf("[STREAM %d] [VK Auth] Connecting Identity - Name: %s | User-Agent: %s", streamID, name, profile.UserAgent)

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		parsedURL, err := neturl.Parse(url)
		if err != nil {
			return nil, fmt.Errorf("parse request URL: %w", err)
		}
		domain := parsedURL.Hostname()

		req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Host = domain
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("close response body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	// Token 1
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", nil, err
	}
	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("unexpected anon token response: %v", resp)
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing access_token in response: %v", resp)
	}

	vkDelayRandom(100, 150)

	// Token 1 -> getCallPreview
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	_, err = doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)
	if err != nil {
		log.Printf("[STREAM %d] [VK Auth] Warning: getCallPreview failed: %v", streamID, err)
	}

	vkDelayRandom(200, 400)

	// Token 2
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)

	var token2 string
	for attempt := 0; ; attempt++ {
		resp, err = doRequest(data, urlAddr)
		if err != nil {
			return "", "", nil, err
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			captchaErr := ParseVkCaptchaError(errObj)
			if captchaErr != nil && captchaErr.IsCaptchaError() {
				solveMode, hasSolveMode := captchaSolveModeForAttempt(attempt, manualCaptcha, autoCaptchaSliderPOC)
				if !hasSolveMode {
					log.Printf("[STREAM %d] [Captcha] No more solve modes available (attempt %d)", streamID, attempt+1)

					// Engage global lockout to protect API
					globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())

					if connectedStreams.Load() == 0 {
						log.Printf("[STREAM %d] [FATAL] 0 connected streams and captcha solve modes exhausted.", streamID)
						return "", "", nil, fmt.Errorf("FATAL_CAPTCHA_FAILED_NO_STREAMS")
					}

					return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}

				var successToken string
				var captchaKey string
				var solveErr error

				switch solveMode {
				case captchaSolveModeAuto:
					if captchaErr.SessionToken != "" && captchaErr.RedirectURI != "" {
						successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, client, profile, false)
						if solveErr != nil {
							log.Printf("[STREAM %d] [Captcha] Auto captcha failed: %v", streamID, solveErr)
						}
					} else {
						solveErr = fmt.Errorf("missing fields for auto solve")
					}
				case captchaSolveModeSliderPOC:
					if captchaErr.SessionToken != "" && captchaErr.RedirectURI != "" {
						successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, client, profile, true)
						if solveErr != nil {
							log.Printf("[STREAM %d] [Captcha] Auto captcha slider POC failed: %v", streamID, solveErr)
						}
					} else {
						solveErr = fmt.Errorf("missing fields for slider POC auto solve")
					}
				case captchaSolveModeManual:
					log.Printf("[STREAM %d] [Captcha] Triggering manual captcha fallback...", streamID)
					// Use context.Background() so that a short deadline on the parent ctx
					// (e.g. the overall auth timeout) doesn't cut the user's solve time short.
					manualCtx, manualCancel := context.WithTimeout(context.Background(), 3*time.Minute)

					type manualRes struct {
						token string
						key   string
						err   error
					}
					resCh := make(chan manualRes, 1)

					go func() {
						var t, k string
						var e error
						if captchaErr.RedirectURI != "" {
							t, e = solveCaptchaViaProxy(captchaErr.RedirectURI, dialer)
						} else if captchaErr.CaptchaImg != "" {
							k, e = solveCaptchaViaHTTP(captchaErr.CaptchaImg)
						} else {
							e = fmt.Errorf("no redirect_uri or captcha_img")
						}
						resCh <- manualRes{t, k, e}
					}()

					select {
					case res := <-resCh:
						successToken = res.token
						captchaKey = res.key
						solveErr = res.err
						// Token may be present even when err != nil (e.g. srv.Shutdown
						// timed out on iSH after the token was already received).
						// Treat a non-empty token as success regardless of the error.
						if successToken != "" || captchaKey != "" {
							if solveErr != nil {
								log.Printf("[STREAM %d] [Captcha] Token received (ignoring cleanup error: %v)", streamID, solveErr)
								solveErr = nil
							}
							log.Printf("[STREAM %d] [Captcha] Successfully got token from browser", streamID)
						} else if solveErr != nil {
							log.Printf("[STREAM %d] [Captcha] solveCaptchaViaProxy returned error: %v", streamID, solveErr)
						}
					case <-manualCtx.Done():
						if manualCtx.Err() == context.DeadlineExceeded {
							solveErr = fmt.Errorf("manual captcha timed out after 3m")
						} else {
							solveErr = fmt.Errorf("manual captcha interrupted: %w", manualCtx.Err())
						}
					}
					manualCancel()
				}

				// If solving failed (auto or manual) or timed out
				if solveErr != nil {
					log.Printf("[STREAM %d] [Captcha] %s failed (attempt %d): %v", streamID, captchaSolveModeLabel(solveMode), attempt+1, solveErr)

					nextSolveMode, hasNextSolveMode := captchaSolveModeForAttempt(attempt+1, manualCaptcha, autoCaptchaSliderPOC)
					if hasNextSolveMode {
						log.Printf("[STREAM %d] [Captcha] Falling back to %s...", streamID, captchaSolveModeLabel(nextSolveMode))
						continue
					}

					// Engage global lockout to protect API
					globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())

					// If we have 0 streams alive, this is fatal
					if connectedStreams.Load() == 0 {
						log.Printf("[STREAM %d] [FATAL] 0 connected streams and manual captcha failed/timed out.", streamID)
						return "", "", nil, fmt.Errorf("FATAL_CAPTCHA_FAILED_NO_STREAMS")
					}

					return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}

				if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
					captchaErr.CaptchaAttempt = "1"
				}

				if captchaKey != "" {
					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=%s&captcha_sid=%s&access_token=%s",
						link, escapedName, neturl.QueryEscape(captchaKey), captchaErr.CaptchaSid, token1)
				} else {
					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
						link, escapedName, captchaErr.CaptchaSid, neturl.QueryEscape(successToken), captchaErr.CaptchaTs, captchaErr.CaptchaAttempt, token1)
				}
				continue
			}
			return "", "", nil, fmt.Errorf("VK API error: %v", errObj)
		}

		respMap, okLoop := resp["response"].(map[string]interface{})
		if !okLoop {
			return "", "", nil, fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}
		token2, okLoop = respMap["token"].(string)
		if !okLoop {
			return "", "", nil, fmt.Errorf("missing token in response: %v", resp)
		}
		break
	}

	vkDelayRandom(100, 150)

	// Token 3
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", nil, err
	}
	token3, ok := resp["session_key"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing session_key in response: %v", resp)
	}

	vkDelayRandom(100, 150)

	// Token 4 -> TURN Creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", nil, err
	}

	tsRaw, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("missing turn_server in response: %v", resp)
	}
	user, ok := tsRaw["username"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing username in turn_server")
	}
	pass, ok := tsRaw["credential"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing credential in turn_server")
	}
	urlsRaw, ok := tsRaw["urls"].([]interface{})
	if !ok || len(urlsRaw) == 0 {
		return "", "", nil, fmt.Errorf("missing or empty urls in turn_server")
	}

	log.Printf("[STREAM %d] [VK Auth] TURN urls (%d total):", streamID, len(urlsRaw))
	for i, u := range urlsRaw {
		log.Printf("[STREAM %d] [VK Auth]   [%d] %v", streamID, i, u)
	}

	var addresses []string
	for _, u := range urlsRaw {
		urlStr, ok := u.(string)
		if !ok {
			continue
		}
		clean := strings.Split(urlStr, "?")[0]
		address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		addresses = append(addresses, address)
	}

	if len(addresses) == 0 {
		return "", "", nil, fmt.Errorf("no valid TURN addresses found")
	}

	return user, pass, addresses, nil
}

// endregion

func getYandexCreds(link string) (string, string, string, error) {
	const telemostConfHost = "cloud-api.yandex.ru"
	telemostConfPath := fmt.Sprintf("%s%s%s", "/telemost_front/v2/telemost/conferences/https%3A%2F%2Ftelemost.yandex.ru%2Fj%2F", link, "/connection?next_gen_media_platform_allowed=false")

	profile := getRandomProfile()
	name := generateName()

	type ConferenceResponse struct {
		URI                 string `json:"uri"`
		RoomID              string `json:"room_id"`
		PeerID              string `json:"peer_id"`
		ClientConfiguration struct {
			MediaServerURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}

	type PartMeta struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
		SendAudio   bool   `json:"sendAudio"`
		SendVideo   bool   `json:"sendVideo"`
	}

	type PartAttrs struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
	}

	type SdkInfo struct {
		Implementation string `json:"implementation"`
		Version        string `json:"version"`
		UserAgent      string `json:"userAgent"`
		HwConcurrency  int    `json:"hwConcurrency"`
	}

	type Capabilities struct {
		OfferAnswerMode             []string `json:"offerAnswerMode"`
		InitialSubscriberOffer      []string `json:"initialSubscriberOffer"`
		SlotsMode                   []string `json:"slotsMode"`
		SimulcastMode               []string `json:"simulcastMode"`
		SelfVadStatus               []string `json:"selfVadStatus"`
		DataChannelSharing          []string `json:"dataChannelSharing"`
		VideoEncoderConfig          []string `json:"videoEncoderConfig"`
		DataChannelVideoCodec       []string `json:"dataChannelVideoCodec"`
		BandwidthLimitationReason   []string `json:"bandwidthLimitationReason"`
		SdkDefaultDeviceManagement  []string `json:"sdkDefaultDeviceManagement"`
		JoinOrderLayout             []string `json:"joinOrderLayout"`
		PinLayout                   []string `json:"pinLayout"`
		SendSelfViewVideoSlot       []string `json:"sendSelfViewVideoSlot"`
		ServerLayoutTransition      []string `json:"serverLayoutTransition"`
		SdkPublisherOptimizeBitrate []string `json:"sdkPublisherOptimizeBitrate"`
		SdkNetworkLostDetection     []string `json:"sdkNetworkLostDetection"`
		SdkNetworkPathMonitor       []string `json:"sdkNetworkPathMonitor"`
		PublisherVp9                []string `json:"publisherVp9"`
		SvcMode                     []string `json:"svcMode"`
		SubscriberOfferAsyncAck     []string `json:"subscriberOfferAsyncAck"`
		SvcModes                    []string `json:"svcModes"`
		ReportTelemetryModes        []string `json:"reportTelemetryModes"`
		KeepDefaultDevicesModes     []string `json:"keepDefaultDevicesModes"`
	}

	type HelloPayload struct {
		ParticipantMeta        PartMeta     `json:"participantMeta"`
		ParticipantAttributes  PartAttrs    `json:"participantAttributes"`
		SendAudio              bool         `json:"sendAudio"`
		SendVideo              bool         `json:"sendVideo"`
		SendSharing            bool         `json:"sendSharing"`
		ParticipantID          string       `json:"participantId"`
		RoomID                 string       `json:"roomId"`
		ServiceName            string       `json:"serviceName"`
		Credentials            string       `json:"credentials"`
		CapabilitiesOffer      Capabilities `json:"capabilitiesOffer"`
		SdkInfo                SdkInfo      `json:"sdkInfo"`
		SdkInitializationID    string       `json:"sdkInitializationId"`
		DisablePublisher       bool         `json:"disablePublisher"`
		DisableSubscriber      bool         `json:"disableSubscriber"`
		DisableSubscriberAudio bool         `json:"disableSubscriberAudio"`
	}

	type HelloRequest struct {
		UID   string       `json:"uid"`
		Hello HelloPayload `json:"hello"`
	}

	type FlexUrls []string

	type WSSResponse struct {
		UID         string `json:"uid"`
		ServerHello struct {
			RtcConfiguration struct {
				IceServers []struct {
					Urls       FlexUrls `json:"urls"`
					Username   string   `json:"username,omitempty"`
					Credential string   `json:"credential,omitempty"`
				} `json:"iceServers"`
			} `json:"rtcConfiguration"`
		} `json:"serverHello"`
	}

	type WSSAck struct {
		UID string `json:"uid"`
		Ack struct {
			Status struct {
				Code string `json:"code"`
			} `json:"status"`
		} `json:"ack"`
	}

	type WSSData struct {
		ParticipantID string
		RoomID        string
		Credentials   string
		Wss           string
	}

	endpoint := "https://" + telemostConfHost + telemostConfPath
	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", "", "", err
	}

	applyBrowserProfile(req, profile)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://telemost.yandex.ru/")
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Client-Instance-Id", uuid.New().String())

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("close response body: %s", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		readBody, err2 := io.ReadAll(resp.Body)
		if err2 != nil {
			return "", "", "", fmt.Errorf("GetConference: status=%s (failed to read body: %v)", resp.Status, err2)
		}
		return "", "", "", fmt.Errorf("GetConference: status=%s body=%s", resp.Status, string(readBody))
	}

	var result ConferenceResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", fmt.Errorf("decode conf: %v", err)
	}
	data := WSSData{
		ParticipantID: result.PeerID,
		RoomID:        result.RoomID,
		Credentials:   result.Credentials,
		Wss:           result.ClientConfiguration.MediaServerURL,
	}
	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	h.Set("User-Agent", profile.UserAgent)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialer := websocket.Dialer{}
	var conn *websocket.Conn
	conn, resp, err = dialer.DialContext(ctx, data.Wss, h)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return "", "", "", fmt.Errorf("ws dial: %w", err)
	}
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("close websocket: %s", closeErr)
		}
	}()

	req1 := HelloRequest{
		UID: uuid.New().String(),
		Hello: HelloPayload{
			ParticipantMeta: PartMeta{
				Name:        name,
				Role:        "SPEAKER",
				Description: "",
				SendAudio:   false,
				SendVideo:   false,
			},
			ParticipantAttributes: PartAttrs{
				Name:        name,
				Role:        "SPEAKER",
				Description: "",
			},
			SendAudio:   false,
			SendVideo:   false,
			SendSharing: false,

			ParticipantID: data.ParticipantID,
			RoomID:        data.RoomID,
			ServiceName:   "telemost",
			Credentials:   data.Credentials,
			SdkInfo: SdkInfo{
				Implementation: "browser",
				Version:        "5.15.0",
				UserAgent:      profile.UserAgent,
				HwConcurrency:  4,
			},
			SdkInitializationID:    uuid.New().String(),
			DisablePublisher:       false,
			DisableSubscriber:      false,
			DisableSubscriberAudio: false,
			CapabilitiesOffer: Capabilities{
				OfferAnswerMode:             []string{"SEPARATE"},
				InitialSubscriberOffer:      []string{"ON_HELLO"},
				SlotsMode:                   []string{"FROM_CONTROLLER"},
				SimulcastMode:               []string{"DISABLED"},
				SelfVadStatus:               []string{"FROM_SERVER"},
				DataChannelSharing:          []string{"TO_RTP"},
				VideoEncoderConfig:          []string{"NO_CONFIG"},
				DataChannelVideoCodec:       []string{"VP8"},
				BandwidthLimitationReason:   []string{"BANDWIDTH_REASON_DISABLED"},
				SdkDefaultDeviceManagement:  []string{"SDK_DEFAULT_DEVICE_MANAGEMENT_DISABLED"},
				JoinOrderLayout:             []string{"JOIN_ORDER_LAYOUT_DISABLED"},
				PinLayout:                   []string{"PIN_LAYOUT_DISABLED"},
				SendSelfViewVideoSlot:       []string{"SEND_SELF_VIEW_VIDEO_SLOT_DISABLED"},
				ServerLayoutTransition:      []string{"SERVER_LAYOUT_TRANSITION_DISABLED"},
				SdkPublisherOptimizeBitrate: []string{"SDK_PUBLISHER_OPTIMIZE_BITRATE_DISABLED"},
				SdkNetworkLostDetection:     []string{"SDK_NETWORK_LOST_DETECTION_DISABLED"},
				SdkNetworkPathMonitor:       []string{"SDK_NETWORK_PATH_MONITOR_DISABLED"},
				PublisherVp9:                []string{"PUBLISH_VP9_DISABLED"},
				SvcMode:                     []string{"SVC_MODE_DISABLED"},
				SubscriberOfferAsyncAck:     []string{"SUBSCRIBER_OFFER_ASYNC_ACK_DISABLED"},
				SvcModes:                    []string{"FALSE"},
				ReportTelemetryModes:        []string{"TRUE"},
				KeepDefaultDevicesModes:     []string{"TRUE"},
			},
		},
	}

	if isDebug {
		b, _ := json.MarshalIndent(req1, "", "  ")
		log.Printf("Sending HELLO:\n%s", string(b))
	}

	if err := conn.WriteJSON(req1); err != nil {
		return "", "", "", fmt.Errorf("ws write: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", "", "", fmt.Errorf("ws set read deadline: %w", err)
	}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return "", "", "", fmt.Errorf("ws read: %w", err)
		}
		if isDebug {
			s := string(msg)
			if len(s) > 800 {
				s = s[:800] + "...(truncated)"
			}
			log.Printf("WSS recv: %s", s)
		}

		var ack WSSAck
		if err := json.Unmarshal(msg, &ack); err == nil && ack.Ack.Status.Code != "" {
			continue
		}

		var resp WSSResponse
		if err := json.Unmarshal(msg, &resp); err == nil {
			ice := resp.ServerHello.RtcConfiguration.IceServers
			for _, s := range ice {
				for _, u := range s.Urls {
					if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
						continue
					}
					if strings.Contains(u, "transport=tcp") {
						continue
					}
					clean := strings.Split(u, "?")[0]
					address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

					return s.Username, s.Credential, address, nil
				}
			}
		}
	}
}

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}

	select {
	case handshakeSem <- struct{}{}:
		defer func() { <-handshakeSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	ctx1, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	dtlsConn, err := dtls.ClientWithOptions(
		conn,
		peer,
		dtls.WithCertificates(certificate),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.OnlySendCIDGenerator()),
	)
	if err != nil {
		return nil, err
	}

	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}

func oneDtlsConnection(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, inboundChan <-chan *UDPPacket, connchan chan<- net.PacketConn, okchan chan<- struct{}, streamID int) error {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)

	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()

	conn1, conn2 := connutil.AsyncPacketPipe()
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case connchan <- conn2:
			}
		}
	}()
	dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, peer)
	if err1 != nil {
		return fmt.Errorf("failed to connect DTLS: %s", err1)
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			log.Printf("[STREAM %d] failed to close DTLS connection: %s", streamID, closeErr)
		}
		log.Printf("[STREAM %d] Closed DTLS connection\n", streamID)
	}()
	log.Printf("[STREAM %d] Established DTLS connection!\n", streamID)

	if okchan != nil {
		go func() {
			select {
			case okchan <- struct{}{}:
			case <-dtlsctx.Done():
			}
		}()
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	context.AfterFunc(dtlsctx, func() {
		if err := dtlsConn.SetDeadline(time.Now()); err != nil {
			log.Printf("[STREAM %d] Warning: SetDeadline failed: %v", streamID, err)
		}
	})

	go func() {
		defer dtlscancel()
		for {
			select {
			case <-dtlsctx.Done():
				return
			case pkt := <-inboundChan:
				_, _ = dtlsConn.Write(pkt.Data[:pkt.N])
				packetPool.Put(pkt)
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				return
			}

			// Send back to the active WG client
			if peerAddr := activeLocalPeer.Load(); peerAddr != nil {
				if addr, ok := peerAddr.(net.Addr); ok {
					if _, err := listenConn.WriteTo(buf[:n], addr); err != nil {
						log.Printf("[STREAM %d] failed to forward packet to local peer: %v", streamID, err)
					}
				}
			}
		}
	}()

	wg.Wait()
	if err := dtlsConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("[STREAM %d] Failed to clear DTLS deadline: %s", streamID, err)
	}
	return nil
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type turnParams struct {
	host     string
	port     string
	link     string
	udp      bool
	wrapKey  []byte
	getCreds getCredsFunc
}

func oneTurnConnection(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, streamID int, c chan<- error) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error
	defer func() { c <- err }()
	user, pass, urlTarget, err1 := turnParams.getCreds(ctx, turnParams.link, streamID)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		return
	}
	urlhost, urlport, err1 := net.SplitHostPort(urlTarget)
	if err1 != nil {
		err = fmt.Errorf("failed to parse TURN server address: %s", err1)
		return
	}
	if turnParams.host != "" {
		urlhost = turnParams.host
	}
	if turnParams.port != "" {
		urlport = turnParams.port
	}
	var turnServerAddr string
	turnServerAddr = net.JoinHostPort(urlhost, urlport)
	turnServerUDPAddr, err1 := net.ResolveUDPAddr("udp", turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %s", err1)
		return
	}
	turnServerAddr = turnServerUDPAddr.String()
	debugf("[STREAM %d] TURN server IP: %s", streamID, turnServerUDPAddr.IP)
	var cfg *turn.ClientConfig
	var turnConn net.PacketConn
	var d net.Dialer
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if turnParams.udp {
		conn, err2 := net.DialUDP("udp", nil, turnServerUDPAddr) // nolint: noctx
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = &connectedUDPConn{conn}
	} else {
		conn, err2 := d.DialContext(ctx1, "tcp", turnServerAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = turn.NewSTUNConn(conn)
	}
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	cfg = &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Net:                    newDirectNet(),
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}

	client, err1 := turn.NewClient(cfg)
	if err1 != nil {
		err = fmt.Errorf("failed to create TURN client: %s", err1)
		return
	}
	defer client.Close()

	err1 = client.Listen()
	if err1 != nil {
		err = fmt.Errorf("failed to listen: %s", err1)
		return
	}

	relayConn, err1 := client.Allocate()
	if err1 != nil {
		if isAuthError(err1) {
			handleAuthError(streamID)
		}
		err = fmt.Errorf("failed to allocate: %s", err1)
		return
	}

	// Reset error count on successful allocation
	getStreamCache(streamID).errorCount.Store(0)

	// Safely track active streams globally
	connectedStreams.Add(1)
	defer func() {
		connectedStreams.Add(-1)
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
		}
	}()

	if isDebug {
		log.Printf("[STREAM %d] relayed-address=%s", streamID, relayConn.LocalAddr().String())
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	turnctx, turncancel := context.WithCancel(ctx)
	defer turncancel()
	stats := &throughputStats{}
	go stats.logEvery(turnctx, fmt.Sprintf("[STREAM %d] TURN", streamID), "to-turn", "from-turn")

	context.AfterFunc(turnctx, func() {
		if err := relayConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set relay deadline: %s", err)
		}
		// Do not set conn2 deadline (conn2 can sometimes be listenConn if direct mode is used)
	})
	var internalPipeAddr atomic.Value
	useWrap := len(turnParams.wrapKey) == wrapKeyLen
	var wrapTX, wrapRX *wrapConn
	if useWrap {
		var wrapErr error
		wrapTX, wrapErr = newWrapConn(turnParams.wrapKey, false)
		if wrapErr != nil {
			log.Printf("[STREAM %d] WRAP init failed: %v", streamID, wrapErr)
			return
		}
		wrapRX, wrapErr = newWrapConn(turnParams.wrapKey, false)
		if wrapErr != nil {
			log.Printf("[STREAM %d] UNWRAP init failed: %v", streamID, wrapErr)
			return
		}
	}

	go func() {
		defer turncancel()
		buf := make([]byte, 1600)
		wrapBuf := make([]byte, wrapMaxWire(len(buf)))
		for {
			if turnctx.Err() != nil {
				return
			}
			n, addr1, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				return
			}
			if turnctx.Err() != nil {
				return
			}

			internalPipeAddr.Store(addr1)

			out := buf[:n]
			if useWrap {
				m, wrapErr := wrapTX.wrapInto(wrapBuf, out)
				if wrapErr != nil {
					log.Printf("[STREAM %d] WRAP failed: %v", streamID, wrapErr)
					return
				}
				out = wrapBuf[:m]
			}

			written, err1 := relayConn.WriteTo(out, peer)
			stats.addTx(written)
			if err1 != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer turncancel()
		readBufLen := 1600
		if useWrap {
			readBufLen = wrapMaxWire(readBufLen)
		}
		buf := make([]byte, readBufLen)
		plain := make([]byte, 1600)
		for {
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				return
			}
			addr1 := internalPipeAddr.Load()
			if addr1 == nil {
				continue
			}

			if addr, ok := addr1.(net.Addr); ok {
				payload := buf[:n]
				if useWrap {
					m, wrapErr := wrapRX.unwrapPacket(payload, plain)
					if wrapErr != nil {
						log.Printf("[STREAM %d] UNWRAP failed: %v (n=%d)", streamID, wrapErr, n)
						continue
					}
					payload = plain[:m]
				}
				stats.addRx(len(payload))
				if _, err := conn2.WriteTo(payload, addr); err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()
	if err := relayConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear relay deadline: %s", err)
	}
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, inboundChan <-chan *UDPPacket, connchan chan<- net.PacketConn, okchan chan<- struct{}, streamID int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := oneDtlsConnection(ctx, peer, listenConn, inboundChan, connchan, okchan, streamID)
			if err != nil {
				if time.Now().Unix() < globalCaptchaLockout.Load() && strings.Contains(err.Error(), "context deadline exceeded") {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(10+rand.Intn(20)) * time.Second):
				}
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time, streamID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
			case <-ctx.Done():
				return
			}
			c := make(chan error)
			go oneTurnConnection(ctx, turnParams, peer, conn2, streamID, c)

			if err := <-c; err != nil {
				if strings.Contains(err.Error(), "FATAL_CAPTCHA") {
					log.Printf("[STREAM %d] Fatal manual captcha error. Shutting down application.", streamID)
					if globalAppCancel != nil {
						globalAppCancel()
					}
					return
				}
				if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") {
					if !strings.Contains(err.Error(), "global lockout active") {
						log.Printf("[STREAM %d] Backing off for 60 seconds to avoid IP ban...", streamID)
						select {
						case <-ctx.Done():
							return
						case <-time.After(60 * time.Second):
						}
					} else {
						lockoutEnd := globalCaptchaLockout.Load()
						sleepDuration := time.Until(time.Unix(lockoutEnd, 0))
						if sleepDuration < 0 {
							sleepDuration = 5 * time.Second
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(sleepDuration):
						}
					}
				} else {
					log.Printf("[STREAM %d] %s", streamID, err)
					time.Sleep(2 * time.Second)
				}
			}
		}
	}
}

func setupGlobalResolver() {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	dnsServers := []string{"77.88.8.8:53", "77.88.8.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"}

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var lastErr error
			for _, dns := range dnsServers {
				conn, err := dialer.DialContext(ctx, "udp", dns)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

type Config struct {
	TURNHost       string `json:"turn_host,omitempty"`
	TURNPort       string `json:"turn_port,omitempty"`
	Listen         string `json:"listen,omitempty"`
	VKLink         string `json:"vk_link,omitempty"`
	YandexLink     string `json:"yandex_link,omitempty"`
	PeerAddr       string `json:"peer_addr,omitempty"`
	NumStreams     int    `json:"num_streams,omitempty"`
	UseUDP         bool   `json:"use_udp,omitempty"`
	NoDTLS         bool   `json:"no_dtls,omitempty"`
	VLESSMode      bool   `json:"vless_mode,omitempty"`
	VLESSBond      bool   `json:"vless_bond,omitempty"`
	WrapMode       bool   `json:"wrap_mode,omitempty"`
	WrapKeyHex     string `json:"wrap_key_hex,omitempty"`
	StreamsPerCred int    `json:"streams_per_cred,omitempty"`
	Debug          bool   `json:"debug,omitempty"`
	ManualCaptcha  bool   `json:"manual_captcha,omitempty"`
	CaptchaSolver  string `json:"captcha_solver,omitempty"`
	CaptchaHost    string `json:"captcha_host,omitempty"`
}

func (cfg *Config) setDefaults() {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9000"
	}
	if cfg.StreamsPerCred <= 0 {
		cfg.StreamsPerCred = streamsPerCache
	}
	if cfg.CaptchaSolver == "" {
		cfg.CaptchaSolver = "v2"
	}
}

func Run(ctx context.Context, cfg Config) error {
	setupGlobalResolver()
	cfg.setDefaults()
	ctx, cancel := context.WithCancel(ctx)
	globalAppCancel = cancel
	defer cancel()

	if cfg.PeerAddr == "" {
		return fmt.Errorf("need peer address")
	}
	peer, err := net.ResolveUDPAddr("udp", cfg.PeerAddr)
	if err != nil {
		return err
	}
	if (cfg.VKLink == "") == (cfg.YandexLink == "") {
		return fmt.Errorf("need either vk-link or yandex-link")
	}
	if cfg.WrapMode && cfg.NoDTLS {
		return fmt.Errorf("-wrap requires DTLS; remove -no-dtls")
	}
	wrapKey, err := decodeWrapKey(cfg.WrapMode, cfg.WrapKeyHex)
	if err != nil {
		return err
	}
	if cfg.WrapMode {
		log.Printf("WRAP mode enabled: peer server must use matching -wrap-key")
	}
	if cfg.StreamsPerCred <= 0 {
		return fmt.Errorf("-streams-per-cred must be positive")
	}
	streamsPerCache = cfg.StreamsPerCred

	isDebug = cfg.Debug
	manualCaptcha = cfg.ManualCaptcha
	captchaSolverVersion = strings.ToLower(strings.TrimSpace(cfg.CaptchaSolver))
	if captchaSolverVersion != "v1" && captchaSolverVersion != "v2" {
		captchaSolverVersion = "v2"
	}
	if captchaHostErr := setLocalCaptchaHost(cfg.CaptchaHost); captchaHostErr != nil {
		return captchaHostErr
	}
	autoCaptchaSliderPOC = !manualCaptcha

	var link string
	var getCreds getCredsFunc
	if cfg.VKLink != "" {
		parts := strings.Split(cfg.VKLink, "join/")
		link = parts[len(parts)-1]

		dialer := dnsdialer.New(
			dnsdialer.WithResolvers("77.88.8.8:53", "77.88.8.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"),
			dnsdialer.WithStrategy(dnsdialer.Fallback{}),
			dnsdialer.WithCache(100, 10*time.Hour, 10*time.Hour),
		)

		getCreds = func(ctx context.Context, s string, streamID int) (string, string, string, error) {
			return getVkCredsCached(ctx, s, streamID, dialer)
		}
		if cfg.NumStreams <= 0 {
			cfg.NumStreams = 10
		}
	} else {
		parts := strings.Split(cfg.YandexLink, "j/")
		link = parts[len(parts)-1]
		getCreds = func(ctx context.Context, s string, streamID int) (string, string, string, error) {
			return getYandexCreds(s)
		}
		if cfg.NumStreams <= 0 {
			cfg.NumStreams = 1
		}
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	params := &turnParams{
		host:     cfg.TURNHost,
		port:     cfg.TURNPort,
		link:     link,
		udp:      cfg.UseUDP,
		wrapKey:  wrapKey,
		getCreds: getCreds,
	}

	if cfg.VLESSMode {
		runVLESSMode(ctx, params, peer, cfg.Listen, cfg.NumStreams, cfg.VLESSBond)
		return nil
	}

	listenConn, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Printf("Failed to close local connection: %s", closeErr)
		}
	})

	numStreams := cfg.NumStreams
	if numStreams <= 0 {
		numStreams = 1
	}

	inboundChan := make(chan *UDPPacket, 2000)

	go func() {
		for {
			pktIface := packetPool.Get()
			pkt, ok := pktIface.(*UDPPacket)
			if !ok {
				log.Printf("packetPool returned unexpected type: %T", pktIface)
				continue
			}
			nRead, addr, err := listenConn.ReadFrom(pkt.Data)
			if err != nil {
				return
			}

			current := activeLocalPeer.Load()
			if current == nil {
				activeLocalPeer.Store(addr)
			} else if addrStr, ok := current.(net.Addr); ok {
				if addrStr.String() != addr.String() {
					activeLocalPeer.Store(addr)
				}
			} else {
				activeLocalPeer.Store(addr)
			}

			pkt.N = nRead

			select {
			case inboundChan <- pkt:
			default:
				packetPool.Put(pkt)
			}
		}
	}()

	wg1 := sync.WaitGroup{}
	t := time.Tick(200 * time.Millisecond)

	if cfg.NoDTLS {
		return fmt.Errorf("direct mode not supported with dispatcher")
	}

	okchan := make(chan struct{})
	connchan := make(chan net.PacketConn)
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		oneDtlsConnectionLoop(ctx, peer, listenConn, inboundChan, connchan, okchan, 0)
	}()
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		oneTurnConnectionLoop(ctx, params, peer, connchan, t, 0)
	}()

	select {
	case <-okchan:
	case <-ctx.Done():
	}

	for i := 1; i < numStreams; i++ {
		cchan := make(chan net.PacketConn)
		wg1.Add(1)
		go func(streamID int) {
			defer wg1.Done()
			oneDtlsConnectionLoop(ctx, peer, listenConn, inboundChan, cchan, nil, streamID)
		}(i)
		wg1.Add(1)
		go func(streamID int) {
			defer wg1.Done()
			oneTurnConnectionLoop(ctx, params, peer, cchan, t, streamID)
		}(i)
	}

	wg1.Wait()
	return nil
}

// sessionPool manages a pool of smux sessions for round-robin TCP distribution.
type pooledSession struct {
	id          int
	sess        *smux.Session
	active      atomic.Int32
	opened      atomic.Uint64
	closed      atomic.Uint64
	toSession   atomic.Uint64
	fromSession atomic.Uint64
}

type sessionPool struct {
	mu          sync.RWMutex
	sessions    []*pooledSession
	counter     atomic.Uint64
	connCounter atomic.Uint64
}

func (p *sessionPool) add(id int, s *smux.Session) *pooledSession {
	ps := &pooledSession{id: id, sess: s}
	p.mu.Lock()
	p.sessions = append(p.sessions, ps)
	p.mu.Unlock()
	return ps
}

func (p *sessionPool) remove(ps *pooledSession) {
	p.mu.Lock()
	for i, sess := range p.sessions {
		if sess == ps {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
}

func (p *sessionPool) pick() *pooledSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.sessions)
	if n == 0 {
		return nil
	}
	idx := (p.counter.Add(1) - 1) % uint64(n)
	return p.sessions[idx]
}

func (p *sessionPool) nextConnID() uint64 {
	return p.connCounter.Add(1)
}

func (p *sessionPool) snapshot() []*pooledSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*pooledSession, 0, len(p.sessions))
	for _, ps := range p.sessions {
		if !ps.sess.IsClosed() {
			out = append(out, ps)
		}
	}
	return out
}

func (p *sessionPool) count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

const (
	bondVersion = 1
	bondMagic   = "VLB1"

	bondFrameData byte = 1
	bondFrameFIN  byte = 2

	bondMaxChunk = 16 * 1024
)

type bondFrame struct {
	typ  byte
	seq  uint64
	data []byte
}

type bondClientLane struct {
	ps     *pooledSession
	stream *smux.Stream
	mu     sync.Mutex
	dead   atomic.Bool
}

func writeBondHello(w io.Writer, connID uint64, laneIndex, laneCount uint16) error {
	var hdr [17]byte
	copy(hdr[0:4], bondMagic)
	hdr[4] = bondVersion
	binary.BigEndian.PutUint64(hdr[5:13], connID)
	binary.BigEndian.PutUint16(hdr[13:15], laneIndex)
	binary.BigEndian.PutUint16(hdr[15:17], laneCount)
	_, err := w.Write(hdr[:])
	return err
}

func writeBondFrame(w io.Writer, typ byte, seq uint64, data []byte) error {
	var hdr [13]byte
	hdr[0] = typ
	binary.BigEndian.PutUint64(hdr[1:9], seq)
	binary.BigEndian.PutUint32(hdr[9:13], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	_, err := w.Write(data)
	return err
}

func readBondFrame(r io.Reader) (bondFrame, error) {
	var hdr [13]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return bondFrame{}, err
	}
	size := binary.BigEndian.Uint32(hdr[9:13])
	if size > 4*1024*1024 {
		return bondFrame{}, fmt.Errorf("bond frame too large: %d", size)
	}
	f := bondFrame{
		typ: hdr[0],
		seq: binary.BigEndian.Uint64(hdr[1:9]),
	}
	if size > 0 {
		f.data = make([]byte, size)
		if _, err := io.ReadFull(r, f.data); err != nil {
			return bondFrame{}, err
		}
	}
	return f, nil
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		if err := cw.CloseWrite(); err != nil && isDebug {
			log.Printf("CloseWrite failed: %v", err)
		}
	}
}

func handleBondedTCP(ctx context.Context, tcpConn net.Conn, connID uint64, candidates []*pooledSession) {
	defer func() { _ = tcpConn.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lanes := make([]*bondClientLane, 0, len(candidates))
	laneIDs := make([]string, 0, len(candidates))
	for i, ps := range candidates {
		if ps.sess.IsClosed() {
			continue
		}
		stream, err := ps.sess.OpenStream()
		if err != nil {
			log.Printf("[bond %d] session %d open stream error: %s", connID, ps.id, err)
			continue
		}
		if err := writeBondHello(stream, connID, uint16(i), uint16(len(candidates))); err != nil {
			log.Printf("[bond %d] session %d hello error: %s", connID, ps.id, err)
			_ = stream.Close()
			continue
		}
		ps.opened.Add(1)
		ps.active.Add(1)
		lanes = append(lanes, &bondClientLane{ps: ps, stream: stream})
		laneIDs = append(laneIDs, strconv.Itoa(ps.id))
	}

	if len(lanes) == 0 {
		log.Printf("[bond %d] no usable lanes, rejecting TCP from %s", connID, tcpConn.RemoteAddr())
		return
	}
	context.AfterFunc(ctx, func() {
		now := time.Now()
		if err := tcpConn.SetDeadline(now); err != nil && isDebug {
			log.Printf("[bond %d] local TCP deadline error: %v", connID, err)
		}
		for _, lane := range lanes {
			if err := lane.stream.SetDeadline(now); err != nil && isDebug {
				log.Printf("[bond %d] session %d stream deadline error: %v", connID, lane.ps.id, err)
			}
		}
	})

	debugf("[bond %d] TCP accept from=%s lanes=%d [%s]", connID, tcpConn.RemoteAddr(), len(lanes), strings.Join(laneIDs, ","))
	defer func() {
		for _, lane := range lanes {
			_ = lane.stream.Close()
			active := lane.ps.active.Add(-1)
			closed := lane.ps.closed.Add(1)
			debugf("[bond %d] lane session %d close active=%d closed=%d totals: to-session=%s from-session=%s",
				connID, lane.ps.id, active, closed,
				formatByteCount(lane.ps.toSession.Load()), formatByteCount(lane.ps.fromSession.Load()))
		}
	}()

	recvCh := make(chan bondFrame, 1024)
	var readWG sync.WaitGroup
	for _, lane := range lanes {
		readWG.Add(1)
		go func(l *bondClientLane) {
			defer readWG.Done()
			for {
				f, err := readBondFrame(l.stream)
				if err != nil {
					l.dead.Store(true)
					select {
					case <-ctx.Done():
					default:
						if err != io.EOF {
							debugf("[bond %d] session %d read frame error: %v", connID, l.ps.id, err)
						}
					}
					return
				}
				if f.typ == bondFrameData {
					l.ps.fromSession.Add(uint64(len(f.data)))
				}
				select {
				case recvCh <- f:
				case <-ctx.Done():
					return
				}
			}
		}(lane)
	}
	go func() {
		readWG.Wait()
		close(recvCh)
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyTCPToBond(ctx, connID, tcpConn, lanes)
	}()
	go func() {
		defer wg.Done()
		copyBondToTCP(ctx, connID, tcpConn, recvCh)
		cancel()
	}()
	wg.Wait()
}

func copyTCPToBond(ctx context.Context, connID uint64, tcpConn net.Conn, lanes []*bondClientLane) {
	buf := make([]byte, bondMaxChunk)
	var seq uint64
	var laneIdx uint64
	for {
		n, err := tcpConn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			lane, writeErr := writeBondFrameToNextLane(ctx, lanes, bondFrameData, seq, data, &laneIdx)
			if writeErr != nil {
				log.Printf("[bond %d] write data error: %v", connID, writeErr)
				return
			}
			lane.ps.toSession.Add(uint64(n))
			seq++
		}
		if err != nil {
			if isDebug && err != io.EOF {
				log.Printf("[bond %d] local TCP read finished with error: %v", connID, err)
			}
			for _, lane := range lanes {
				if lane.dead.Load() {
					continue
				}
				lane.mu.Lock()
				writeErr := writeBondFrame(lane.stream, bondFrameFIN, seq, nil)
				lane.mu.Unlock()
				if writeErr != nil && ctx.Err() == nil {
					log.Printf("[bond %d] session %d write FIN error: %v", connID, lane.ps.id, writeErr)
				}
			}
			debugf("[bond %d] upload finished chunks=%d", connID, seq)
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func writeBondFrameToNextLane(ctx context.Context, lanes []*bondClientLane, typ byte, seq uint64, data []byte, laneIdx *uint64) (*bondClientLane, error) {
	for attempts := 0; attempts < len(lanes); attempts++ {
		idx := *laneIdx % uint64(len(lanes))
		*laneIdx++
		lane := lanes[idx]
		if lane.dead.Load() {
			continue
		}
		lane.mu.Lock()
		err := writeBondFrame(lane.stream, typ, seq, data)
		lane.mu.Unlock()
		if err == nil {
			return lane, nil
		}
		lane.dead.Store(true)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, fmt.Errorf("no live bond lanes")
}

func copyBondToTCP(ctx context.Context, connID uint64, tcpConn net.Conn, recvCh <-chan bondFrame) {
	pending := make(map[uint64][]byte)
	var expect uint64
	var finSeq *uint64

	for {
		if finSeq != nil && expect == *finSeq {
			closeWrite(tcpConn)
			debugf("[bond %d] download finished chunks=%d", connID, expect)
			return
		}

		select {
		case <-ctx.Done():
			return
		case f, ok := <-recvCh:
			if !ok {
				return
			}
			switch f.typ {
			case bondFrameData:
				pending[f.seq] = f.data
			case bondFrameFIN:
				v := f.seq
				if finSeq == nil || v < *finSeq {
					finSeq = &v
				}
			default:
				log.Printf("[bond %d] unknown frame type %d", connID, f.typ)
				return
			}

			for {
				data, ok := pending[expect]
				if !ok {
					break
				}
				delete(pending, expect)
				if len(data) > 0 {
					if _, err := tcpConn.Write(data); err != nil {
						log.Printf("[bond %d] local TCP write error: %v", connID, err)
						return
					}
				}
				expect++
			}
		}
	}
}

// runVLESSMode implements TCP forwarding with round-robin across N TURN sessions.
func runVLESSMode(ctx context.Context, tp *turnParams, peer *net.UDPAddr, listenAddr string, numSessions int, bond bool) {
	pool := &sessionPool{}

	// Start N session maintainers with staggered startup
	var wgMaint sync.WaitGroup
	for i := 0; i < numSessions; i++ {
		wgMaint.Add(1)
		go func(id int) {
			defer wgMaint.Done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(id) * 300 * time.Millisecond):
			}
			maintainVLESSSession(ctx, tp, peer, id, pool)
		}(i)
	}

	// Wait for at least one session
	log.Printf("VLESS mode: waiting for sessions to connect (total: %d)...", numSessions)
	for {
		select {
		case <-ctx.Done():
			wgMaint.Wait()
			return
		case <-time.After(100 * time.Millisecond):
		}
		if pool.count() > 0 {
			break
		}
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panicf("TCP listen: %s", err)
	}

	wrappedListener, err := wrapISHListener(listener)
	if err != nil {
		log.Printf("Warning: failed to wrap listener: %v", err)
		wrappedListener = listener
	}

	context.AfterFunc(ctx, func() { _ = wrappedListener.Close() })
	if bond {
		log.Printf("VLESS bond mode: listening on %s (striping each TCP connection across active sessions)", listenAddr)
	} else {
		log.Printf("VLESS mode: listening on %s (round-robin across %d sessions)", listenAddr, numSessions)
	}

	var wgConn sync.WaitGroup
	for {
		tcpConn, err := wrappedListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wgConn.Wait()
				wgMaint.Wait()
				return
			default:
			}
			log.Printf("TCP accept error: %s", err)
			continue
		}

		if bond {
			connID := (uint64(time.Now().UnixNano()) << 16) ^ pool.nextConnID()
			lanes := pool.snapshot()
			if len(lanes) == 0 {
				log.Printf("No active sessions, rejecting connection")
				_ = tcpConn.Close()
				continue
			}

			wgConn.Add(1)
			go func(tc net.Conn, connID uint64, lanes []*pooledSession) {
				defer wgConn.Done()
				handleBondedTCP(ctx, tc, connID, lanes)
			}(tcpConn, connID, lanes)
			continue
		}

		ps := pool.pick()
		if ps == nil || ps.sess.IsClosed() {
			log.Printf("No active sessions, rejecting connection")
			_ = tcpConn.Close()
			continue
		}

		connID := pool.nextConnID()
		opened := ps.opened.Add(1)
		active := ps.active.Add(1)
		debugf("[session %d] TCP accept #%d from=%s active=%d opened=%d pool=%d",
			ps.id, connID, tcpConn.RemoteAddr(), active, opened, pool.count())

		wgConn.Add(1)
		go func(tc net.Conn, ps *pooledSession, connID uint64) {
			defer wgConn.Done()
			defer func() { _ = tc.Close() }()
			defer func() {
				active := ps.active.Add(-1)
				closed := ps.closed.Add(1)
				debugf("[session %d] TCP close #%d active=%d closed=%d totals: to-session=%s from-session=%s",
					ps.id, connID, active, closed,
					formatByteCount(ps.toSession.Load()), formatByteCount(ps.fromSession.Load()))
			}()

			stream, err := ps.sess.OpenStream()
			if err != nil {
				log.Printf("[session %d] smux open stream error for TCP #%d: %s", ps.id, connID, err)
				return
			}
			defer func() { _ = stream.Close() }()
			fromSession, toSession := pipe(ctx, tc, stream)
			ps.fromSession.Add(uint64(fromSession))
			ps.toSession.Add(uint64(toSession))
			debugf("[session %d] TCP done #%d local<-session=%s local->session=%s",
				ps.id, connID, formatByteCount(uint64(fromSession)), formatByteCount(uint64(toSession)))
		}(tcpConn, ps, connID)
	}
}

// maintainVLESSSession keeps one TURN+DTLS+KCP+smux session alive, reconnecting on failure.
func maintainVLESSSession(ctx context.Context, tp *turnParams, peer *net.UDPAddr, id int, pool *sessionPool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		smuxSess, cleanup, err := createSmuxSession(ctx, tp, peer, id)
		if err != nil {
			if shouldRotateTURNServer(err) {
				offset := rotateStreamServer(id)
				if addr, ok := turnSetupAddr(err); ok {
					markTURNServerCooldown(addr)
					debugf("[session %d] cooling down TURN server %s for %s after setup failure (offset=%d)", id, addr, turnServerCooldown, offset)
				} else {
					debugf("[session %d] rotating TURN server after setup failure (offset=%d)", id, offset)
				}
			}
			log.Printf("[session %d] setup error: %s, retrying...", id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}

		ps := pool.add(id, smuxSess)
		log.Printf("[session %d] connected (active: %d)", id, pool.count())

		for !smuxSess.IsClosed() {
			select {
			case <-ctx.Done():
				pool.remove(ps)
				cleanup()
				return
			case <-time.After(1 * time.Second):
			}
		}

		pool.remove(ps)
		cleanup()
		log.Printf("[session %d] disconnected (active: %d), reconnecting...", id, pool.count())

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

type turnSetupError struct {
	addr string
	err  error
}

func (e *turnSetupError) Error() string {
	return e.err.Error()
}

func (e *turnSetupError) Unwrap() error {
	return e.err
}

func turnSetupAddr(err error) (string, bool) {
	var setupErr *turnSetupError
	if errors.As(err, &setupErr) && setupErr.addr != "" {
		return setupErr.addr, true
	}
	return "", false
}

func shouldRotateTURNServer(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "dial TURN") ||
		strings.Contains(errStr, "TURN allocate") ||
		strings.Contains(errStr, "DTLS handshake")
}

// createSmuxSession establishes a full TURN+DTLS+KCP+smux pipeline and returns
// the smux session along with a cleanup function to tear down all layers.
func createSmuxSession(ctx context.Context, tp *turnParams, peer *net.UDPAddr, id int) (*smux.Session, func(), error) {
	var cleanupFns []func()
	cleanup := func() {
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			cleanupFns[i]()
		}
	}

	// 1. Get TURN credentials
	user, pass, rawURL, err := tp.getCreds(ctx, tp.link, id)
	if err != nil {
		return nil, nil, fmt.Errorf("get TURN creds: %w", err)
	}
	urlhost, urlport, err := net.SplitHostPort(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse TURN addr: %w", err)
	}
	if tp.host != "" {
		urlhost = tp.host
	}
	if tp.port != "" {
		urlport = tp.port
	}
	turnServerAddr := net.JoinHostPort(urlhost, urlport)
	turnServerUDPAddr, err := net.ResolveUDPAddr("udp", turnServerAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve TURN addr: %w", err)
	}
	turnServerAddr = turnServerUDPAddr.String()
	debugf("[session %d] TURN server IP: %s", id, turnServerUDPAddr.IP)

	// 2. Connect to TURN server
	var turnConn net.PacketConn
	ctx1, cancel1 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel1()
	if tp.udp {
		c, err1 := net.DialUDP("udp", nil, turnServerUDPAddr)
		if err1 != nil {
			return nil, nil, &turnSetupError{addr: turnServerAddr, err: fmt.Errorf("dial TURN (udp): %w", err1)}
		}
		cleanupFns = append(cleanupFns, func() { _ = c.Close() })
		turnConn = &connectedUDPConn{c}
	} else {
		var d net.Dialer
		c, err1 := d.DialContext(ctx1, "tcp", turnServerAddr)
		if err1 != nil {
			return nil, nil, &turnSetupError{addr: turnServerAddr, err: fmt.Errorf("dial TURN (tcp): %w", err1)}
		}
		cleanupFns = append(cleanupFns, func() { _ = c.Close() })
		turnConn = turn.NewSTUNConn(c)
	}

	// 3. Create TURN client and allocate relay
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}
	cfg := &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Net:                    newDirectNet(),
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}
	turnClient, err := turn.NewClient(cfg)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create TURN client: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { turnClient.Close() })
	if err = turnClient.Listen(); err != nil {
		cleanup()
		return nil, nil, &turnSetupError{addr: turnServerAddr, err: fmt.Errorf("TURN listen: %w", err)}
	}
	relayConn, err := turnClient.Allocate()
	if err != nil {
		cleanup()
		return nil, nil, &turnSetupError{addr: turnServerAddr, err: fmt.Errorf("TURN allocate: %w", err)}
	}
	cleanupFns = append(cleanupFns, func() { _ = relayConn.Close() })
	debugf("relayed-address=%s", relayConn.LocalAddr().String())

	// 4. Establish DTLS over TURN relay
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("generate cert: %w", err)
	}
	dtlsPC, err := newRelayPacketConn(relayConn, peer, tp.wrapKey)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	dtlsConn, err := dtls.ClientWithOptions(dtlsPC, peer,
		dtls.WithCertificates(certificate),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.OnlySendCIDGenerator()),
	)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("DTLS client create: %w", err)
	}
	ctx2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel2()
	if err = dtlsConn.HandshakeContext(ctx2); err != nil {
		_ = dtlsConn.Close()
		cleanup()
		return nil, nil, &turnSetupError{addr: turnServerAddr, err: fmt.Errorf("DTLS handshake: %w", err)}
	}
	cleanupFns = append(cleanupFns, func() { _ = dtlsConn.Close() })
	debugf("DTLS connection established")

	// 5. Create KCP session over DTLS
	statsCtx, statsCancel := context.WithCancel(ctx)
	cleanupFns = append(cleanupFns, statsCancel)
	stats := &throughputStats{}
	go stats.logEvery(statsCtx, fmt.Sprintf("[session %d] VLESS", id), "to-turn", "from-turn")

	kcpSess, err := tcputil.NewKCPOverDTLS(&countingConn{Conn: dtlsConn, stats: stats}, false)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("KCP session: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = kcpSess.Close() })
	debugf("KCP session established")

	// 6. Create smux client session over KCP
	smuxSess, err := smux.Client(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("smux client: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = smuxSess.Close() })
	debugf("smux session established")

	return smuxSess, cleanup, nil
}

// relayPacketConn wraps a TURN relay PacketConn to direct all writes to the peer.
// When wrapTX/wrapRX are set, packets are wrapped/unwrapped with SRTP-mimicry AEAD.
type relayPacketConn struct {
	relay  net.PacketConn
	peer   net.Addr
	wrapTX *wrapConn
	wrapRX *wrapConn
}

func newRelayPacketConn(relay net.PacketConn, peer net.Addr, wrapKey []byte) (*relayPacketConn, error) {
	r := &relayPacketConn{relay: relay, peer: peer}
	if len(wrapKey) != wrapKeyLen {
		return r, nil
	}
	var err error
	r.wrapTX, err = newWrapConn(wrapKey, false)
	if err != nil {
		return nil, fmt.Errorf("wrap tx init: %w", err)
	}
	r.wrapRX, err = newWrapConn(wrapKey, false)
	if err != nil {
		return nil, fmt.Errorf("wrap rx init: %w", err)
	}
	return r, nil
}

func (r *relayPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if r.wrapRX == nil {
		return r.relay.ReadFrom(b)
	}
	buf := make([]byte, wrapMaxWire(len(b)))
	n, addr, err := r.relay.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	m, err := r.wrapRX.unwrapPacket(buf[:n], b)
	if err != nil {
		return 0, addr, err
	}
	return m, addr, nil
}

func (r *relayPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if r.wrapTX == nil {
		return r.relay.WriteTo(b, r.peer)
	}
	out := make([]byte, wrapMaxWire(len(b)))
	n, err := r.wrapTX.wrapInto(out, b)
	if err != nil {
		return 0, err
	}
	if _, err = r.relay.WriteTo(out[:n], r.peer); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (r *relayPacketConn) Close() error                       { return r.relay.Close() }
func (r *relayPacketConn) LocalAddr() net.Addr                { return r.relay.LocalAddr() }
func (r *relayPacketConn) SetDeadline(t time.Time) error      { return r.relay.SetDeadline(t) }
func (r *relayPacketConn) SetReadDeadline(t time.Time) error  { return r.relay.SetReadDeadline(t) }
func (r *relayPacketConn) SetWriteDeadline(t time.Time) error { return r.relay.SetWriteDeadline(t) }

// pipe copies data bidirectionally between two connections.
// It returns bytes copied as c1<-c2 and c2<-c1.
func pipe(ctx context.Context, c1, c2 net.Conn) (int64, int64) {
	ctx2, cancel := context.WithCancel(ctx)
	context.AfterFunc(ctx2, func() {
		if err := c1.SetDeadline(time.Now()); err != nil {
			log.Printf("pipe: failed to set deadline c1: %v", err)
		}
		if err := c2.SetDeadline(time.Now()); err != nil {
			log.Printf("pipe: failed to set deadline c2: %v", err)
		}
	})

	var wg sync.WaitGroup
	var c1FromC2 int64
	var c2FromC1 int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		n, err := io.Copy(c1, c2)
		c1FromC2 = n
		if err != nil {
			if isDebug {
				log.Printf("pipe: c1<-c2 copy error: %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		n, err := io.Copy(c2, c1)
		c2FromC1 = n
		if err != nil {
			if isDebug {
				log.Printf("pipe: c2<-c1 copy error: %v", err)
			}
		}
	}()
	wg.Wait()
	if err := c1.SetDeadline(time.Time{}); err != nil {
		if isDebug {
			log.Printf("pipe: failed to reset deadline c1: %v", err)
		}
	}
	if err := c2.SetDeadline(time.Time{}); err != nil {
		if isDebug {
			log.Printf("pipe: failed to reset deadline c2: %v", err)
		}
	}
	return c1FromC2, c2FromC1
}
