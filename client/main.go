// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

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
	allocsPerStream      int
	udpMode              bool
)

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

// generateBrowserFp produces a stable fallback fingerprint when no SavedProfile
// is available. Stable (no time component) so the value matches between
// componentDone and check inside the same auto-solve attempt.
func generateBrowserFp(profile Profile) string {
	data := profile.UserAgent + profile.SecChUa + "1536x864x24"
	h := md5.Sum([]byte(data))
	return hex.EncodeToString(h[:])
}

// dnsMode is set in main() from the -dns flag and consumed by appDialer().
var dnsMode = DNSModeAuto

// dohResolverSingleton is shared across all callers of appDialer().
var (
	dohResolverOnce     sync.Once
	dohResolverInstance *DohResolver
)

func sharedDohResolver() *DohResolver {
	dohResolverOnce.Do(func() {
		dohResolverInstance = NewDohResolver(nil)
	})
	return dohResolverInstance
}

// appDialer returns the net.Dialer used by tls-client and other HTTP callers.
// DNS transport is selected by the -dns flag (udp | doh | auto).
func appDialer() net.Dialer {
	return buildDialer(dnsMode, sharedDohResolver())
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

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	// Extract error_code
	codeFloat, ok := errData["error_code"].(float64)
	if !ok {
		log.Printf("missing error_code in captcha error data")
		return nil
	}
	code := int(codeFloat)

	// Extract redirect_uri
	RedirectURI, ok := errData["redirect_uri"].(string)
	if !ok {
		log.Printf("missing redirect_uri in captcha error data")
		return nil
	}

	// Extract captcha_sid
	captchaSid, ok := errData["captcha_sid"].(string)
	if !ok {
		// try numeric
		if sidNum, ok2 := errData["captcha_sid"].(float64); ok2 {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		} else {
			log.Printf("missing captcha_sid in captcha error data")
			return nil
		}
	}

	// Extract captcha_img
	captchaImg, ok := errData["captcha_img"].(string)
	if !ok {
		log.Printf("missing captcha_img in captcha error data")
		return nil
	}

	// Extract error_msg
	errorMsg, ok := errData["error_msg"].(string)
	if !ok {
		log.Printf("missing error_msg in captcha error data")
		return nil
	}

	// Extract session token if redirect_uri present
	var sessionToken string
	if RedirectURI != "" {
		if parsed, err := neturl.Parse(RedirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		} else {
			log.Printf("failed to parse redirect_uri: %v", err)
			return nil
		}
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
	return e.ErrorCode == 14 && e.RedirectURI != "" && e.SessionToken != ""
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

	// Reuse the real-browser fingerprint captured during a prior manual solve.
	// VK fingerprints (browser_fp, device, UA) together; keeping them consistent
	// across runs helps the auto path stay out of the BOT bucket.
	var savedProfile *SavedProfile
	if sp, err := LoadProfileFromDisk(); err == nil {
		log.Printf("[STREAM %d] [Captcha] Using saved real browser profile", streamID)
		savedProfile = sp
		profile = sp.Profile
	}

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	log.Printf("[STREAM %d] [Captcha] PoW input: %s, difficulty: %d", streamID, bootstrap.PowInput, bootstrap.Difficulty)

	hash, err := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	if err != nil {
		return "", fmt.Errorf("PoW: %w", err)
	}
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
			savedProfile,
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

func solvePoW(powInput string, difficulty int) (string, error) {
	target := strings.Repeat("0", difficulty)
	const maxNonce = 10000000
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	var (
		found    atomic.Bool
		resultCh = make(chan string, 1)
		wg       sync.WaitGroup
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			for nonce := start; nonce <= maxNonce; nonce += workers {
				if found.Load() {
					return
				}
				data := powInput + strconv.Itoa(nonce)
				hash := sha256.Sum256([]byte(data))
				hexHash := hex.EncodeToString(hash[:])
				if strings.HasPrefix(hexHash, target) {
					if found.CompareAndSwap(false, true) {
						resultCh <- hexHash
					}
					return
				}
			}
		}(w + 1)
	}

	go func() { wg.Wait(); close(resultCh) }()

	if h, ok := <-resultCh; ok {
		return h, nil
	}
	return "", fmt.Errorf("PoW unsolved (difficulty=%d, tried %dM nonces)", difficulty, maxNonce/1000000)
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

	// Per-session adFp: a stable empty value is itself a fingerprint.
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
	// Real browser sends [] for cursor on the first check.
	cursorJSON := "[]"
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	// debug_info must vary per-session — a hardcoded hash becomes a stable
	// fingerprint VK uses to flag the bot path (status=BOT).
	debugInfoBytes := sha256.Sum256([]byte(profile.UserAgent + sessionToken + strconv.FormatInt(time.Now().UnixNano(), 10)))
	debugInfo := hex.EncodeToString(debugInfoBytes[:])

	// Realistic per-session jitter; static arrays were also a fingerprint.
	rttSamples := 4 + rand.Intn(4)
	rttBase := 40 + rand.Intn(120)
	rttVals := make([]string, rttSamples)
	for i := range rttVals {
		rttVals[i] = strconv.Itoa(rttBase + rand.Intn(40) - 20)
	}
	connectionRtt := "[" + strings.Join(rttVals, ",") + "]"

	dlSamples := 4 + rand.Intn(4)
	dlBase := 2.0 + rand.Float64()*8.0
	dlVals := make([]string, dlSamples)
	for i := range dlVals {
		dlVals[i] = strconv.FormatFloat(dlBase+(rand.Float64()-0.5)*0.4, 'f', 2, 64)
	}
	connectionDownlink := "[" + strings.Join(dlVals, ",") + "]"

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

// Only client_ids that currently expose calls.getAnonymousToken.
// VKVIDEO_* and VK_ID_AUTH_APP started returning error_code:3 "Unknown method"
// (observed 2026-04-28) and only burn throttle budget if kept in rotation.
var vkCredentialsList = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"}, // VK_WEB_APP_ID
	{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"}, // VK_MVK_APP_ID
}

type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
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
	// streamsPerCache=1: each stream caches its own slot creds because
	// acquireVkTurnSlot mints a unique (username, password) per call.
	streamsPerCache  = 1
	identityLifetime = 8 * time.Minute
)

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

func getVkCredsCached(ctx context.Context, link string, streamID int) (string, string, string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.RLock()
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		expires := time.Until(cache.creds.ExpiresAt)
		u, p, a := cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr
		cache.mutex.RUnlock()
		if isDebug {
			log.Printf("[STREAM %d] [VK Auth] Using cached credentials (cache=%d, expires in %v)", streamID, cacheID, expires)
		}
		return u, p, a, nil
	}
	cache.mutex.RUnlock()

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Double-check inside lock
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, nil
	}

	user, pass, addr, err := fetchVkCreds(ctx, link, streamID)
	if err != nil {
		return "", "", "", err
	}

	cache.creds = TurnCredentials{Username: user, Password: pass, ServerAddr: addr, ExpiresAt: time.Now().Add(credentialLifetime - cacheSafetyMargin), Link: link}
	return user, pass, addr, nil
}

// vkClientThrottle holds per-client_id serialisation + cooldown timestamp.
// Was previously a single global mutex which forced acquires across distinct
// client_ids onto the same queue even though VK rate-limits per client_id.
type vkClientThrottle struct {
	mu       sync.Mutex
	lastTime time.Time
}

var (
	vkThrottleStore = struct {
		mu sync.Mutex
		m  map[string]*vkClientThrottle
	}{m: make(map[string]*vkClientThrottle)}
)

func getVkThrottle(clientID string) *vkClientThrottle {
	vkThrottleStore.mu.Lock()
	defer vkThrottleStore.mu.Unlock()
	t, ok := vkThrottleStore.m[clientID]
	if !ok {
		t = &vkClientThrottle{}
		vkThrottleStore.m[clientID] = t
	}
	return t
}

// vkIdentity caches the captcha-gated portion of a VK auth chain (steps 1-3:
// anonym_token + getCallPreview + getAnonymousToken). Once acquired it can be
// replayed via acquireVkTurnSlot to mint independent TURN credentials, each
// with a unique username — bypassing per-username throttling at the cost of a
// single captcha solve per (link, client_id) pair.
type vkIdentity struct {
	creds      VKCredentials
	profile    Profile
	name       string
	token1     string
	token2     string
	client     tlsclient.HttpClient
	expiresAt  time.Time
	urlCounter atomic.Uint64 // round-robin index across turn_server.urls
}

type identityCacheKey struct {
	link     string
	clientID string
}

type identityEntry struct {
	mu    sync.Mutex
	ident *vkIdentity
}

var identityStore = struct {
	mu sync.Mutex
	m  map[identityCacheKey]*identityEntry
}{m: make(map[identityCacheKey]*identityEntry)}

func getOrAcquireIdentity(ctx context.Context, link string, streamID int, creds VKCredentials) (*vkIdentity, error) {
	key := identityCacheKey{link: link, clientID: creds.ClientID}

	identityStore.mu.Lock()
	entry, ok := identityStore.m[key]
	if !ok {
		entry = &identityEntry{}
		identityStore.m[key] = entry
	}
	identityStore.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.ident != nil && time.Now().Before(entry.ident.expiresAt) {
		return entry.ident, nil
	}

	ident, err := acquireVkIdentity(ctx, link, streamID, creds)
	if err != nil {
		return nil, err
	}
	entry.ident = ident
	return ident, nil
}

func invalidateIdentity(link, clientID string) {
	identityStore.mu.Lock()
	entry, ok := identityStore.m[identityCacheKey{link: link, clientID: clientID}]
	identityStore.mu.Unlock()
	if !ok {
		return
	}
	entry.mu.Lock()
	entry.ident = nil
	entry.mu.Unlock()
}

func fetchVkCreds(ctx context.Context, link string, streamID int) (string, string, string, error) {
	if time.Now().Unix() < globalCaptchaLockout.Load() {
		return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active")
	}

	n := len(vkCredentialsList)
	startIdx := streamID % n

	var lastErr error
	for offset := 0; offset < n; offset++ {
		creds := vkCredentialsList[(startIdx+offset)%n]
		log.Printf("[STREAM %d] [VK Auth] Trying credentials: client_id=%s", streamID, creds.ClientID)

		ident, err := getOrAcquireIdentity(ctx, link, streamID, creds)
		if err != nil {
			lastErr = err
			log.Printf("[STREAM %d] [VK Auth] identity acquire failed (client_id=%s): %v", streamID, creds.ClientID, err)
			if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") || strings.Contains(err.Error(), "FATAL_CAPTCHA") {
				return "", "", "", err
			}
			continue
		}

		user, pass, addr, err := acquireVkTurnSlot(ctx, link, streamID, ident)
		if err == nil {
			log.Printf("[STREAM %d] [VK Auth] Success with client_id=%s", streamID, creds.ClientID)
			return user, pass, addr, nil
		}

		lastErr = err
		log.Printf("[STREAM %d] [VK Auth] slot acquire failed (client_id=%s): %v", streamID, creds.ClientID, err)
		invalidateIdentity(link, creds.ClientID)

		if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") || strings.Contains(err.Error(), "FATAL_CAPTCHA") {
			return "", "", "", err
		}
		if strings.Contains(err.Error(), "error_code:29") || strings.Contains(err.Error(), "error_code: 29") || strings.Contains(err.Error(), "Rate limit") {
			log.Printf("[STREAM %d] [VK Auth] Rate limit detected, trying next credentials...", streamID)
		}
	}

	return "", "", "", fmt.Errorf("all VK credentials failed: %w", lastErr)
}

func vkDoRequest(ctx context.Context, client tlsclient.HttpClient, profile Profile, data, url string) (map[string]interface{}, error) {
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

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// acquireVkIdentity runs the heavy + captcha-gated portion of the VK auth chain
// (steps 1-3: get_anonym_token, calls.getCallPreview, calls.getAnonymousToken).
// The result is cached and reused across many TURN slot acquisitions.
//
// Per-client_id serialised + 3-6s cooldown to avoid VK API bans. Distinct
// client_ids run in parallel.
func acquireVkIdentity(ctx context.Context, link string, streamID int, creds VKCredentials) (*vkIdentity, error) {
	throttle := getVkThrottle(creds.ClientID)
	throttle.mu.Lock()
	defer throttle.mu.Unlock()

	minInterval := 3*time.Second + time.Duration(rand.Intn(3000))*time.Millisecond
	elapsed := time.Since(throttle.lastTime)
	if !throttle.lastTime.IsZero() && elapsed < minInterval {
		wait := minInterval - elapsed
		log.Printf("[STREAM %d] [VK Auth] Throttling client_id=%s: waiting %v...", streamID, creds.ClientID, wait.Truncate(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	defer func() {
		throttle.lastTime = time.Now()
	}()

	if time.Now().Unix() < globalCaptchaLockout.Load() {
		return nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active")
	}

	profile := Profile{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Not(A:Brand";v="99", "Google Chrome";v="146", "Chromium";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	}

	jar := tlsclient.NewCookieJar()
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithDialer(appDialer()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tls_client: %w", err)
	}

	name := generateName()
	escapedName := neturl.QueryEscape(name)

	log.Printf("[STREAM %d] [VK Auth] Connecting Identity - Name: %s | client_id=%s", streamID, name, creds.ClientID)

	// Step 1: anonym_token
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := vkDoRequest(ctx, client, profile, data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, err
	}
	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected anon token response: %v", resp)
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return nil, fmt.Errorf("missing access_token in response: %v", resp)
	}

	vkDelayRandom(100, 150)

	// Step 2: getCallPreview (best-effort)
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	_, err = vkDoRequest(ctx, client, profile, data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)
	if err != nil {
		log.Printf("[STREAM %d] [VK Auth] Warning: getCallPreview failed: %v", streamID, err)
	}

	vkDelayRandom(200, 400)

	// Step 3: getAnonymousToken (captcha-gated)
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)

	exhaustedCaptcha := func() error {
		globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())
		if connectedStreams.Load() == 0 {
			log.Printf("[STREAM %d] [FATAL] 0 connected streams and captcha solve modes exhausted.", streamID)
			return fmt.Errorf("FATAL_CAPTCHA_FAILED_NO_STREAMS")
		}
		return fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
	}

	var token2 string
	for attempt := 0; ; attempt++ {
		resp, err = vkDoRequest(ctx, client, profile, data, urlAddr)
		if err != nil {
			return nil, err
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			captchaErr := ParseVkCaptchaError(errObj)
			if captchaErr != nil && captchaErr.IsCaptchaError() {
				solveMode, hasSolveMode := captchaSolveModeForAttempt(attempt, manualCaptcha, autoCaptchaSliderPOC)
				if !hasSolveMode {
					log.Printf("[STREAM %d] [Captcha] No more solve modes available (attempt %d)", streamID, attempt+1)
					return nil, exhaustedCaptcha()
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
					// Manual solve waits on a human; keep generous timeout
					// independent of any auth-level deadline.
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
							t, e = solveCaptchaViaProxy(captchaErr.RedirectURI)
						} else if captchaErr.CaptchaImg != "" {
							k, e = solveCaptchaViaHTTP(captchaErr.CaptchaImg)
						} else {
							e = fmt.Errorf("no redirect_uri or captcha_img")
						}
						resCh <- manualRes{t, k, e}
					}()

					select {
					case res := <-resCh:
						// Token can arrive even when err != nil (e.g. server
						// Shutdown timeout after the token was already received).
						// A non-empty token/key counts as success.
						if res.token != "" || res.key != "" {
							successToken = res.token
							captchaKey = res.key
							if res.err != nil {
								log.Printf("[STREAM %d] [Captcha] Token received (ignoring cleanup error: %v)", streamID, res.err)
							}
						} else {
							solveErr = res.err
						}
					case <-manualCtx.Done():
						solveErr = fmt.Errorf("manual captcha timed out after 3m")
					}
					manualCancel()
				}

				if solveErr != nil {
					log.Printf("[STREAM %d] [Captcha] %s failed (attempt %d): %v", streamID, captchaSolveModeLabel(solveMode), attempt+1, solveErr)

					nextSolveMode, hasNextSolveMode := captchaSolveModeForAttempt(attempt+1, manualCaptcha, autoCaptchaSliderPOC)
					if hasNextSolveMode {
						log.Printf("[STREAM %d] [Captcha] Falling back to %s...", streamID, captchaSolveModeLabel(nextSolveMode))
						continue
					}
					return nil, exhaustedCaptcha()
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
			return nil, fmt.Errorf("VK API error: %v", errObj)
		}

		respMap, okLoop := resp["response"].(map[string]interface{})
		if !okLoop {
			return nil, fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}
		token2, okLoop = respMap["token"].(string)
		if !okLoop {
			return nil, fmt.Errorf("missing token in response: %v", resp)
		}
		break
	}

	return &vkIdentity{
		creds:     creds,
		profile:   profile,
		name:      name,
		token1:    token1,
		token2:    token2,
		client:    client,
		expiresAt: time.Now().Add(identityLifetime),
	}, nil
}

// acquireVkTurnSlot runs the lightweight portion of the chain (steps 4-5):
// auth.anonymLogin (with a fresh device_id) followed by vchat.joinConversationByLink.
// Each call returns a distinct (username, password) pair from VK, which lets us
// run multiple parallel TURN allocations under the same identity — bypassing
// per-username throttling without re-solving captcha.
func acquireVkTurnSlot(ctx context.Context, link string, streamID int, ident *vkIdentity) (string, string, string, error) {
	// Step 4: auth.anonymLogin with fresh device_id → fresh session_key
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data := fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
	resp, err := vkDoRequest(ctx, ident.client, ident.profile, data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}
	token3, ok := resp["session_key"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing session_key in response: %v", resp)
	}

	vkDelayRandom(100, 150)

	// Step 5: vchat.joinConversationByLink → turn_server creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, ident.token2, token3)
	resp, err = vkDoRequest(ctx, ident.client, ident.profile, data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}

	tsRaw, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("missing turn_server in response: %v", resp)
	}
	user, ok := tsRaw["username"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing username in turn_server")
	}
	pass, ok := tsRaw["credential"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing credential in turn_server")
	}
	urlsRaw, ok := tsRaw["urls"].([]interface{})
	if !ok || len(urlsRaw) == 0 {
		return "", "", "", fmt.Errorf("missing or empty urls in turn_server")
	}
	if isDebug {
		log.Printf("[STREAM %d] [VK Auth] turn_server urls: %v", streamID, urlsRaw)
	}

	// Prefer URLs whose transport matches the requested mode (udpMode).
	// Per RFC 7065, "?transport=tcp" → TCP, missing or "transport=udp" → UDP.
	// Fall back to the full list if nothing matches — this preserves the
	// -port override path where the user intentionally dials a port not
	// advertised in the URL list.
	all := make([]string, 0, len(urlsRaw))
	preferred := make([]string, 0, len(urlsRaw))
	for _, raw := range urlsRaw {
		s, ok := raw.(string)
		if !ok {
			continue
		}
		all = append(all, s)
		isTCP := strings.Contains(s, "transport=tcp")
		if udpMode == !isTCP {
			preferred = append(preferred, s)
		}
	}
	if len(all) == 0 {
		return "", "", "", fmt.Errorf("turn_server urls list contained no strings: %v", urlsRaw)
	}

	pool := preferred
	if len(pool) == 0 {
		pool = all
		log.Printf("[STREAM %d] [VK Auth] no urls match transport (udp=%v), falling back to full list (relying on -port override). urls=%v", streamID, udpMode, all)
	}

	// Round-robin within the identity. streamID%len(pool) collapses every
	// stream of the identity onto the same parity, so use a counter instead.
	urlIdx := int(ident.urlCounter.Add(1)-1) % len(pool)
	urlStr := pool[urlIdx]
	log.Printf("[STREAM %d] [VK Auth] turn_server urls=%d (preferred=%d), picked[%d]: %s", streamID, len(all), len(preferred), urlIdx, urlStr)

	clean := strings.Split(urlStr, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
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
	appD := appDialer()
	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         appD.DialContext,
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

	wsAppD := appDialer()
	dialer := websocket.Dialer{NetDialContext: wsAppD.DialContext}
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
		var cachedAddr net.Addr
		var cachedPtr any
		for {
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				return
			}

			// Send back to the active WG client. Cache addr locally — only
			// re-resolve when atomic.Value pointer changes (rare).
			peerAddr := activeLocalPeer.Load()
			if peerAddr == nil {
				continue
			}
			if peerAddr != cachedPtr {
				if a, ok := peerAddr.(net.Addr); ok {
					cachedAddr = a
					cachedPtr = peerAddr
				} else {
					continue
				}
			}
			if _, err := listenConn.WriteTo(buf[:n], cachedAddr); err != nil {
				log.Printf("[STREAM %d] failed to forward packet to local peer: %v", streamID, err)
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

type countingConn struct {
	net.Conn
	written atomic.Int64
	read    atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.read.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.written.Add(int64(n))
	}
	return n, err
}

func classifyNetErr(err error) string {
	if err == nil {
		return "nil"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "ctx-deadline"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "rst"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	if errors.Is(err, syscall.EPIPE) {
		return "broken-pipe"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "net-timeout"
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return "op:" + oe.Op
	}
	return "other"
}

type turnParams struct {
	host     string
	port     string
	link     string
	udp      bool
	getCreds getCredsFunc
}

// turnAllocation bundles a single TURN session: dial socket, TURN client, relay PacketConn.
type turnAllocation struct {
	dialConn io.Closer
	client   *turn.Client
	relay    net.PacketConn
}

func (a *turnAllocation) close() {
	if a.relay != nil {
		_ = a.relay.Close()
	}
	if a.client != nil {
		a.client.Close()
	}
	if a.dialConn != nil {
		_ = a.dialConn.Close()
	}
}

// dialTurn opens a fresh TURN session under the given (user, pass). Each call
// produces an independent 5-tuple (own source UDP/TCP port) and an independent
// TURN allocation. VK may or may not allow multiple allocations under the same
// credentials — caller must tolerate failures on additional sessions.
func dialTurn(ctx context.Context, useUDP bool, turnServerAddr string, turnServerUDPAddr *net.UDPAddr, addrFamily turn.RequestedAddressFamily, user, pass string, streamID int) (*turnAllocation, error) {
	var dialCloser io.Closer
	var turnConn net.PacketConn
	if useUDP {
		conn, err := net.DialUDP("udp", nil, turnServerUDPAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to TURN server: %w", err)
		}
		dialCloser = conn
		turnConn = &connectedUDPConn{conn}
	} else {
		ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var d net.Dialer
		conn, err := d.DialContext(ctx1, "tcp", turnServerAddr)
		if err != nil {
			log.Printf("[STREAM %d] [TURN] tcp dial %s failed: class=%s err=%v",
				streamID, turnServerAddr, classifyNetErr(err), err)
			return nil, fmt.Errorf("failed to connect to TURN server: %w", err)
		}
		if isDebug {
			log.Printf("[STREAM %d] [TURN] tcp established %s -> %s",
				streamID, conn.LocalAddr(), conn.RemoteAddr())
		}
		dialCloser = conn
		turnConn = turn.NewSTUNConn(&countingConn{Conn: conn})
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

	client, err := turn.NewClient(cfg)
	if err != nil {
		_ = dialCloser.Close()
		return nil, fmt.Errorf("failed to create TURN client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		_ = dialCloser.Close()
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	relay, err := client.Allocate()
	if err != nil {
		client.Close()
		_ = dialCloser.Close()
		return nil, fmt.Errorf("failed to allocate: %w", err)
	}

	return &turnAllocation{dialConn: dialCloser, client: client, relay: relay}, nil
}

// relayPool is a concurrent ring of live relay PacketConns. Reads (pick) are
// fully lock-free via atomic.Pointer to a snapshot slice (copy-on-write).
// add is rare and pays the alloc cost.
type relayPool struct {
	relays  atomic.Pointer[[]net.PacketConn]
	addMu   sync.Mutex
	counter atomic.Uint64
}

func (p *relayPool) add(r net.PacketConn) {
	p.addMu.Lock()
	defer p.addMu.Unlock()
	cur := p.relays.Load()
	var next []net.PacketConn
	if cur != nil {
		next = make([]net.PacketConn, len(*cur)+1)
		copy(next, *cur)
		next[len(*cur)] = r
	} else {
		next = []net.PacketConn{r}
	}
	p.relays.Store(&next)
}

func (p *relayPool) pick() net.PacketConn {
	cur := p.relays.Load()
	if cur == nil {
		return nil
	}
	n := len(*cur)
	if n == 0 {
		return nil
	}
	idx := int(p.counter.Add(1)-1) % n
	return (*cur)[idx]
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
	turnServerAddr := net.JoinHostPort(urlhost, urlport)
	log.Printf("[STREAM %d] [TURN] dialing %s (udp=%v)", streamID, turnServerAddr, turnParams.udp)
	turnServerUDPAddr, err1 := net.ResolveUDPAddr("udp", turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %s", err1)
		return
	}
	turnServerAddr = turnServerUDPAddr.String()
	fmt.Println(turnServerUDPAddr.IP)

	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	primary, err1 := dialTurn(ctx, turnParams.udp, turnServerAddr, turnServerUDPAddr, addrFamily, user, pass, streamID)
	if err1 != nil {
		if isAuthError(err1) {
			handleAuthError(streamID)
		}
		err = err1
		return
	}

	getStreamCache(streamID).errorCount.Store(0)

	connectedStreams.Add(1)
	defer connectedStreams.Add(-1)

	if isDebug {
		log.Printf("[STREAM %d] relayed-address=%s", streamID, primary.relay.LocalAddr().String())
	}

	pool := &relayPool{}
	pool.add(primary.relay)

	turnctx, turncancel := context.WithCancel(ctx)
	defer turncancel()

	// Track all allocations for clean shutdown.
	allocs := []*turnAllocation{primary}
	var allocsMu sync.Mutex
	defer func() {
		allocsMu.Lock()
		toClose := allocs
		allocs = nil
		allocsMu.Unlock()
		for _, a := range toClose {
			a.close()
		}
	}()

	context.AfterFunc(turnctx, func() {
		allocsMu.Lock()
		defer allocsMu.Unlock()
		for _, a := range allocs {
			if a.relay != nil {
				_ = a.relay.SetDeadline(time.Now())
			}
		}
	})

	var internalPipeAddr atomic.Value

	// Per-relay inbound goroutine: read from its own relay, forward to conn2.
	var inboundWg sync.WaitGroup
	spawnInbound := func(relay net.PacketConn) {
		inboundWg.Add(1)
		go func() {
			defer inboundWg.Done()
			defer turncancel()
			buf := make([]byte, 1600)
			for {
				n, _, err1 := relay.ReadFrom(buf)
				if err1 != nil {
					return
				}
				addr1 := internalPipeAddr.Load()
				if addr1 == nil {
					continue
				}
				if addr, ok := addr1.(net.Addr); ok {
					if _, err := conn2.WriteTo(buf[:n], addr); err != nil {
						return
					}
				}
			}
		}()
	}
	spawnInbound(primary.relay)

	// Outbound: read from conn2, send via round-robin across the relay pool.
	go func() {
		defer turncancel()
		buf := make([]byte, 1600)
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

			r := pool.pick()
			if r == nil {
				return
			}
			if _, err1 = r.WriteTo(buf[:n], peer); err1 != nil {
				return
			}
		}
	}()

	// Open extra allocations under the same creds. DTLS handshake completes
	// over the primary first; deferring extras lets the server install the
	// Connection ID so subsequent multi-path packets are matched to the
	// existing session via CID rather than 5-tuple.
	extras := allocsPerStream - 1
	if extras > 0 {
		go func() {
			select {
			case <-turnctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			for i := 0; i < extras; i++ {
				if turnctx.Err() != nil {
					return
				}
				extra, err := dialTurn(ctx, turnParams.udp, turnServerAddr, turnServerUDPAddr, addrFamily, user, pass, streamID)
				if err != nil {
					log.Printf("[STREAM %d] [TURN] extra alloc %d/%d failed: %v", streamID, i+1, extras, err)
					continue
				}
				log.Printf("[STREAM %d] [TURN] extra alloc %d/%d OK relay=%s", streamID, i+1, extras, extra.relay.LocalAddr())
				allocsMu.Lock()
				allocs = append(allocs, extra)
				allocsMu.Unlock()
				pool.add(extra.relay)
				spawnInbound(extra.relay)
				time.Sleep(200 * time.Millisecond)
			}
		}()
	}

	inboundWg.Wait()
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

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	globalAppCancel = cancel
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		select {
		case <-signalChan:
		case <-time.After(5 * time.Second):
		}
		log.Fatalf("Exit...\n")
	}()

	host := flag.String("turn", "", "override TURN server ip")
	port := flag.String("port", "", "override TURN port")
	listen := flag.String("listen", "127.0.0.1:9000", "listen on ip:port")
	vklink := flag.String("vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	yalink := flag.String("yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	peerAddr := flag.String("peer", "", "peer server address (host:port)")
	n := flag.Int("n", 0, "connections to TURN (default 10 for VK, 1 for Yandex)")
	udp := flag.Bool("udp", false, "connect to TURN with UDP")
	direct := flag.Bool("no-dtls", false, "connect without obfuscation. DO NOT USE")
	vlessMode := flag.Bool("vless", false, "VLESS mode: forward TCP connections (for VLESS) instead of UDP packets")
	debugFlag := flag.Bool("debug", false, "enable debug logging")
	manualCaptchaFlag := flag.Bool("manual-captcha", false, "skip auto captcha solving, use manual mode immediately")
	dnsFlag := flag.String("dns", DNSModeAuto, "DNS resolution mode: udp | doh | auto (auto tries UDP/53 first, sticky-fallback to DoH on total failure)")
	allocsFlag := flag.Int("allocs-per-stream", 1, "open this many TURN allocations per stream under shared creds (only useful if VK throttles per-allocation)")
	flag.Parse()
	switch *dnsFlag {
	case DNSModeUDP, DNSModeDoH, DNSModeAuto:
		dnsMode = *dnsFlag
	default:
		log.Panicf("invalid -dns value %q (expected udp|doh|auto)", *dnsFlag)
	}
	log.Printf("[DNS] mode=%s", dnsMode)
	if *peerAddr == "" {
		log.Panicf("Need peer address!")
	}
	peer, err := net.ResolveUDPAddr("udp", *peerAddr)
	if err != nil {
		panic(err)
	}
	if (*vklink == "") == (*yalink == "") {
		log.Panicf("Need either vk-link or yandex-link!")
	}

	isDebug = *debugFlag
	manualCaptcha = *manualCaptchaFlag
	autoCaptchaSliderPOC = !manualCaptcha
	allocsPerStream = *allocsFlag
	if allocsPerStream < 1 {
		allocsPerStream = 1
	}
	udpMode = *udp

	var link string
	var getCreds getCredsFunc
	if *vklink != "" {
		parts := strings.Split(*vklink, "join/")
		link = parts[len(parts)-1]

		getCreds = func(ctx context.Context, s string, streamID int) (string, string, string, error) {
			return getVkCredsCached(ctx, s, streamID)
		}
		if *n <= 0 {
			*n = 10
		}
	} else {
		parts := strings.Split(*yalink, "j/")
		link = parts[len(parts)-1]
		getCreds = func(ctx context.Context, s string, streamID int) (string, string, string, error) {
			return getYandexCreds(s)
		}
		if *n <= 0 {
			*n = 1
		}
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	params := &turnParams{
		host:     *host,
		port:     *port,
		link:     link,
		udp:      *udp,
		getCreds: getCreds,
	}

	if *vlessMode {
		runVLESSMode(ctx, params, peer, *listen, *n)
		return
	}

	listenConn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Printf("Failed to close local connection: %s", closeErr)
		}
	})

	numStreams := *n
	if numStreams <= 0 {
		numStreams = 1
	}

	// Shared Worker Pool Queue for Aggregation
	inboundChan := make(chan *UDPPacket, 8192)
	var droppedPkts atomic.Uint64

	go func() {
		dropTicker := time.NewTicker(5 * time.Second)
		defer dropTicker.Stop()
		var lastDropped uint64
		for range dropTicker.C {
			cur := droppedPkts.Load()
			if cur != lastDropped {
				log.Printf("[inbound] dropped %d pkts since start (delta=%d) — queue saturated", cur, cur-lastDropped)
				lastDropped = cur
			}
		}
	}()

	go func() {
		var lastAddrStr string
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

			// Save local WireGuard peer addr; cache string to avoid repeated
			// type-assert + String() in hot path.
			s := addr.String()
			if s != lastAddrStr {
				activeLocalPeer.Store(addr)
				lastAddrStr = s
			}

			pkt.N = nRead

			select {
			case inboundChan <- pkt:
			default:
				droppedPkts.Add(1)
				packetPool.Put(pkt)
			}
		}
	}()

	wg1 := sync.WaitGroup{}
	t := time.Tick(200 * time.Millisecond)

	if *direct {
		log.Panicf("Direct mode not supported with dispatcher")
	}

	okchan := make(chan struct{})
	connchan := make(chan net.PacketConn)
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		oneDtlsConnectionLoop(ctx, peer, listenConn, inboundChan, connchan, okchan, 1)
	}()
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		oneTurnConnectionLoop(ctx, params, peer, connchan, t, 1)
	}()

	select {
	case <-okchan:
	case <-ctx.Done():
	}

	for i := 2; i <= numStreams; i++ {
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
}

// sessionPool manages smux sessions for round-robin TCP distribution.
// Lock-free reads via atomic.Pointer copy-on-write snapshot.
type sessionPool struct {
	sessions atomic.Pointer[[]*smux.Session]
	mu       sync.Mutex
	counter  atomic.Uint64
}

func (p *sessionPool) snapshot() []*smux.Session {
	cur := p.sessions.Load()
	if cur == nil {
		return nil
	}
	return *cur
}

func (p *sessionPool) add(s *smux.Session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.snapshot()
	next := make([]*smux.Session, len(cur)+1)
	copy(next, cur)
	next[len(cur)] = s
	p.sessions.Store(&next)
}

func (p *sessionPool) remove(s *smux.Session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.snapshot()
	next := make([]*smux.Session, 0, len(cur))
	for _, sess := range cur {
		if sess != s {
			next = append(next, sess)
		}
	}
	p.sessions.Store(&next)
}

func (p *sessionPool) pick() *smux.Session {
	cur := p.snapshot()
	n := len(cur)
	if n == 0 {
		return nil
	}
	idx := p.counter.Add(1) % uint64(n)
	return cur[idx]
}

func (p *sessionPool) count() int {
	return len(p.snapshot())
}

// runVLESSMode implements TCP forwarding with round-robin across N TURN sessions.
func runVLESSMode(ctx context.Context, tp *turnParams, peer *net.UDPAddr, listenAddr string, numSessions int) {
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
	context.AfterFunc(ctx, func() { _ = listener.Close() })
	log.Printf("VLESS mode: listening on %s (round-robin across %d sessions)", listenAddr, numSessions)

	var wgConn sync.WaitGroup
	for {
		tcpConn, err := listener.Accept()
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

		sess := pool.pick()
		if sess == nil || sess.IsClosed() {
			log.Printf("No active sessions, rejecting connection")
			_ = tcpConn.Close()
			continue
		}

		wgConn.Add(1)
		go func(tc net.Conn, s *smux.Session) {
			defer wgConn.Done()
			defer func() { _ = tc.Close() }()
			stream, err := s.OpenStream()
			if err != nil {
				log.Printf("smux open stream error: %s", err)
				return
			}
			defer func() { _ = stream.Close() }()
			pipe(ctx, tc, stream)
		}(tcpConn, sess)
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
			log.Printf("[session %d] setup error: %s, retrying...", id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}

		pool.add(smuxSess)
		log.Printf("[session %d] connected (active: %d)", id, pool.count())

		for !smuxSess.IsClosed() {
			select {
			case <-ctx.Done():
				pool.remove(smuxSess)
				cleanup()
				return
			case <-time.After(1 * time.Second):
			}
		}

		pool.remove(smuxSess)
		cleanup()
		log.Printf("[session %d] disconnected (active: %d), reconnecting...", id, pool.count())

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
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
	fmt.Println(turnServerUDPAddr.IP)

	// 2. Connect to TURN server
	var turnConn net.PacketConn
	ctx1, cancel1 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel1()
	if tp.udp {
		c, err1 := net.DialUDP("udp", nil, turnServerUDPAddr)
		if err1 != nil {
			return nil, nil, fmt.Errorf("dial TURN (udp): %w", err1)
		}
		cleanupFns = append(cleanupFns, func() { _ = c.Close() })
		turnConn = &connectedUDPConn{c}
	} else {
		var d net.Dialer
		c, err1 := d.DialContext(ctx1, "tcp", turnServerAddr)
		if err1 != nil {
			return nil, nil, fmt.Errorf("dial TURN (tcp): %w", err1)
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
		return nil, nil, fmt.Errorf("TURN listen: %w", err)
	}
	relayConn, err := turnClient.Allocate()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("TURN allocate: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = relayConn.Close() })
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	// 4. Establish DTLS over TURN relay
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("generate cert: %w", err)
	}
	dtlsPC := &relayPacketConn{relay: relayConn, peer: peer}
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
		return nil, nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = dtlsConn.Close() })
	log.Printf("DTLS connection established")

	// 5. Create KCP session over DTLS
	kcpSess, err := tcputil.NewKCPOverDTLS(dtlsConn, false)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("KCP session: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = kcpSess.Close() })
	log.Printf("KCP session established")

	// 6. Create smux client session over KCP
	smuxSess, err := smux.Client(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("smux client: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = smuxSess.Close() })
	log.Printf("smux session established")

	return smuxSess, cleanup, nil
}

// relayPacketConn wraps a TURN relay PacketConn to direct all writes to the peer.
type relayPacketConn struct {
	relay net.PacketConn
	peer  net.Addr
}

func (r *relayPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return r.relay.ReadFrom(b)
}

func (r *relayPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return r.relay.WriteTo(b, r.peer)
}

func (r *relayPacketConn) Close() error                       { return r.relay.Close() }
func (r *relayPacketConn) LocalAddr() net.Addr                { return r.relay.LocalAddr() }
func (r *relayPacketConn) SetDeadline(t time.Time) error      { return r.relay.SetDeadline(t) }
func (r *relayPacketConn) SetReadDeadline(t time.Time) error  { return r.relay.SetReadDeadline(t) }
func (r *relayPacketConn) SetWriteDeadline(t time.Time) error { return r.relay.SetWriteDeadline(t) }

// pipe copies data bidirectionally between two connections.
func pipe(ctx context.Context, c1, c2 net.Conn) {
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
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		if _, err := io.Copy(c1, c2); err != nil {
			log.Printf("pipe: c1<-c2 copy error: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		if _, err := io.Copy(c2, c1); err != nil {
			log.Printf("pipe: c2<-c1 copy error: %v", err)
		}
	}()
	wg.Wait()
	if err := c1.SetDeadline(time.Time{}); err != nil {
		log.Printf("pipe: failed to reset deadline c1: %v", err)
	}
	if err := c2.SetDeadline(time.Time{}); err != nil {
		log.Printf("pipe: failed to reset deadline c2: %v", err)
	}
}
