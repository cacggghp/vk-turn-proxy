// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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

type getCredsFunc func(string) (string, string, string, error)

type directNet struct{}

type directDialer struct {
	*net.Dialer
}

type directListenConfig struct {
	*net.ListenConfig
}

// globalClientWGAddr safely stores the UDP address of the local WireGuard client
var globalClientWGAddr atomic.Value

func newDirectNet() transport.Net {
	return directNet{}
}

func (directNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address) //nolint:noctx
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
	return net.Dial(network, address) //nolint:noctx
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

// region automatic captcha solver

type vkCaptchaError struct {
	ErrorCode      int
	ErrorMsg       string
	CaptchaSid     string
	RedirectURI    string
	SessionToken   string
	CaptchaTs      string
	CaptchaAttempt string
}

func parseVkCaptchaError(errData map[string]interface{}) *vkCaptchaError {
	var codeFloat float64
	if val, ok := errData["error_code"].(float64); ok {
		codeFloat = val
	}

	var redirectURI string
	if val, ok := errData["redirect_uri"].(string); ok {
		redirectURI = val
	}

	var errorMsg string
	if val, ok := errData["error_msg"].(string); ok {
		errorMsg = val
	}

	var captchaSid string
	if val, ok := errData["captcha_sid"].(string); ok {
		captchaSid = val
	}

	if captchaSid == "" {
		if sidNum, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}

	var sessionToken string
	if redirectURI != "" {
		if parsed, err := neturl.Parse(redirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &vkCaptchaError{
		ErrorCode:      int(codeFloat),
		ErrorMsg:       errorMsg,
		CaptchaSid:     captchaSid,
		RedirectURI:    redirectURI,
		SessionToken:   sessionToken,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}

func solveVkCaptcha(ctx context.Context, captchaErr *vkCaptchaError, dialer *dnsdialer.Dialer) (string, error) {
	log.Printf("Solving VK Smart Captcha automatically...")
	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	powInput, difficulty, err := fetchPowInput(ctx, captchaErr.RedirectURI, dialer)
	if err != nil {
		return "", fmt.Errorf("failed to fetch PoW input: %w", err)
	}

	hash := solvePoW(powInput, difficulty)

	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, dialer)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	log.Printf("VK Smart Captcha Solved Successfully!")
	return successToken, nil
}

func fetchPowInput(ctx context.Context, redirectURI string, dialer *dnsdialer.Dialer) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Failed to close response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}
	html := string(body)

	powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	powInputMatch := powInputRe.FindStringSubmatch(html)
	if len(powInputMatch) < 2 {
		return "", 0, fmt.Errorf("powInput not found in captcha HTML")
	}
	powInput := powInputMatch[1]

	diffRe := regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`)
	diffMatch := diffRe.FindStringSubmatch(html)
	difficulty := 2
	if len(diffMatch) >= 2 {
		if d, err := strconv.Atoi(diffMatch[1]); err == nil {
			difficulty = d
		}
	}
	return powInput, difficulty, nil
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

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash string, dialer *dnsdialer.Dialer) (string, error) {
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")

		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext: dialer.DialContext,
			},
		}

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("Failed to close response body: %v", closeErr)
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

	baseParams := fmt.Sprintf("session_token=%s&domain=vk.com&adFp=&access_token=", neturl.QueryEscape(sessionToken))

	// Step 1: settings
	if _, err := vkReq("captchaNotRobot.settings", baseParams); err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Step 2: componentDone
	browserFp := fmt.Sprintf("%032x", rand.Int63())
	deviceJSON := `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1032,"innerWidth":1920,"innerHeight":945,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":16,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, neturl.QueryEscape(deviceJSON))

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Step 3: check
	cursorJSON := `[{"x":950,"y":500},{"x":945,"y":510},{"x":940,"y":520},{"x":938,"y":525},{"x":938,"y":525}]`
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))
	debugInfo := "d44f534ce8deb56ba20be52e05c433309b49ee4d2a70602deeb17a1954257785"

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
		neturl.QueryEscape("[9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5]"),
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

	// Step 4: endSession
	if _, err := vkReq("captchaNotRobot.endSession", baseParams); err != nil {
		log.Printf("endSession failed: %v", err)
	}

	return successToken, nil
}

// endregion automatic captcha solver

var (
	cachedCaptchaTokenMu sync.Mutex
	cachedCaptchaToken   string
)

func getVkCreds(link string, dialer *dnsdialer.Dialer) (string, string, string, error) {
	profile := getRandomProfile()
	name := generateName()
	escapedName := neturl.QueryEscape(name)

	log.Printf("Connecting Identity - Name: %s | User-Agent: %s", name, profile.UserAgent)

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DialContext:         dialer.DialContext,
			},
		}
		defer client.CloseIdleConnections()

		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Header.Add("User-Agent", profile.UserAgent)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

	var resp map[string]interface{}
	defer func() {
		if r := recover(); r != nil {
			log.Panicf("get TURN creds error: %v\n\n", resp)
		}
	}()

	data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
	url := "https://login.vk.ru/?act=get_anonym_token"

	resp, err := doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("unexpected anon token response: %v", resp)
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing access_token in response: %v", resp)
	}

	cachedCaptchaTokenMu.Lock()
	curSuccessToken := cachedCaptchaToken
	cachedCaptchaTokenMu.Unlock()

	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	if curSuccessToken != "" {
		data += fmt.Sprintf("&success_token=%s", neturl.QueryEscape(curSuccessToken))
	}
	url = "https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=6287487"

	var token2 string
	const maxCaptchaAttempts = 3
	for attempt := 0; attempt <= maxCaptchaAttempts; attempt++ {
		resp, err = doRequest(data, url)
		if err != nil {
			return "", "", "", fmt.Errorf("request error:%s", err)
		}

		// Check for captcha error
		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			errCode, ok2 := errObj["error_code"].(float64)
			if ok2 && errCode == 14 {
				if attempt == maxCaptchaAttempts {
					return "", "", "", fmt.Errorf("captcha failed after %d attempts", maxCaptchaAttempts)
				}

				captchaErr := parseVkCaptchaError(errObj)
				if captchaErr.SessionToken != "" {
					successToken, solveErr := solveVkCaptcha(context.Background(), captchaErr, dialer)
					if solveErr != nil {
						return "", "", "", fmt.Errorf("auto captcha solve error: %w", solveErr)
					}

					cachedCaptchaTokenMu.Lock()
					cachedCaptchaToken = successToken
					cachedCaptchaTokenMu.Unlock()

					if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
						captchaErr.CaptchaAttempt = "1"
					}

					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s",
						link, escapedName, token1, captchaErr.CaptchaSid, neturl.QueryEscape(successToken), captchaErr.CaptchaTs, captchaErr.CaptchaAttempt)
					continue
				} else {
					return "", "", "", fmt.Errorf("old image captcha detected - not supported in auto solver")
				}
			}
			return "", "", "", fmt.Errorf("VK API error: %v", errObj)
		}

		respMap, okLoop := resp["response"].(map[string]interface{})
		if !okLoop {
			return "", "", "", fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}
		token2, okLoop = respMap["token"].(string)
		if !okLoop {
			return "", "", "", fmt.Errorf("missing token in response: %v", resp)
		}
		break
	}

	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token3, ok := resp["session_key"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing session_key in response: %v", resp)
	}

	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	turnServer, ok2 := resp["turn_server"].(map[string]interface{})
	if !ok2 {
		return "", "", "", fmt.Errorf("missing turn_server in response: %v", resp)
	}

	user, ok2 := turnServer["username"].(string)
	if !ok2 {
		return "", "", "", fmt.Errorf("missing username in turn_server: %v", turnServer)
	}

	pass, ok2 := turnServer["credential"].(string)
	if !ok2 {
		return "", "", "", fmt.Errorf("missing credential in turn_server: %v", turnServer)
	}

	urls, ok2 := turnServer["urls"].([]interface{})
	if !ok2 || len(urls) == 0 {
		return "", "", "", fmt.Errorf("missing or empty urls in turn_server: %v", turnServer)
	}

	turn, ok2 := urls[0].(string)
	if !ok2 {
		return "", "", "", fmt.Errorf("first url is not a string: %v", urls[0])
	}

	clean := strings.Split(turn, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}

func getYandexCreds(link string) (string, string, string, error) {
	const debug = false
	const telemostConfHost = "cloud-api.yandex.ru"
	telemostConfPath := fmt.Sprintf("%s%s%s", "/telemost_front/v2/telemost/conferences/https%3A%2F%2Ftelemost.yandex.ru%2Fj%2F", link, "/connection?next_gen_media_platform_allowed=false")
	profile := getRandomProfile()
	userAgent := profile.UserAgent
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
	req.Header.Set("User-Agent", userAgent)
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
	h.Set("User-Agent", userAgent)

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
				UserAgent:      userAgent,
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

	if debug {
		b, err2 := json.MarshalIndent(req1, "", "  ")
		if err2 != nil {
			log.Printf("Failed to marshal HELLO: %v", err2)
		} else {
			log.Printf("Sending HELLO:\n%s", string(b))
		}
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
		if debug {
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
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Client(conn, peer, config)
	if err != nil {
		return nil, err
	}

	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}

func oneDtlsConnection(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, c chan<- error) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error
	defer func() { c <- err }()
	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()
	var conn1, conn2 net.PacketConn
	conn1, conn2 = connutil.AsyncPacketPipe()
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
		err = fmt.Errorf("failed to connect DTLS: %s", err1)
		return
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close DTLS connection: %s", closeErr)
			return
		}
		log.Printf("Closed DTLS connection\n")
	}()
	log.Printf("Established DTLS connection!\n")

	// Trigger the okchan safely to spawn the rest of the threads
	if okchan != nil {
		go func() {
			select {
			case okchan <- struct{}{}:
			case <-dtlsctx.Done():
			}
		}()
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	context.AfterFunc(dtlsctx, func() {
		if err := listenConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set listener deadline: %s", err)
		}
		if err := dtlsConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set DTLS deadline: %s", err)
		}
	})

	// Start read-loop on listenConn
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, addr1, err1 := listenConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			globalClientWGAddr.Store(addr1) // store local WG peer address globally

			_, err1 = dtlsConn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	// Start read-loop on dtlsConn
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			addr1, ok := globalClientWGAddr.Load().(net.Addr)
			if !ok {
				// Safely drop packet if wireguard hasn't sent an initial packet yet
				continue
			}

			_, err1 = listenConn.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	wg.Wait()
	if err := listenConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear listener deadline: %s", err)
	}
	if err := dtlsConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear DTLS deadline: %s", err)
	}
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
	getCreds getCredsFunc
}

func oneTurnConnection(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, c chan<- error) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error
	defer func() { c <- err }()
	user, pass, url, err1 := turnParams.getCreds(turnParams.link)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		return
	}
	urlhost, urlport, err1 := net.SplitHostPort(url)
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
	fmt.Println(turnServerUDPAddr.IP)
	// Dial TURN Server
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
		conn, err2 := d.DialContext(ctx1, "tcp", turnServerAddr) // nolint: noctx
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
	// Start a new TURN Client and wrap our net.Conn in a STUNConn
	// This allows us to simulate datagram based communication over a net.Conn
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

	// Start listening on the conn provided.
	err1 = client.Listen()
	if err1 != nil {
		err = fmt.Errorf("failed to listen: %s", err1)
		return
	}

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = fmt.Errorf("failed to allocate: %s", err1)
		return
	}
	defer func() {
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
		}
	}()

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(context.Background())
	context.AfterFunc(turnctx, func() {
		if err := relayConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set relay deadline: %s", err)
		}
		if err := conn2.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set upstream deadline: %s", err)
		}
	})
	var internalPipeAddr atomic.Value
	// Start read-loop on conn2 (output of DTLS)
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, addr1, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			internalPipeAddr.Store(addr1) // store local async pipe peer

			_, err1 = relayConn.WriteTo(buf[:n], peer)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	// Start read-loop on relayConn
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr1, ok := internalPipeAddr.Load().(net.Addr)
			if !ok {
				log.Printf("Failed: no listener ip")
				return
			}

			_, err1 = conn2.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	wg.Wait()
	if err := relayConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear relay deadline: %s", err)
	}
	if err := conn2.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear upstream deadline: %s", err)
	}
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, listenConnChan <-chan net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case listenConn := <-listenConnChan:
			c := make(chan error)
			go oneDtlsConnection(ctx, peer, listenConn, connchan, okchan, c)
			if err := <-c; err != nil {
				log.Printf("%s", err)
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			// Ensure we block cleanly until the tick signals to proceed
			select {
			case <-t:
			case <-ctx.Done():
				return
			}
			c := make(chan error)
			go oneTurnConnection(ctx, turnParams, peer, conn2, c)
			if err := <-c; err != nil {
				log.Printf("%s", err)
			}
		}
	}
}

type turnCred struct {
	user, pass, addr string
}

// poolCreds allows retrieving unique TURN credentials for N distinct connections.
// Because it natively handles the automatic captcha bypass, every request gets a unique identity safely.
func poolCreds(f getCredsFunc, poolSize int) getCredsFunc {
	var mu sync.Mutex
	var pool []turnCred
	var cTime time.Time
	var idx int

	return func(link string) (string, string, string, error) {
		mu.Lock()
		defer mu.Unlock()

		// Refresh identities every 10 minutes
		if !cTime.IsZero() && time.Since(cTime) > 10*time.Minute {
			pool = nil
			cTime = time.Time{}
		}

		if len(pool) < poolSize {
			u, p, a, err := f(link)
			if err == nil {
				pool = append(pool, turnCred{u, p, a})
				cTime = time.Now()
				log.Printf("Successfully registered User Identity %d/%d", len(pool), poolSize)

				// Space out requests by 1000ms to avoid API limits
				if len(pool) < poolSize {
					time.Sleep(1000 * time.Millisecond)
				}

				c := pool[len(pool)-1]
				idx++
				return c.user, c.pass, c.addr, nil
			}

			log.Printf("Failed to get unique TURN identity: %v", err)
			if len(pool) > 0 {
				log.Printf("Falling back to reusing a previous identity...")
				c := pool[idx%len(pool)]
				idx++
				return c.user, c.pass, c.addr, nil
			}
			return "", "", "", err
		}

		c := pool[idx%len(pool)]
		idx++
		return c.user, c.pass, c.addr, nil
	}
}

func main() { //nolint:cyclop
	ctx, cancel := context.WithCancel(context.Background())
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
	flag.Parse()
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

	var link string
	var getCreds getCredsFunc
	if *vklink != "" {
		parts := strings.Split(*vklink, "join/")
		link = parts[len(parts)-1]

		dialer := dnsdialer.New(
			dnsdialer.WithResolvers("77.88.8.8:53", "77.88.8.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"),
			dnsdialer.WithStrategy(dnsdialer.Fallback{}),
			dnsdialer.WithCache(100, 10*time.Hour, 10*time.Hour),
		)

		getCreds = func(s string) (string, string, string, error) {
			return getVkCreds(s, dialer)
		}
		if *n <= 0 {
			*n = 10
		}
	} else {
		parts := strings.Split(*yalink, "j/")
		link = parts[len(parts)-1]
		getCreds = getYandexCreds
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
		getCreds: poolCreds(getCreds, 1),
	}

	if *vlessMode {
		runVLESSMode(ctx, params, peer, *listen, *n)
		return
	}

	listenConnChan := make(chan net.PacketConn)
	listenConn, err := net.ListenPacket("udp", *listen) // nolint: noctx
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Panicf("Failed to close local connection: %s", closeErr)
		}
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenConnChan <- listenConn:
			}
		}
	}()

	wg1 := sync.WaitGroup{}
	t := time.Tick(200 * time.Millisecond)
	if *direct {
		for i := 0; i < *n; i++ {
			wg1.Add(1)
			go func() {
				defer wg1.Done()
				oneTurnConnectionLoop(ctx, params, peer, listenConnChan, t)
			}()
		}
	} else {
		okchan := make(chan struct{})
		connchan := make(chan net.PacketConn)

		wg1.Add(1)
		go func() {
			defer wg1.Done()
			oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, okchan)
		}()

		wg1.Add(1)
		go func() {
			defer wg1.Done()
			oneTurnConnectionLoop(ctx, params, peer, connchan, t)
		}()

		select {
		case <-okchan:
		case <-ctx.Done():
		}
		for i := 0; i < *n-1; i++ {
			connchan := make(chan net.PacketConn)
			wg1.Add(1)
			go func() {
				defer wg1.Done()
				oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, nil)
			}()
			wg1.Add(1)
			go func() {
				defer wg1.Done()
				oneTurnConnectionLoop(ctx, params, peer, connchan, t)
			}()
		}
	}

	wg1.Wait()
}

// sessionPool manages a pool of smux sessions for round-robin TCP distribution.
type sessionPool struct {
	mu       sync.RWMutex
	sessions []*smux.Session
	counter  atomic.Uint64
}

func (p *sessionPool) add(s *smux.Session) {
	p.mu.Lock()
	p.sessions = append(p.sessions, s)
	p.mu.Unlock()
}

func (p *sessionPool) remove(s *smux.Session) {
	p.mu.Lock()
	for i, sess := range p.sessions {
		if sess == s {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
}

func (p *sessionPool) pick() *smux.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.sessions)
	if n == 0 {
		return nil
	}
	idx := p.counter.Add(1) % uint64(n)
	return p.sessions[idx]
}

func (p *sessionPool) count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
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

		smuxSess, cleanup, err := createSmuxSession(ctx, tp, peer)
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
func createSmuxSession(ctx context.Context, tp *turnParams, peer *net.UDPAddr) (*smux.Session, func(), error) {
	var cleanupFns []func()
	cleanup := func() {
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			cleanupFns[i]()
		}
	}

	// 1. Get TURN credentials
	user, pass, rawURL, err := tp.getCreds(tp.link)
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
	dtlsConfig := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	dtlsConn, err := dtls.Client(dtlsPC, peer, dtlsConfig)
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
