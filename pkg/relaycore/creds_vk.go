// SPDX-License-Identifier: GPL-3.0-only

package relaycore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
	"github.com/google/uuid"
)

type vkCredentialProvider struct {
	dialer *dnsdialer.Dialer
	logger *log.Logger
}

type vkCaptchaError struct {
	ErrorCode      int
	ErrorMsg       string
	CaptchaSid     string
	RedirectURI    string
	SessionToken   string
	CaptchaTs      string
	CaptchaAttempt string
}

func NewDefaultDNSDialer() *dnsdialer.Dialer {
	return dnsdialer.New(
		dnsdialer.WithResolvers("77.88.8.8:53", "77.88.8.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"),
		dnsdialer.WithStrategy(dnsdialer.Fallback{}),
		dnsdialer.WithCache(100, 10*time.Hour, 10*time.Hour),
	)
}

func NewVKCredentialProvider(dialer *dnsdialer.Dialer) CredentialProvider {
	if dialer == nil {
		dialer = NewDefaultDNSDialer()
	}

	return &vkCredentialProvider{
		dialer: dialer,
		logger: log.Default(),
	}
}

func (p *vkCredentialProvider) GetCredentials(ctx context.Context, inviteLink string) (TurnCredentials, error) {
	profile := getRandomProfile()
	name := generateName()
	escapedName := neturl.QueryEscape(name)

	p.logger.Printf("connecting identity - name: %s | user-agent: %s", name, profile.UserAgent)

	doRequest := func(requestCtx context.Context, data string, url string) (map[string]interface{}, error) {
		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DialContext:         p.dialer.DialContext,
			},
		}
		defer client.CloseIdleConnections()

		req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Header.Add("User-Agent", profile.UserAgent)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

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

	data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
	url := "https://login.vk.ru/?act=get_anonym_token"

	resp, err := doRequest(ctx, data, url)
	if err != nil {
		return TurnCredentials{}, fmt.Errorf("request error: %w", err)
	}

	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return TurnCredentials{}, fmt.Errorf("unexpected anon token response: %v", resp)
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return TurnCredentials{}, fmt.Errorf("missing access_token in response: %v", resp)
	}

	data = fmt.Sprintf(
		"vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s",
		inviteLink,
		escapedName,
		token1,
	)
	url = "https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=6287487"

	var token2 string
	const maxCaptchaAttempts = 3
	for attempt := 0; attempt <= maxCaptchaAttempts; attempt++ {
		resp, err = doRequest(ctx, data, url)
		if err != nil {
			return TurnCredentials{}, fmt.Errorf("request error: %w", err)
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			errCode, _ := errObj["error_code"].(float64)
			if errCode == 14 {
				if attempt == maxCaptchaAttempts {
					return TurnCredentials{}, fmt.Errorf("captcha failed after %d attempts", maxCaptchaAttempts)
				}

				captchaErr := parseVKCaptchaError(errObj)
				if captchaErr.SessionToken == "" {
					return TurnCredentials{}, fmt.Errorf("old image captcha detected: unsupported in auto solver")
				}

				successToken, solveErr := solveVKCaptcha(ctx, captchaErr, p.dialer, p.logger)
				if solveErr != nil {
					return TurnCredentials{}, fmt.Errorf("auto captcha solve error: %w", solveErr)
				}

				if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
					captchaErr.CaptchaAttempt = "1"
				}

				data = fmt.Sprintf(
					"vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s",
					inviteLink,
					escapedName,
					token1,
					captchaErr.CaptchaSid,
					neturl.QueryEscape(successToken),
					captchaErr.CaptchaTs,
					captchaErr.CaptchaAttempt,
				)
				continue
			}
			return TurnCredentials{}, fmt.Errorf("VK API error: %v", errObj)
		}

		respMap, ok := resp["response"].(map[string]interface{})
		if !ok {
			return TurnCredentials{}, fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}
		token2, ok = respMap["token"].(string)
		if !ok {
			return TurnCredentials{}, fmt.Errorf("missing token in response: %v", resp)
		}
		break
	}

	data = fmt.Sprintf(
		"%s%s%s",
		"session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22",
		uuid.New(),
		"%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA",
	)
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(ctx, data, url)
	if err != nil {
		return TurnCredentials{}, fmt.Errorf("request error: %w", err)
	}

	token3, ok := resp["session_key"].(string)
	if !ok {
		return TurnCredentials{}, fmt.Errorf("missing session_key in response: %v", resp)
	}

	data = fmt.Sprintf(
		"joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s",
		inviteLink,
		token2,
		token3,
	)
	resp, err = doRequest(ctx, data, url)
	if err != nil {
		return TurnCredentials{}, fmt.Errorf("request error: %w", err)
	}

	turnServer, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return TurnCredentials{}, fmt.Errorf("missing turn_server in response: %v", resp)
	}

	user, _ := turnServer["username"].(string)
	pass, _ := turnServer["credential"].(string)
	urls, _ := turnServer["urls"].([]interface{})
	if len(urls) == 0 {
		return TurnCredentials{}, fmt.Errorf("missing TURN urls in response: %v", resp)
	}

	turnURL, _ := urls[0].(string)
	clean := strings.Split(turnURL, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return TurnCredentials{
		Username: user,
		Password: pass,
		Address:  address,
	}, nil
}

func parseVKCaptchaError(errData map[string]interface{}) *vkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	redirectURI, _ := errData["redirect_uri"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	captchaSid, _ := errData["captcha_sid"].(string)
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

func solveVKCaptcha(ctx context.Context, captchaErr *vkCaptchaError, dialer *dnsdialer.Dialer, logger *log.Logger) (string, error) {
	logger.Printf("solving VK Smart Captcha automatically")
	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	powInput, difficulty, err := fetchPoWInput(ctx, captchaErr.RedirectURI, dialer)
	if err != nil {
		return "", fmt.Errorf("failed to fetch PoW input: %w", err)
	}

	hash := solvePoW(powInput, difficulty)
	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, dialer)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	logger.Printf("VK Smart Captcha solved successfully")
	return successToken, nil
}

func fetchPoWInput(ctx context.Context, redirectURI string, dialer *dnsdialer.Dialer) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, redirectURI, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", defaultBrowserUserAgent)
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
	defer resp.Body.Close()

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
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", defaultBrowserUserAgent)
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
		defer httpResp.Body.Close()

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

	if _, err := vkReq("captchaNotRobot.settings", baseParams); err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	time.Sleep(200 * time.Millisecond)

	browserFp := fmt.Sprintf("%032x", rand.Int63())
	deviceJSON := `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1032,"innerWidth":1920,"innerHeight":945,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":16,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, neturl.QueryEscape(deviceJSON))

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}
	time.Sleep(200 * time.Millisecond)

	cursorJSON := `[{"x":950,"y":500},{"x":945,"y":510},{"x":940,"y":520},{"x":938,"y":525},{"x":938,"y":525}]`
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))
	debugInfo := "d44f534ce8deb56ba20be52e05c433309b49ee4d2a70602deeb17a1954257785"

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5]"),
		browserFp,
		hash,
		answer,
		debugInfo,
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}
	status, _ := respObj["status"].(string)
	if status != "OK" {
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found")
	}

	time.Sleep(200 * time.Millisecond)
	_, _ = vkReq("captchaNotRobot.endSession", baseParams)

	return successToken, nil
}
