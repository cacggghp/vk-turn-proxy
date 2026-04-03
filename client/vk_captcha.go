// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	vkCaptchaAPIVersion = "5.275"
	vkCaptchaNotRobotVer = "5.131"
	vkDebugInfo          = "d44f534ce8deb56ba20be52e05c433309b49ee4d2a70602deeb17a1954257785"
)

// VkCaptchaData holds captcha challenge data from VK error response
type VkCaptchaData struct {
	CaptchaSid     string
	CaptchaTs      string
	CaptchaAttempt string
	RedirectURI    string
	SessionToken   string
}

// ExtractCaptchaData parses VK API error response for captcha info
func ExtractCaptchaData(errResp map[string]interface{}) (*VkCaptchaData, bool) {
	code, _ := errResp["error_code"].(float64)
	if int(code) != 14 {
		return nil, false
	}

	redirectURI, _ := errResp["redirect_uri"].(string)
	if redirectURI == "" {
		return nil, false
	}

	// Parse session_token from redirect_uri
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return nil, false
	}
	sessionToken := parsed.Query().Get("session_token")
	if sessionToken == "" {
		return nil, false
	}

	// Extract captcha_sid
	captchaSid, _ := errResp["captcha_sid"].(string)

	// captcha_ts can be float64 or string
	var captchaTs string
	if tsFloat, ok := errResp["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errResp["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	// captcha_attempt
	var captchaAttempt string
	if attFloat, ok := errResp["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errResp["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &VkCaptchaData{
		CaptchaSid:     captchaSid,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
		RedirectURI:    redirectURI,
		SessionToken:   sessionToken,
	}, true
}

// SolveVkCaptcha fetches captcha page, solves PoW, and calls captchaNotRobot API
func SolveVkCaptcha(ctx context.Context, captchaData *VkCaptchaData) (string, error) {
	log.Printf("[Captcha] Solving Not Robot Captcha...")

	// HAR: Token 2 error → Captcha HTML = 2.72s (browser page load + user perception)
	time.Sleep(1500*time.Millisecond + time.Duration(rand.Intn(1000))*time.Millisecond)

	// Fetch captcha HTML (browser redirect)
	powInput, difficulty, cookies, err := fetchCaptchaPowInput(ctx, captchaData.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to fetch powInput: %w", err)
	}
	log.Printf("[Captcha] PoW input: %s, difficulty: %d", powInput, difficulty)

	// Solve PoW
	hash := solveCaptchaPoW(powInput, difficulty)
	log.Printf("[Captcha] PoW solved: hash=%s", hash)

	// Call captchaNotRobot API with cookies from captcha page
	successToken, err := callCaptchaNotRobotAPI(ctx, captchaData.SessionToken, hash, cookies)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	log.Printf("[Captcha] Success! Got success_token")
	return successToken, nil
}

func fetchCaptchaPowInput(ctx context.Context, redirectURI string) (string, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()

	// Capture Set-Cookie headers
	var cookieValues []string
	for _, setCookie := range resp.Header.Values("Set-Cookie") {
		// Extract just the cookie name=value part (before ; expires= or ; path=)
		cookieParts := strings.Split(setCookie, ";")
		cookieValues = append(cookieValues, strings.TrimSpace(cookieParts[0]))
	}
	cookies := strings.Join(cookieValues, "; ")
	if cookies != "" {
		log.Printf("[Captcha] Captcha page set %d cookie(s)", len(cookieValues))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, "", err
	}

	html := string(body)

	// Extract powInput: const powInput = "..."
	powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	powInputMatch := powInputRe.FindStringSubmatch(html)
	if len(powInputMatch) < 2 {
		return "", 0, "", fmt.Errorf("powInput not found in captcha HTML")
	}
	powInput := powInputMatch[1]

	// Extract difficulty: '0'.repeat(N)
	diffRe := regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`)
	diffMatch := diffRe.FindStringSubmatch(html)
	difficulty := 2 // default
	if len(diffMatch) >= 2 {
		if d, err := strconv.Atoi(diffMatch[1]); err == nil {
			difficulty = d
		}
	}

	return powInput, difficulty, cookies, nil
}

func solveCaptchaPoW(powInput string, difficulty int) string {
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

func callCaptchaNotRobotAPI(ctx context.Context, sessionToken, hash, cookies string) (string, error) {
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		requestURL := fmt.Sprintf("https://api.vk.ru/method/%s?v=%s", method, vkCaptchaNotRobotVer)

		req, err := http.NewRequestWithContext(ctx, "POST", requestURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		// Headers matching HAR capture exactly
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("sec-ch-ua-platform", `"Windows"`)
		req.Header.Set("sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`)
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("DNT", "1")
		req.Header.Set("Priority", "u=1, i")
		// Add cookies captured from captcha page
		if cookies != "" {
			req.Header.Set("Cookie", cookies)
		}

		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, err
		}
		return result, nil
	}

	domain := "vk.com"
	baseParams := fmt.Sprintf("session_token=%s&domain=%s&adFp=&access_token=",
		url.QueryEscape(sessionToken), url.QueryEscape(domain))

	// Step 1: settings
	log.Printf("[Captcha] Step 1/4: settings")
	_, err := vkReq("captchaNotRobot.settings", baseParams)
	if err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	// HAR: settings → componentDone = 0.19s
	time.Sleep(100*time.Millisecond + time.Duration(rand.Intn(100))*time.Millisecond)

	// Step 2: componentDone
	log.Printf("[Captcha] Step 2/4: componentDone")
	browserFp := fmt.Sprintf("%032x", uint64(time.Now().UnixNano()))
	deviceJSON := `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1032,"innerWidth":1920,"innerHeight":945,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":16,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`
	componentData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, url.QueryEscape(deviceJSON))
	_, err = vkReq("captchaNotRobot.componentDone", componentData)
	if err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}
	// HAR: componentDone → check ≈ 1.95s + statEvents delay ≈ 3.2s total
	time.Sleep(1500*time.Millisecond + time.Duration(rand.Intn(1000))*time.Millisecond)

	// Step 3: check
	log.Printf("[Captcha] Step 3/4: check")
	cursorJSON := `[{"x":950,"y":500},{"x":945,"y":510},{"x":940,"y":520},{"x":938,"y":525},{"x":938,"y":525}]`
	answer := base64.StdEncoding.EncodeToString([]byte("{}")) // e30=

	// Generate random connectionDownlink values (simulating Network Information API)
	// HAR shows browser repeats the same value 7 times: [9.8,9.8,9.8,9.8,9.8,9.8,9.8]
	baseDownlink := 8.0 + rand.Float64()*4.0 // Random in [8.0, 12.0) for typical WiFi
	downlinkStr := fmt.Sprintf("%.1f", baseDownlink)
	connectionDownlink := "[" + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "]"

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s"+
			"&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		url.QueryEscape("[]"),       // accelerometer
		url.QueryEscape("[]"),       // gyroscope
		url.QueryEscape("[]"),       // motion
		url.QueryEscape(cursorJSON), // cursor
		url.QueryEscape("[]"),       // taps
		url.QueryEscape("[]"),       // connectionRtt
		url.QueryEscape(connectionDownlink),
		browserFp, // browser_fp
		hash,      // hash (PoW result)
		answer,    // answer
		vkDebugInfo, // debug_info (static)
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check request failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}

	status, _ := respObj["status"].(string)
	if status != "OK" {
		return "", fmt.Errorf("check response status: %s, full response: %v", status, checkResp)
	}

	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found in check response: %v", checkResp)
	}
	// HAR: check → endSession = 0.48s
	time.Sleep(200*time.Millisecond + time.Duration(rand.Intn(300))*time.Millisecond)

	// Step 4: endSession
	log.Printf("[Captcha] Step 4/4: endSession")
	vkReq("captchaNotRobot.endSession", baseParams)

	return successToken, nil
}
