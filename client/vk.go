// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const vkClientID = "6287487"
const vkClientSecret = "QbYic1K3lEV5kTGiqlq2"
const vkAPIVersion = "5.275"

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// vkDelay sleeps for a random duration between minMs and maxMs to avoid bot detection
func vkDelay(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func vkHTTPPost(ctx context.Context, data string, url string) (map[string]interface{}, error) {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return nil, err
	}
	// Headers matching HAR capture exactly
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", "https://vk.ru")
	req.Header.Set("Referer", "https://vk.ru/")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("DNT", "1")
	req.Header.Set("Priority", "u=1, i")

	httpResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	// Handle HTTP errors (redirects, rate limits, etc.)
	if httpResp.StatusCode >= 400 {
		body, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("HTTP %d from %s: %s", httpResp.StatusCode, req.URL, string(body[:min(len(body), 500)]))
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	// Check content type - VK may return HTML instead of JSON (captcha page, redirect, etc.)
	contentType := httpResp.Header.Get("Content-Type")
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "text/javascript") {
		// Log first 500 chars of non-JSON response for debugging
		logPreview := string(body)
		if len(logPreview) > 500 {
			logPreview = logPreview[:500] + "...(truncated)"
		}
		return nil, fmt.Errorf("unexpected content-type %s, status %d, body: %s", contentType, httpResp.StatusCode, logPreview)
	}

	var resp map[string]interface{}
	if err = json.Unmarshal(body, &resp); err != nil {
		// Log the raw body for debugging
		logPreview := string(body)
		if len(logPreview) > 500 {
			logPreview = logPreview[:500] + "...(truncated)"
		}
		return nil, fmt.Errorf("JSON parse error: %w, body: %s", err, logPreview)
	}
	return resp, nil
}

func getVkCreds(ctx context.Context, link string) (string, string, string, error) {
	// Token 1 (messages)
	log.Println("[VK Auth] Getting Token 1...")
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s",
		vkClientID, vkClientSecret, vkClientID)
	resp, err := vkHTTPPost(ctx, data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", "", fmt.Errorf("Token 1 request error: %w", err)
	}
	if errMsg, ok := resp["error"].(map[string]interface{}); ok {
		return "", "", "", fmt.Errorf("Token 1 VK error: %v", errMsg)
	}
	dataObj, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid Token 1 response: %v", resp)
	}
	token1, ok := dataObj["access_token"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("access_token not found in Token 1 response")
	}
	log.Println("[VK Auth] Token 1 received")
	vkDelay(100, 200) // Token 1 → getCallPreview

	// getCallPreview (optional, like browser)
	log.Println("[VK Auth] Getting call preview...")
	cpData := fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&fields=photo_200&access_token=%s",
		url.QueryEscape(link), token1)
	cpURL := fmt.Sprintf("https://api.vk.ru/method/calls.getCallPreview?v=%s&client_id=%s", vkAPIVersion, vkClientID)
	_, _ = vkHTTPPost(ctx, cpData, cpURL) // non-critical
	vkDelay(500, 1000) // getCallPreview → Token 2

	// Token 2 (may require captcha)
	log.Println("[VK Auth] Getting Token 2...")
	t2Data := fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=123&access_token=%s",
		url.QueryEscape(link), token1)
	t2URL := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=%s&client_id=%s", vkAPIVersion, vkClientID)
	resp, err = vkHTTPPost(ctx, t2Data, t2URL)
	if err != nil {
		return "", "", "", fmt.Errorf("Token 2 request error: %w", err)
	}

	// Check for captcha error
	if errMsg, ok := resp["error"].(map[string]interface{}); ok {
		captchaData, isCaptcha := ExtractCaptchaData(errMsg)
		if !isCaptcha {
			return "", "", "", fmt.Errorf("Token 2 VK error: %v", errMsg)
		}

		log.Printf("[VK Auth] Captcha detected, solving...")
		successToken, solveErr := SolveVkCaptcha(ctx, captchaData)
		if solveErr != nil {
			return "", "", "", fmt.Errorf("captcha solving failed: %w", solveErr)
		}

		// Delay before retry (endSession → Token 2 retry)
		vkDelay(100, 200)

		// Retry Token 2 with captcha solution
		log.Println("[VK Auth] Retrying Token 2 with captcha solution...")
		t2Data = fmt.Sprintf(
			"vk_join_link=https://vk.ru/call/join/%s&name=123"+
				"&captcha_key=&captcha_sid=%s&is_sound_captcha=0"+
				"&success_token=%s&captcha_ts=%s&captcha_attempt=%s"+
				"&access_token=%s",
			url.QueryEscape(link),
			captchaData.CaptchaSid,
			successToken,
			captchaData.CaptchaTs,
			captchaData.CaptchaAttempt,
			token1,
		)
		resp, err = vkHTTPPost(ctx, t2Data, t2URL)
		if err != nil {
			return "", "", "", fmt.Errorf("Token 2 retry request error: %w", err)
		}
		if errMsg2, ok := resp["error"].(map[string]interface{}); ok {
			return "", "", "", fmt.Errorf("Token 2 retry VK error: %v", errMsg2)
		}
		// Token 2 retry → Token 3
		vkDelay(100, 200)
	}

	token2Obj, ok := resp["response"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid Token 2 response: %v", resp)
	}
	token2, ok := token2Obj["token"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("token not found in Token 2 response")
	}
	log.Println("[VK Auth] Token 2 received")
	// Token 2 → Token 3
	vkDelay(100, 200)

	// Token 3 (OK auth.anonymLogin)
	log.Println("[VK Auth] Getting Token 3...")
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	t3Data := fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA",
		url.QueryEscape(sessionData))
	resp, err = vkHTTPPost(ctx, t3Data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", fmt.Errorf("Token 3 request error: %w", err)
	}
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		return "", "", "", fmt.Errorf("Token 3 API error: %s", errMsg)
	}
	token3, ok := resp["session_key"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("session_key not found in Token 3 response")
	}
	log.Println("[VK Auth] Token 3 received")
	// Token 3 → Final (TURN)
	vkDelay(100, 200)

	// Final: vchat.joinConversationByLink (Token 4)
	log.Println("[VK Auth] Getting TURN credentials (Token 4)...")
	finalData := fmt.Sprintf(
		"joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s",
		url.QueryEscape(link), token2, token3)
	resp, err = vkHTTPPost(ctx, finalData, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", fmt.Errorf("Final request error: %w", err)
	}
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		return "", "", "", fmt.Errorf("Final API error: %s", errMsg)
	}

	ts, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("turn_server not found in response: %v", resp)
	}
	urls, _ := ts["urls"].([]interface{})
	if len(urls) == 0 {
		return "", "", "", fmt.Errorf("urls not found in turn_server")
	}
	urlStr, _ := urls[0].(string)
	clean := strings.Split(urlStr, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	username, _ := ts["username"].(string)
	credential, _ := ts["credential"].(string)

	if username == "" || credential == "" {
		return "", "", "", fmt.Errorf("username or credential not found in turn_server")
	}

	log.Println("[VK Auth] TURN credentials received")
	vkDelay(1500, 2500) // Final delay before exit
	return username, credential, address, nil
}
