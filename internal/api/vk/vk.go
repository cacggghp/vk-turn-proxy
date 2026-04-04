package vk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
	"github.com/cacggghp/vk-turn-proxy/internal/api/identity"
	"github.com/google/uuid"
)

const (
	clientID       = "6287487"
	clientSecret   = "QbYic1K3lEV5kTGiqlq2"
	applicationKey = "CGMMEJLGDIHBABABA" // For OKCDN
)

// turnCredentials represents the relevant data returned by the final API call.
type turnCredentials struct {
	TurnServer struct {
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
		Urls       []string `json:"urls"`
	} `json:"turn_server"`
}

// GetCreds requests temporary TURN server credentials from VK's backend services
// using an anonymous call invite link. It uses the provided dnsdialer to
// circumvent potential local DNS blockades.
func GetCreds(link string, dialer *dnsdialer.Dialer) (user string, pass string, address string, err error) {
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

	prof := identity.GetRandomProfile()
	name := identity.GenerateName()
	escapedName := neturl.QueryEscape(name)

	doRequest := func(data string, url string, out interface{}) error {
		req, reqErr := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewBufferString(data))
		if reqErr != nil {
			return reqErr
		}

		req.Header.Add("User-Agent", prof.UserAgent)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, doErr := client.Do(req)
		if doErr != nil {
			return doErr
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
		}

		if out != nil {
			if decErr := json.NewDecoder(resp.Body).Decode(out); decErr != nil {
				return decErr
			}
		}
		return nil
	}

	// 1. Get anonymous messages token
	var resp1 struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	data1 := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", clientID, clientSecret, clientID)
	url1 := "https://login.vk.ru/?act=get_anonym_token"
	if err := doRequest(data1, url1, &resp1); err != nil {
		return "", "", "", fmt.Errorf("step 1 (get_anonym_token) failed: %w", err)
	}
	token1 := resp1.Data.AccessToken

	// 2. Get anonymous call token using the invite link
	data2 := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	url2 := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=%s", clientID)
	var token2 string
	const maxCaptchaAttempts = 3
	for attempt := 0; attempt <= maxCaptchaAttempts; attempt++ {
		var resp2 map[string]interface{}
		if err := doRequest(data2, url2, &resp2); err != nil {
			return "", "", "", fmt.Errorf("step 2 request failed: %w", err)
		}

		// Check for captcha error
		if errObj, hasErr := resp2["error"].(map[string]interface{}); hasErr {
			errCode, _ := errObj["error_code"].(float64)
			if errCode == 14 {
				if attempt == maxCaptchaAttempts {
					return "", "", "", fmt.Errorf("captcha failed after %d attempts", maxCaptchaAttempts)
				}

				captchaErr := parseVkCaptchaError(errObj)
				if captchaErr.SessionToken != "" {
					successToken, solveErr := solveVkCaptcha(context.Background(), captchaErr, dialer, prof.UserAgent)
					if solveErr != nil {
						return "", "", "", fmt.Errorf("auto captcha solve error: %w", solveErr)
					}

					if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
						captchaErr.CaptchaAttempt = "1"
					}

					data2 = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s",
						link, escapedName, token1, captchaErr.CaptchaSid, neturl.QueryEscape(successToken), captchaErr.CaptchaTs, captchaErr.CaptchaAttempt)
					continue
				} else {
					return "", "", "", fmt.Errorf("old image captcha detected - not supported in auto solver")
				}
			}
			return "", "", "", fmt.Errorf("VK API error: %v", errObj)
		}

		respMap, ok := resp2["response"].(map[string]interface{})
		if !ok {
			return "", "", "", fmt.Errorf("unexpected getAnonymousToken response: %v", resp2)
		}
		var okToken bool
		token2, okToken = respMap["token"].(string)
		if !okToken {
			return "", "", "", fmt.Errorf("missing token in response: %v", resp2)
		}
		break
	}

	// 3. Login anonymously to OKCDN WebRTC backend
	var resp3 struct {
		SessionKey string `json:"session_key"`
	}
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New().String())
	// session_data must be URL encoded (basic encoding for quotes/braces)
	sessionDataEnc := strings.ReplaceAll(sessionData, `"`, "%22")
	sessionDataEnc = strings.ReplaceAll(sessionDataEnc, "{", "%7B")
	sessionDataEnc = strings.ReplaceAll(sessionDataEnc, "}", "%7D")
	sessionDataEnc = strings.ReplaceAll(sessionDataEnc, ":", "%3A")
	sessionDataEnc = strings.ReplaceAll(sessionDataEnc, ",", "%2C")

	data3 := fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=%s", sessionDataEnc, applicationKey)
	url3 := "https://calls.okcdn.ru/fb.do"
	if err := doRequest(data3, url3, &resp3); err != nil {
		return "", "", "", fmt.Errorf("step 3 (auth.anonymLogin) failed: %w", err)
	}
	token3 := resp3.SessionKey

	// 4. Join the specific conversation link and retrieve TURN server config
	var resp4 turnCredentials
	data4 := fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=%s&session_key=%s",
		link, token2, applicationKey, token3)
	if err := doRequest(data4, url3, &resp4); err != nil {
		return "", "", "", fmt.Errorf("step 4 (vchat.joinConversationByLink) failed: %w", err)
	}

	if len(resp4.TurnServer.Urls) == 0 {
		return "", "", "", fmt.Errorf("no TURN URLs provided by VK/OKCDN backend")
	}

	user = resp4.TurnServer.Username
	pass = resp4.TurnServer.Credential
	
	// Example URL: turn:95.163.76.101:3478?transport=udp
	turnURL := resp4.TurnServer.Urls[0]
	clean := strings.Split(turnURL, "?")[0]
	address = strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}
