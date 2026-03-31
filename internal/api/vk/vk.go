package vk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
	"github.com/google/uuid"
)

const (
	userAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"
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

	doRequest := func(data string, url string, out interface{}) error {
		req, reqErr := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewBufferString(data))
		if reqErr != nil {
			return reqErr
		}

		req.Header.Add("User-Agent", userAgent)
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
	var resp2 struct {
		Response struct {
			Token string `json:"token"`
		} `json:"response"`
	}
	data2 := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", link, token1)
	url2 := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=%s", clientID)
	if err := doRequest(data2, url2, &resp2); err != nil {
		return "", "", "", fmt.Errorf("step 2 (getAnonymousToken) failed: %w", err)
	}
	token2 := resp2.Response.Token

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
