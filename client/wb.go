// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/gorilla/websocket"
)

const (
	wbBase = "https://stream.wb.ru"
)

// WbTurnCred stores a single TURN credential
type WbTurnCred struct {
	URL      string
	Username string
	Password string
}

// wbFetch adapts fetchWbCreds to the fetchFunc signature
func wbFetch(ctx context.Context, link string) (string, string, string, error) {
	_ = link // WB doesn't use link parameter
	creds, err := fetchWbCreds(ctx)
	if err != nil {
		return "", "", "", err
	}
	if len(creds) > 0 {
		// Clean URL: "turn:host:port?transport=udp" -> "host:port"
		clean := strings.Split(creds[0].URL, "?")[0]
		address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		return creds[0].Username, creds[0].Password, address, nil
	}
	return "", "", "", fmt.Errorf("no TURN credentials received from WB")
}

// wbReq makes an HTTP request to WB API using tls-client
func wbReq(ctx context.Context, client tlsclient.HttpClient, profile Profile, method, ep string, body []byte, tok string) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}

	rq, err := fhttp.NewRequestWithContext(ctx, method, wbBase+ep, rd)
	if err != nil {
		return nil, err
	}

	applyBrowserProfileFhttp(rq, profile)
	rq.Header.Set("Accept", "application/json")
	rq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	rq.Header.Set("Origin", wbBase)
	rq.Header.Set("Referer", wbBase+"/")
	if body != nil {
		rq.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		rq.Header.Set("Authorization", "Bearer "+tok)
	}

	rs, err := client.Do(rq)
	if err != nil {
		return nil, err
	}
	defer rs.Body.Close()

	var r io.Reader = rs.Body
	if rs.Header.Get("Content-Encoding") == "gzip" {
		if g, e := gzip.NewReader(rs.Body); e == nil {
			defer g.Close()
			r = g
		}
	}

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if rs.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", rs.StatusCode, string(b))
	}

	return b, nil
}

// fetchWbCreds performs the full WB credential acquisition flow
func fetchWbCreds(ctx context.Context) ([]WbTurnCred, error) {
	profile := Profile{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Not(A:Brand";v="99", "Google Chrome";v="146", "Chromium";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithDialer(getCustomNetDialer()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tls_client: %w", err)
	}

	nm := fmt.Sprintf("lh_%d", time.Now().UnixMilli()%100000)

	log.Println("[WB Auth] Step 1: Guest registration...")
	rr, err := wbReq(ctx, client, profile, "POST", "/auth/api/v1/auth/user/guest-register",
		[]byte(`{"displayName":"`+nm+`"}`), "")
	if err != nil {
		return nil, fmt.Errorf("guest register: %w", err)
	}

	var reg struct {
		AccessToken string `json:"accessToken"`
	}
	if err = json.Unmarshal(rr, &reg); err != nil {
		return nil, fmt.Errorf("parse register response: %w", err)
	}
	if reg.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response")
	}
	log.Println("[WB Auth] Guest registered")

	log.Println("[WB Auth] Step 2: Create room...")
	rr, err = wbReq(ctx, client, profile, "POST", "/api-room/api/v2/room",
		[]byte(`{"roomType":"ROOM_TYPE_ALL_ON_SCREEN","roomPrivacy":"ROOM_PRIVACY_FREE"}`),
		reg.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("create room: %w", err)
	}

	var room struct {
		RoomID string `json:"roomId"`
	}
	if err = json.Unmarshal(rr, &room); err != nil {
		return nil, fmt.Errorf("parse room response: %w", err)
	}
	if room.RoomID == "" {
		return nil, fmt.Errorf("no room ID in response")
	}
	roomPreview := room.RoomID
	if len(roomPreview) > 8 {
		roomPreview = roomPreview[:8]
	}
	log.Printf("[WB Auth] Room created: %s", roomPreview)

	log.Println("[WB Auth] Step 3: Join room...")
	_, err = wbReq(ctx, client, profile, "POST", fmt.Sprintf("/api-room/api/v1/room/%s/join", room.RoomID),
		[]byte("{}"), reg.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("join room: %w", err)
	}

	log.Println("[WB Auth] Step 4: Get room token...")
	rr, err = wbReq(ctx, client, profile, "GET", fmt.Sprintf(
		"/api-room-manager/api/v1/room/%s/token?deviceType=PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP&displayName=%s",
		room.RoomID, url.QueryEscape(nm)), nil, reg.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}

	var tok struct {
		RoomToken string `json:"roomToken"`
	}
	if err = json.Unmarshal(rr, &tok); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	if tok.RoomToken == "" {
		return nil, fmt.Errorf("no room token in response")
	}

	log.Println("[WB Auth] Step 5: Negotiating ICE (LiveKit)...")
	creds, err := wbLkICE(ctx, tok.RoomToken, profile.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("livekit ICE: %w", err)
	}

	for _, c := range creds {
		log.Printf("[WB Auth]   → %s", c.URL)
	}

	return creds, nil
}

// wbLkICE connects to LiveKit WebSocket and extracts TURN credentials
func wbLkICE(ctx context.Context, token string, userAgent string) ([]WbTurnCred, error) {
	u := "wss://wbstream01-el.wb.ru:7880/rtc?access_token=" + url.QueryEscape(token) +
		"&auto_subscribe=1&sdk=js&version=2.15.3&protocol=16&adaptive_stream=1"

	header := http.Header{}
	header.Set("User-Agent", userAgent)
	header.Set("Origin", wbBase)

	conn, _, err := (&websocket.Dialer{
		TLSClientConfig:  &tls.Config{},
		HandshakeTimeout: 10 * time.Second,
	}).DialContext(ctx, u, header)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	for i := 0; i < 15; i++ {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if creds := wbPbICE(msg); len(creds) > 0 {
			return wbDedup(creds), nil
		}
	}

	return nil, fmt.Errorf("TURN credentials not found in LiveKit response")
}

// PbVar reads protobuf varint
func wbPbVar(d []byte, o int) (uint64, int) {
	var v uint64
	for s := 0; o < len(d) && s < 64; s += 7 {
		b := d[o]
		o++
		v |= uint64(b&0x7f) << s
		if b < 0x80 {
			return v, o
		}
	}
	return 0, o
}

// PbAll finds all fields with given tag number in protobuf data
func wbPbAll(d []byte, f uint64) (r [][]byte) {
	for o := 0; o < len(d); {
		t, n := wbPbVar(d, o)
		if n == o {
			break
		}
		o = n
		switch t & 7 {
		case 0:
			_, o = wbPbVar(d, o)
		case 2:
			l, n := wbPbVar(d, o)
			o = n
			e := o + int(l)
			if e > len(d) || e < o {
				return
			}
			if t>>3 == f {
				r = append(r, d[o:e])
			}
			o = e
		case 1:
			o += 8
		case 5:
			o += 4
		default:
			return
		}
	}
	return
}

// PbStr extracts string field with given tag number
func wbPbStr(d []byte, f uint64) string {
	if a := wbPbAll(d, f); len(a) > 0 {
		return string(a[0])
	}
	return ""
}

// PbICE extracts TURN/STUN credentials from protobuf message
func wbPbICE(d []byte) (res []WbTurnCred) {
	for o := 0; o < len(d); {
		t, n := wbPbVar(d, o)
		if n == o {
			break
		}
		o = n
		switch t & 7 {
		case 0:
			_, o = wbPbVar(d, o)
		case 2:
			l, n := wbPbVar(d, o)
			o = n
			e := o + int(l)
			if e > len(d) || e < o {
				return
			}
			inner := d[o:e]
			for _, f := range []uint64{5, 9} {
				for _, blk := range wbPbAll(inner, f) {
					urls := wbPbAll(blk, 1)
					hit := false
					for _, u := range urls {
						s := string(u)
						if strings.HasPrefix(s, "turn") || strings.HasPrefix(s, "stun") {
							hit = true
							break
						}
					}
					if !hit {
						continue
					}
					un, pw := wbPbStr(blk, 2), wbPbStr(blk, 3)
					for _, u := range urls {
						res = append(res, WbTurnCred{string(u), un, pw})
					}
					for _, blk2 := range wbPbAll(inner, f) {
						if len(blk2) > 0 && len(blk) > 0 && &blk2[0] == &blk[0] {
							continue
						}
						u2, p2 := wbPbStr(blk2, 2), wbPbStr(blk2, 3)
						for _, u := range wbPbAll(blk2, 1) {
							res = append(res, WbTurnCred{string(u), u2, p2})
						}
					}
					return
				}
			}
			o = e
		case 1:
			o += 8
		case 5:
			o += 4
		default:
			return
		}
	}
	return
}

// wbDedup removes duplicate credentials
func wbDedup(cc []WbTurnCred) (r []WbTurnCred) {
	seen := map[string]bool{}
	for _, c := range cc {
		k := c.URL + "|" + c.Username
		if !seen[k] {
			seen[k] = true
			r = append(r, c)
		}
	}
	return
}
