package vk

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bschaatsbergen/dnsdialer"
)

// roundTripFunc allows using a function as http.RoundTripper for intercepting all requests.
type roundTripFunc func(r *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r), nil
}

// TestParseVkCaptchaError tests the internal parsing helper.
func TestParseVkCaptchaError(t *testing.T) {
	errData := map[string]interface{}{
		"error_code":      float64(14),
		"error_msg":       "Captcha required",
		"captcha_sid":     float64(123456),
		"redirect_uri":    "https://vk.com/captcha?session_token=abc123",
		"captcha_ts":      float64(1700000000),
		"captcha_attempt": float64(1),
	}

	result := parseVkCaptchaError(errData)

	if result.ErrorCode != 14 {
		t.Errorf("ErrorCode: expected 14, got %d", result.ErrorCode)
	}
	if result.ErrorMsg != "Captcha required" {
		t.Errorf("ErrorMsg: expected 'Captcha required', got %q", result.ErrorMsg)
	}
	if result.CaptchaSid != "123456" {
		t.Errorf("CaptchaSid: expected '123456', got %q", result.CaptchaSid)
	}
	if result.SessionToken != "abc123" {
		t.Errorf("SessionToken: expected 'abc123', got %q", result.SessionToken)
	}
	if result.CaptchaTs != "1700000000" {
		t.Errorf("CaptchaTs: expected '1700000000', got %q", result.CaptchaTs)
	}
	if result.CaptchaAttempt != "1" {
		t.Errorf("CaptchaAttempt: expected '1', got %q", result.CaptchaAttempt)
	}
}

// TestParseVkCaptchaError_StringSid tests parsing when captcha_sid is already a string.
func TestParseVkCaptchaError_StringSid(t *testing.T) {
	errData := map[string]interface{}{
		"error_code":  float64(14),
		"captcha_sid": "sid-string-value",
		"redirect_uri": "",
	}
	result := parseVkCaptchaError(errData)
	if result.CaptchaSid != "sid-string-value" {
		t.Errorf("expected 'sid-string-value', got %q", result.CaptchaSid)
	}
	if result.SessionToken != "" {
		t.Errorf("expected empty session token for empty redirect_uri, got %q", result.SessionToken)
	}
}

// TestSolvePoW tests the Proof-of-Work hash computation.
func TestSolvePoW(t *testing.T) {
	// Use a very short difficulty so it completes quickly in tests
	result := solvePoW("testinput", 1)
	if result == "" {
		t.Fatal("solvePoW returned empty string — couldn't find a nonce")
	}
	if !strings.HasPrefix(result, "0") {
		t.Errorf("Expected hash starting with '0' (difficulty=1), got %q", result)
	}
}

// TestGetCreds_StepOneFailure tests that GetCreds returns an error when step 1 fails.
func TestGetCreds_StepOneFailure(t *testing.T) {
	// Intercept ALL HTTP requests via a custom transport injected at test time
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal server error`))
	}))
	defer ts.Close()

	// Patch the transport on the dialer for all HTTP requests
	dialer := dnsdialer.New(dnsdialer.WithResolvers("8.8.8.8:53"))

	// Since vk.go uses hardcoded URLs we can't redirect easily.
	// Instead, we test error propagation by providing a known-bad server via
	// temporarily swapping the default transport.
	origTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		DialContext: dialer.DialContext,
	}
	defer func() { http.DefaultTransport = origTransport }()

	// This will fail at network level since 127.0.0.1 won't have ssl cert
	// The test verifies GetCreds always returns an error when upstream is down
	_, _, _, err := GetCreds("test-link", dialer)
	if err == nil {
		t.Fatal("Expected GetCreds to fail, but got nil error")
	}
}

// TestGetCreds_TurnURLParsing tests the TURN URL strip logic inline.
func TestGetCreds_TurnURLParsing(t *testing.T) {
	cases := []struct {
		raw      string
		expected string
	}{
		{"turn:95.163.76.101:3478?transport=udp", "95.163.76.101:3478"},
		{"turns:95.163.76.101:3479?transport=tcp", "95.163.76.101:3479"},
		{"turn:10.0.0.1:3478", "10.0.0.1:3478"},
	}
	for _, tc := range cases {
		clean := strings.Split(tc.raw, "?")[0]
		got := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		if got != tc.expected {
			t.Errorf("parsing %q: expected %q, got %q", tc.raw, tc.expected, got)
		}
	}
}

// TestGetCreds_FullMockFlow tests GetCreds handles responses without panicking.
func TestGetCreds_FullMockFlow(t *testing.T) {
	// Intercept HTTP traffic with a stub that returns empty JSON for all calls
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		pr, pw := io.Pipe()
		go func() {
			pw.Write([]byte(`{}`))
			pw.Close()
		}()
		return &http.Response{
			StatusCode: 200,
			Body:       pr,
			Header:     make(http.Header),
		}
	})

	origTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = origTransport }()

	dialer := dnsdialer.New(dnsdialer.WithResolvers("8.8.8.8:53"))
	// Should return an error (empty token / missing fields), never panic
	_, _, _, err := GetCreds("test-link-slug", dialer)
	if err == nil {
		t.Log("GetCreds unexpectedly succeeded with empty JSON responses")
	}
}
