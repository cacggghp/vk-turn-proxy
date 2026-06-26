package clientcore

import (
	"net/url"
	"testing"
)

func TestRewriteProxyRedirectLocation(t *testing.T) {
	targetURL, err := url.Parse("https://id.vk.ru/captcha")
	if err != nil {
		t.Fatalf("failed to parse target URL: %v", err)
	}

	testCases := []struct {
		name     string
		location string
		want     string
		ok       bool
	}{
		{
			name:     "keeps safe relative path",
			location: "/captcha?step=2",
			want:     "/captcha?step=2",
			ok:       true,
		},
		{
			name:     "rewrites same-origin absolute URL",
			location: "https://id.vk.ru/captcha?step=2",
			want:     "http://localhost:8765/captcha?step=2",
			ok:       true,
		},
		{
			name:     "blocks scheme-relative redirect",
			location: "//evil.example/captcha",
			ok:       false,
		},
		{
			name:     "blocks slash-backslash redirect",
			location: `/\evil.example/captcha`,
			ok:       false,
		},
		{
			name:     "blocks lookalike absolute host",
			location: "https://id.vk.ru.evil.example/captcha",
			ok:       false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, ok := rewriteProxyRedirectLocation(tc.location, targetURL)
			if ok != tc.ok {
				t.Fatalf("rewriteProxyRedirectLocation() ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("rewriteProxyRedirectLocation() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCustomCaptchaHost(t *testing.T) {
	if err := setLocalCaptchaHost("192.168.99.1:8765"); err != nil {
		t.Fatalf("setLocalCaptchaHost() failed: %v", err)
	}
	defer func() {
		if err := setLocalCaptchaHost(""); err != nil {
			t.Fatalf("reset local captcha host: %v", err)
		}
	}()

	targetURL, err := url.Parse("https://id.vk.ru/captcha?step=2")
	if err != nil {
		t.Fatalf("failed to parse target URL: %v", err)
	}

	if got, want := localCaptchaOrigin(), "http://192.168.99.1:8765"; got != want {
		t.Fatalf("localCaptchaOrigin() = %q, want %q", got, want)
	}
	if got, want := localCaptchaURLForTarget(targetURL), "http://192.168.99.1:8765/captcha?step=2"; got != want {
		t.Fatalf("localCaptchaURLForTarget() = %q, want %q", got, want)
	}
	if !isLocalCaptchaHost("192.168.99.1:8765") {
		t.Fatal("custom captcha host should be accepted as local")
	}

	addrs := localCaptchaListenAddrs()
	if len(addrs) != 3 || addrs[2] != "192.168.99.1:8765" {
		t.Fatalf("localCaptchaListenAddrs() = %v, want custom host appended", addrs)
	}
}

func TestSetLocalCaptchaHostRejectsInvalidValues(t *testing.T) {
	testCases := []string{
		"http://192.168.99.1:8765",
		"192.168.99.1",
		":8765",
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc, func(t *testing.T) {
			if err := setLocalCaptchaHost(tc); err == nil {
				t.Fatalf("setLocalCaptchaHost(%q) succeeded, want error", tc)
			}
		})
	}
}
