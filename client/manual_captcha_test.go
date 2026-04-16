package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestRewriteProxyRedirectLocation(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

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

func TestRunCaptchaServerAndWaitStopsOnContextCancel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:"+captchaListenPort)
	if err != nil {
		t.Skipf("captcha listener test requires a free localhost port: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to release preflight listener: %v", err)
	}

	previousOpenBrowser := openBrowserFunc
	openBrowserFunc = func(string) {}
	defer func() {
		openBrowserFunc = previousOpenBrowser
	}()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		_, err := runCaptchaServerAndWait(
			ctx,
			http.NewServeMux(),
			localCaptchaOrigin(),
			make(chan string),
			"test captcha server",
		)
		errCh <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:"+captchaListenPort, 50*time.Millisecond)
		if dialErr == nil {
			if err := conn.Close(); err != nil {
				t.Fatalf("failed to close probe connection: %v", err)
			}
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("captcha server did not start listening: %v", dialErr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runCaptchaServerAndWait() error = %v, want context canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runCaptchaServerAndWait() did not return after context cancellation")
	}

	deadline = time.Now().Add(2 * time.Second)
	for {
		listener, err = net.Listen("tcp", "127.0.0.1:"+captchaListenPort)
		if err == nil {
			if closeErr := listener.Close(); closeErr != nil {
				t.Fatalf("failed to close verification listener: %v", closeErr)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("captcha listener was not released after cancellation: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
