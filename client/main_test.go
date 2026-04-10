package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
	"github.com/cacggghp/vk-turn-proxy/internal/cliutil"
)

func TestParseClientOptionsShowsUsageWithoutArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseClientOptions(nil, "client", &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("parseClientOptions() exitCode = %d, want 0", exitCode)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "Usage:\n  client -peer <host:port> -vk-link <link> [flags]") {
		t.Fatalf("usage output missing client help text: %q", got)
	}
}

func TestParseClientOptionsShowsHelpFlagUsage(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseClientOptions([]string{"-help"}, "client", &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("parseClientOptions() exitCode = %d, want 0", exitCode)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "Examples:") {
		t.Fatalf("expected help examples in output, got %q", got)
	}
}

func TestParseClientOptionsRequiresPeer(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseClientOptions([]string{"-vk-link", "https://vk.com/call/join/test"}, "client", &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("parseClientOptions() exitCode = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}
	if got := stderr.String(); !strings.Contains(got, "error: -peer is required") {
		t.Fatalf("expected missing peer error, got %q", got)
	}
}

func TestParseClientOptionsParsesValidVKArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	opts, exitCode := parseClientOptions([]string{"-peer", "127.0.0.1:56000", "-vk-link", "https://vk.com/call/join/test", "-listen", "127.0.0.1:9001"}, "client", &stdout, &stderr)
	if exitCode != cliutil.ContinueExecution {
		t.Fatalf("parseClientOptions() exitCode = %d, want %d", exitCode, cliutil.ContinueExecution)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
	if opts.peerAddr != "127.0.0.1:56000" {
		t.Fatalf("peerAddr = %q, want 127.0.0.1:56000", opts.peerAddr)
	}
	if opts.vklink != "https://vk.com/call/join/test" {
		t.Fatalf("vklink = %q, want VK link", opts.vklink)
	}
	if opts.listen != "127.0.0.1:9001" {
		t.Fatalf("listen = %q, want 127.0.0.1:9001", opts.listen)
	}
}

func TestCaptchaSolveModeForAttempt(t *testing.T) {
	t.Parallel()

	t.Run("default flow", func(t *testing.T) {
		t.Parallel()

		mode, ok := captchaSolveModeForAttempt(0, false, true)
		if !ok || mode != captchaSolveModeAuto {
			t.Fatalf("expected first attempt to use auto captcha, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = captchaSolveModeForAttempt(1, false, true)
		if !ok || mode != captchaSolveModeSliderPOC {
			t.Fatalf("expected second attempt to use slider POC, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = captchaSolveModeForAttempt(2, false, true)
		if !ok || mode != captchaSolveModeManual {
			t.Fatalf("expected third attempt to use manual captcha, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = captchaSolveModeForAttempt(3, false, true); ok {
			t.Fatal("expected no fourth captcha attempt in default flow")
		}
	})

	t.Run("manual only flow", func(t *testing.T) {
		t.Parallel()

		mode, ok := captchaSolveModeForAttempt(0, true, true)
		if !ok || mode != captchaSolveModeManual {
			t.Fatalf("expected manual mode on first attempt, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = captchaSolveModeForAttempt(1, true, true); ok {
			t.Fatal("expected only one manual captcha attempt when manual mode is forced")
		}
	})

	t.Run("flow without slider poc", func(t *testing.T) {
		t.Parallel()

		mode, ok := captchaSolveModeForAttempt(0, false, false)
		if !ok || mode != captchaSolveModeAuto {
			t.Fatalf("expected auto captcha first, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = captchaSolveModeForAttempt(1, false, false)
		if !ok || mode != captchaSolveModeManual {
			t.Fatalf("expected manual captcha second when slider POC is disabled, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = captchaSolveModeForAttempt(2, false, false); ok {
			t.Fatal("expected only two attempts when slider POC is disabled")
		}
	})
}

func TestCaptchaLogAttempt(t *testing.T) {
	t.Parallel()

	if got := captchaLogAttempt(context.Background(), captchaSolveModeManual, 0); got != 1 {
		t.Fatalf("captchaLogAttempt() = %d, want 1 for first manual attempt", got)
	}

	ctx := withCaptchaFailureCount(context.Background(), 1)
	if got := captchaLogAttempt(ctx, captchaSolveModeManual, 0); got != 2 {
		t.Fatalf("captchaLogAttempt() = %d, want 2 for second bucket manual attempt", got)
	}

	if got := captchaLogAttempt(ctx, captchaSolveModeManual, 2); got != 3 {
		t.Fatalf("captchaLogAttempt() = %d, want 3 when in-request attempt count is already higher", got)
	}

	if got := captchaLogAttempt(ctx, captchaSolveModeAuto, 0); got != 1 {
		t.Fatalf("captchaLogAttempt() = %d, want 1 for auto attempt count", got)
	}
}

func TestGetVkCredsCachedDisablesBucketAfterTwoCaptchaFailures(t *testing.T) {
	credentialsStore.mu.Lock()
	previousCaches := credentialsStore.caches
	credentialsStore.caches = make(map[int]*StreamCredentialsCache)
	credentialsStore.mu.Unlock()
	defer func() {
		credentialsStore.mu.Lock()
		credentialsStore.caches = previousCaches
		credentialsStore.mu.Unlock()
	}()

	previousFetch := fetchVkCredsSerializedFunc
	defer func() {
		fetchVkCredsSerializedFunc = previousFetch
	}()
	previousConfiguredStreams := configuredStreams.Load()
	configuredStreams.Store(20)
	defer configuredStreams.Store(previousConfiguredStreams)

	var (
		mu        sync.Mutex
		callCount int
	)
	fetchVkCredsSerializedFunc = func(ctx context.Context, link string, streamID int, dialer *dnsdialer.Dialer) (string, string, string, error) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		switch callCount {
		case 1:
			return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
		case 2:
			return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
		default:
			return "", "", "", fmt.Errorf("unexpected extra fetch for stream %d", streamID)
		}
	}

	_, _, _, err := getVkCredsCached(context.Background(), "link", 10, nil)
	if err == nil || err.Error() != "CAPTCHA_WAIT_REQUIRED" {
		t.Fatalf("first getVkCredsCached() error = %v, want CAPTCHA_WAIT_REQUIRED", err)
	}

	_, _, _, err = getVkCredsCached(context.Background(), "link", 17, nil)
	if err == nil || err.Error() != "CAPTCHA_WAIT_REQUIRED" {
		t.Fatalf("second getVkCredsCached() error = %v, want shared CAPTCHA_WAIT_REQUIRED", err)
	}

	mu.Lock()
	if callCount != 1 {
		mu.Unlock()
		t.Fatalf("expected one fetch attempt during shared captcha cooldown, got %d", callCount)
	}
	mu.Unlock()

	cache := getStreamCache(10)
	cache.mutex.Lock()
	cache.retryAfter = time.Now().Add(-time.Second)
	cache.mutex.Unlock()

	_, _, _, err = getVkCredsCached(context.Background(), "link", 19, nil)
	if err == nil || !strings.Contains(err.Error(), errCaptchaBucketDisabled.Error()) {
		t.Fatalf("third getVkCredsCached() error = %v, want bucket disabled", err)
	}

	_, _, _, err = getVkCredsCached(context.Background(), "link", 11, nil)
	if err == nil || !strings.Contains(err.Error(), errCaptchaBucketDisabled.Error()) {
		t.Fatalf("fourth getVkCredsCached() error = %v, want bucket disabled without new fetch", err)
	}

	mu.Lock()
	if callCount != 2 {
		mu.Unlock()
		t.Fatalf("expected exactly two fetch attempts before bucket disable, got %d", callCount)
	}
	mu.Unlock()

	if got := activeConfiguredStreamCount(); got != 10 {
		t.Fatalf("activeConfiguredStreamCount() = %d, want 10 after disabling second bucket", got)
	}
}
