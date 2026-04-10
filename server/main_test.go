package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cacggghp/vk-turn-proxy/internal/cliutil"
)

func TestParseServerOptionsShowsUsageWithoutArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseServerOptions(nil, "server", &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("parseServerOptions() exitCode = %d, want 0", exitCode)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "Usage:\n  server -connect <ip:port> [flags]") {
		t.Fatalf("usage output missing server help text: %q", got)
	}
}

func TestParseServerOptionsShowsHelpFlagUsage(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseServerOptions([]string{"-help"}, "server", &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("parseServerOptions() exitCode = %d, want 0", exitCode)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "Examples:") {
		t.Fatalf("expected help examples in output, got %q", got)
	}
}

func TestParseServerOptionsRequiresConnect(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseServerOptions([]string{"-listen", "0.0.0.0:56000"}, "server", &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("parseServerOptions() exitCode = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}
	if got := stderr.String(); !strings.Contains(got, "error: -connect is required") {
		t.Fatalf("expected missing connect error, got %q", got)
	}
}

func TestParseServerOptionsParsesValidArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	opts, exitCode := parseServerOptions([]string{"-connect", "127.0.0.1:51820", "-listen", "0.0.0.0:56000", "-vless"}, "server", &stdout, &stderr)
	if exitCode != cliutil.ContinueExecution {
		t.Fatalf("parseServerOptions() exitCode = %d, want %d", exitCode, cliutil.ContinueExecution)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
	if opts.connect != "127.0.0.1:51820" {
		t.Fatalf("connect = %q, want 127.0.0.1:51820", opts.connect)
	}
	if opts.listen != "0.0.0.0:56000" {
		t.Fatalf("listen = %q, want 0.0.0.0:56000", opts.listen)
	}
	if !opts.vlessMode {
		t.Fatal("vlessMode = false, want true")
	}
}
