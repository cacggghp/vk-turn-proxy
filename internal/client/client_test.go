package client

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestClientNew checks the constructor returns a valid Client.
func TestClientNew(t *testing.T) {
	peerAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:56000")
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		PeerAddr:   peerAddr,
		Secret:     "test-secret",
		Threads:    1,
	}
	c := New(cfg)
	if c == nil {
		t.Fatal("New() returned nil")
	}
	if c.config.Secret != "test-secret" {
		t.Errorf("Expected secret 'test-secret', got %q", c.config.Secret)
	}
	if c.params == nil {
		t.Fatal("params should be initialized")
	}
}

// TestClientRunCancellation verifies the client exits cleanly when ctx is cancelled.
func TestClientRunCancellation(t *testing.T) {
	peerAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:59999")
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		PeerAddr:   peerAddr,
		Secret:     "test-secret",
		Threads:    1,
		NoDTLS:     true,
		GetCreds: func() (string, string, string, error) {
			return "user", "pass", "127.0.0.1:3478", nil
		},
	}
	c := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx)
	}()

	// Cancel after a brief moment
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run() did not exit after context cancellation")
	}
}

// TestConnectedUDPConnWriteTo tests that our wrapper correctly redirects WriteTo to Write.
func TestConnectedUDPConnWriteTo(t *testing.T) {
	// Bind a real UDP server
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// Connect from client side
	raw, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	conn := &connectedUDPConn{raw}

	// Write using WriteTo (addr is ignored by connectedUDPConn)
	msg := []byte("test-msg")
	n, err := conn.WriteTo(msg, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 9999}) // addr is intentionally wrong
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(msg) {
		t.Errorf("WriteTo wrote %d bytes, want %d", n, len(msg))
	}

	// Read from server side
	server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 100)
	nn, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server ReadFrom: %v", err)
	}
	if string(buf[:nn]) != string(msg) {
		t.Errorf("got %q, want %q", buf[:nn], msg)
	}
}
