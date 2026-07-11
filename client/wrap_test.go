package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestWrapConnRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, wrapKeyLen)
	payload := []byte("dtls record bytes")

	client, err := newWrapConn(key, false)
	if err != nil {
		t.Fatalf("newWrapConn(client): %v", err)
	}
	server, err := newWrapConn(key, true)
	if err != nil {
		t.Fatalf("newWrapConn(server): %v", err)
	}

	wire := make([]byte, wrapMaxWire(len(payload)))
	n, err := client.wrapInto(wire, payload)
	if err != nil {
		t.Fatalf("wrapInto: %v", err)
	}
	wire = wire[:n]

	if wire[0] != wrapRTPVersion {
		t.Fatalf("RTP byte0 = 0x%02X, want 0x%02X", wire[0], wrapRTPVersion)
	}
	if wire[1] != wrapRTPPT {
		t.Fatalf("RTP byte1 (PT) = 0x%02X, want 0x%02X", wire[1], wrapRTPPT)
	}
	if bytes.Contains(wire, payload) {
		t.Fatalf("wrapped packet contains plaintext payload")
	}

	dst := make([]byte, 1600)
	m, err := server.unwrapPacket(wire, dst)
	if err != nil {
		t.Fatalf("unwrapPacket: %v", err)
	}
	if m != len(payload) {
		t.Fatalf("unwrapped len = %d, want %d", m, len(payload))
	}
	if !bytes.Equal(dst[:m], payload) {
		t.Fatalf("round trip mismatch: got %q want %q", dst[:m], payload)
	}

	// Server → Client
	wire2 := make([]byte, wrapMaxWire(len(payload)))
	n2, err := server.wrapInto(wire2, payload)
	if err != nil {
		t.Fatalf("server wrapInto: %v", err)
	}
	m2, err := client.unwrapPacket(wire2[:n2], dst)
	if err != nil {
		t.Fatalf("client unwrapPacket: %v", err)
	}
	if !bytes.Equal(dst[:m2], payload) {
		t.Fatalf("server→client round trip mismatch")
	}
}

func TestWrapRTPHeaderProgression(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, wrapKeyLen)
	wc, err := newWrapConn(key, false)
	if err != nil {
		t.Fatalf("newWrapConn: %v", err)
	}
	payload := []byte("x")

	wire1 := make([]byte, wrapMaxWire(len(payload)))
	n1, err := wc.wrapInto(wire1, payload)
	if err != nil {
		t.Fatalf("wrapInto 1: %v", err)
	}
	wire2 := make([]byte, wrapMaxWire(len(payload)))
	n2, err := wc.wrapInto(wire2, payload)
	if err != nil {
		t.Fatalf("wrapInto 2: %v", err)
	}
	if n1 != n2 {
		t.Fatalf("wire size variance: %d vs %d", n1, n2)
	}

	seq1 := binary.BigEndian.Uint16(wire1[2:4])
	seq2 := binary.BigEndian.Uint16(wire2[2:4])
	if seq2 != seq1+1 {
		t.Fatalf("seq did not increment: %d → %d", seq1, seq2)
	}

	ts1 := binary.BigEndian.Uint32(wire1[4:8])
	ts2 := binary.BigEndian.Uint32(wire2[4:8])
	if ts2-ts1 != wrapTSStep {
		t.Fatalf("timestamp step = %d, want %d", ts2-ts1, wrapTSStep)
	}

	// SSRC stable across packets.
	if !bytes.Equal(wire1[8:12], wire2[8:12]) {
		t.Fatalf("SSRC changed between packets")
	}
}

func TestWrapDirectionBit(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, wrapKeyLen)
	client, err := newWrapConn(key, false)
	if err != nil {
		t.Fatalf("newWrapConn(client): %v", err)
	}
	server, err := newWrapConn(key, true)
	if err != nil {
		t.Fatalf("newWrapConn(server): %v", err)
	}

	if client.sessionID[0]&0x80 != 0 {
		t.Fatalf("client sessionID MSB should be 0, got 0x%02X", client.sessionID[0])
	}
	if server.sessionID[0]&0x80 == 0 {
		t.Fatalf("server sessionID MSB should be 1, got 0x%02X", server.sessionID[0])
	}
	if client.ssrc[0]&0x80 != 0 {
		t.Fatalf("client SSRC MSB should be 0, got 0x%02X", client.ssrc[0])
	}
	if server.ssrc[0]&0x80 == 0 {
		t.Fatalf("server SSRC MSB should be 1, got 0x%02X", server.ssrc[0])
	}
}

func TestDecodeWrapKeyRequiresValidKeyWhenEnabled(t *testing.T) {
	if key, err := decodeWrapKey(false, ""); err != nil || key != nil {
		t.Fatalf("disabled decodeWrapKey = (%v, %v), want (nil, nil)", key, err)
	}

	if _, err := decodeWrapKey(true, ""); err == nil {
		t.Fatalf("decodeWrapKey accepted empty key")
	}

	shortHex := strings.Repeat("ab", wrapKeyLen-1)
	if _, err := decodeWrapKey(true, shortHex); err == nil {
		t.Fatalf("decodeWrapKey accepted short key")
	}

	fullHex := strings.Repeat("ab", wrapKeyLen)
	key, err := decodeWrapKey(true, fullHex)
	if err != nil {
		t.Fatalf("decodeWrapKey returned error: %v", err)
	}
	if len(key) != wrapKeyLen {
		t.Fatalf("decoded key len = %d, want %d", len(key), wrapKeyLen)
	}
}

func TestUnwrapRejectsShortPacket(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, wrapKeyLen)
	wc, err := newWrapConn(key, false)
	if err != nil {
		t.Fatalf("newWrapConn: %v", err)
	}
	if _, err := wc.unwrapPacket([]byte("short"), make([]byte, 16)); err == nil {
		t.Fatalf("unwrapPacket accepted short packet")
	}
}

func TestUnwrapRejectsTamperedPacket(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, wrapKeyLen)
	client, err := newWrapConn(key, false)
	if err != nil {
		t.Fatalf("newWrapConn(client): %v", err)
	}
	server, err := newWrapConn(key, true)
	if err != nil {
		t.Fatalf("newWrapConn(server): %v", err)
	}

	payload := []byte("integrity test")
	wire := make([]byte, wrapMaxWire(len(payload)))
	n, err := client.wrapInto(wire, payload)
	if err != nil {
		t.Fatalf("wrapInto: %v", err)
	}
	wire = wire[:n]

	// Flip a bit in the ciphertext.
	wire[wrapHeaderLen+1] ^= 0xFF

	dst := make([]byte, 1600)
	if _, err := server.unwrapPacket(wire, dst); err == nil {
		t.Fatalf("unwrapPacket accepted tampered ciphertext")
	}

	// Re-wrap and tamper RTP header (AAD).
	n2, _ := client.wrapInto(wire, payload)
	wire = wire[:n2]
	wire[8] ^= 0x01 // flip a bit in SSRC
	if _, err := server.unwrapPacket(wire, dst); err == nil {
		t.Fatalf("unwrapPacket accepted tampered AAD")
	}
}
