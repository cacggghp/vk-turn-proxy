// SPDX-License-Identifier: MIT

package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// Wire format — SRTP-like mimicry:
//
//	[12B RTP header | 12B explicit nonce | AEAD ciphertext | 16B tag]
//
// RTP header (RFC 3550):
//
//	byte 0: 0x80         V=2, P=0, X=0, CC=0
//	byte 1: 0x6F         M=0, PT=111 (opus, typical voice PT)
//	byte 2-3: seq16 BE   monotonic, init random
//	byte 4-7: ts32 BE    monotonic, init random, increments by 960 (20ms @ 48kHz)
//	byte 8-11: SSRC      random per conn, MSB encodes direction
//
// 12B explicit nonce = 4B sessionID || 8B counter (BE). sessionID MSB
// matches SSRC MSB (direction bit). counter starts at a random uint64.
// AAD = first 24 bytes (RTP header || nonce).
//
// VK TURN appears to forward SRTP-shaped ChannelData on a fast path and
// drop anomalous payloads. AEAD ciphertext + 16B tag is plausible as
// AES-GCM SRTP per RFC 7714.

const (
	wrapKeyLen     = 32
	wrapRTPHdrLen  = 12
	wrapNonceLen   = 12
	wrapTagLen     = 16
	wrapHeaderLen  = wrapRTPHdrLen + wrapNonceLen // 24
	wrapOverhead   = wrapHeaderLen + wrapTagLen   // 40
	wrapRTPVersion = 0x80                         // V=2, P=0, X=0, CC=0
	wrapRTPPT      = 0x6F                         // M=0, PT=111 (opus)
	wrapTSStep     = 960                          // 20ms @ 48kHz
)

type wrapConn struct {
	aead      cipher.AEAD
	sessionID [4]byte // 4B prefix for nonce; MSB encodes direction
	ssrc      [4]byte // SSRC for RTP header; MSB encodes direction
	counter   atomic.Uint64
	seq       atomic.Uint32 // RTP sequence (used as uint16)
	timestamp atomic.Uint32 // RTP timestamp
}

func newWrapConn(key []byte, isServer bool) (*wrapConn, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("wrap: aead init: %w", err)
	}
	w := &wrapConn{aead: aead}

	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("wrap: rand init: %w", err)
	}
	copy(w.sessionID[:], rnd[0:4])
	copy(w.ssrc[:], rnd[4:8])
	if isServer {
		w.sessionID[0] |= 0x80
		w.ssrc[0] |= 0x80
	} else {
		w.sessionID[0] &^= 0x80
		w.ssrc[0] &^= 0x80
	}
	w.seq.Store(uint32(binary.BigEndian.Uint16(rnd[8:10])))
	w.timestamp.Store(binary.BigEndian.Uint32(rnd[10:14]))

	var cb [8]byte
	if _, err := rand.Read(cb[:]); err != nil {
		return nil, fmt.Errorf("wrap: counter rand: %w", err)
	}
	w.counter.Store(binary.BigEndian.Uint64(cb[:]))
	return w, nil
}

// wrapMaxWire returns max wire bytes for a given payload size.
func wrapMaxWire(payloadLen int) int {
	return wrapOverhead + payloadLen
}

func (w *wrapConn) wrapInto(dst, payload []byte) (int, error) {
	wireLen := wrapOverhead + len(payload)
	if len(dst) < wireLen {
		return 0, errors.New("wrap: dst buffer too small")
	}

	// RTP header.
	dst[0] = wrapRTPVersion
	dst[1] = wrapRTPPT
	seq := uint16(w.seq.Add(1) - 1)
	binary.BigEndian.PutUint16(dst[2:4], seq)
	ts := w.timestamp.Add(wrapTSStep) - wrapTSStep
	binary.BigEndian.PutUint32(dst[4:8], ts)
	copy(dst[8:12], w.ssrc[:])

	// Explicit nonce.
	noncePos := wrapRTPHdrLen
	copy(dst[noncePos:noncePos+4], w.sessionID[:])
	ctr := w.counter.Add(1) - 1
	binary.BigEndian.PutUint64(dst[noncePos+4:noncePos+wrapNonceLen], ctr)

	nonce := dst[noncePos : noncePos+wrapNonceLen]
	aad := dst[:wrapHeaderLen]
	ctPos := wrapHeaderLen
	copy(dst[ctPos:], payload)
	w.aead.Seal(dst[ctPos:ctPos], nonce, dst[ctPos:ctPos+len(payload)], aad)

	return wireLen, nil
}

func (w *wrapConn) unwrapPacket(wire, dst []byte) (int, error) {
	if len(wire) < wrapOverhead {
		return 0, errors.New("wrap: packet too short")
	}
	nonce := wire[wrapRTPHdrLen : wrapRTPHdrLen+wrapNonceLen]
	aad := wire[:wrapHeaderLen]
	ct := wire[wrapHeaderLen:]

	plain, err := w.aead.Open(ct[:0], nonce, ct, aad)
	if err != nil {
		return 0, fmt.Errorf("wrap: AEAD open: %w", err)
	}
	if len(plain) > len(dst) {
		return 0, errors.New("wrap: dst buffer too small")
	}
	copy(dst[:len(plain)], plain)
	return len(plain), nil
}

// --- Helpers ---

func genWrapKeyHex() (string, error) {
	key := make([]byte, wrapKeyLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("wrap: key gen: %w", err)
	}
	return hex.EncodeToString(key), nil
}

func decodeWrapKey(enabled bool, raw string) ([]byte, error) {
	if !enabled {
		return nil, nil
	}
	if raw == "" {
		return nil, errors.New("-wrap requires -wrap-key")
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("-wrap-key invalid hex: %w", err)
	}
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("-wrap-key must decode to %d bytes (got %d)", wrapKeyLen, len(key))
	}
	return key, nil
}
