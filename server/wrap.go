// SPDX-License-Identifier: MIT

package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"golang.org/x/crypto/chacha20poly1305"
)

// Wire format is identical to client. Server sets the MSB of sessionID/SSRC;
// client clears it. RTP header fields are per-conn.

const (
	wrapKeyLen     = 32
	wrapRTPHdrLen  = 12
	wrapNonceLen   = 12
	wrapTagLen     = 16
	wrapHeaderLen  = wrapRTPHdrLen + wrapNonceLen
	wrapOverhead   = wrapHeaderLen + wrapTagLen
	wrapRTPVersion = 0x80
	wrapRTPPT      = 0x6F
	wrapTSStep     = 960
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1600+wrapOverhead)
		return &b
	},
}

type wrapState struct {
	aead cipher.AEAD
}

func newWrapState(key []byte) (*wrapState, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("wrap: aead init: %w", err)
	}
	return &wrapState{aead: aead}, nil
}

func listenWrapped(addr *net.UDPAddr, key []byte) (dtlsnet.PacketListener, error) {
	ws, err := newWrapState(key)
	if err != nil {
		return nil, err
	}
	innerConn, err := listenPacketInfoUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wrap: udp listen: %w", err)
	}
	return &wrapPacketListener{
		inner: newUDPPacketListener(innerConn, nil),
		ws:    ws,
	}, nil
}

type wrapPacketListener struct {
	inner dtlsnet.PacketListener
	ws    *wrapState
}

func (l *wrapPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	c := &wrapPacketConn{inner: pc, ws: l.ws}

	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, addr, fmt.Errorf("wrap: rand init: %w", err)
	}
	copy(c.sessionID[:], rnd[0:4])
	copy(c.ssrc[:], rnd[4:8])
	c.sessionID[0] |= 0x80
	c.ssrc[0] |= 0x80
	c.seq.Store(uint32(binary.BigEndian.Uint16(rnd[8:10])))
	c.timestamp.Store(binary.BigEndian.Uint32(rnd[10:14]))

	var cb [8]byte
	if _, err := rand.Read(cb[:]); err != nil {
		return nil, addr, fmt.Errorf("wrap: counter rand: %w", err)
	}
	c.counter.Store(binary.BigEndian.Uint64(cb[:]))
	return c, addr, nil
}

func (l *wrapPacketListener) Close() error   { return l.inner.Close() }
func (l *wrapPacketListener) Addr() net.Addr { return l.inner.Addr() }

type wrapPacketConn struct {
	inner     net.PacketConn
	ws        *wrapState
	sessionID [4]byte
	ssrc      [4]byte
	counter   atomic.Uint64
	seq       atomic.Uint32
	timestamp atomic.Uint32
}

func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bp, ok := bufPool.Get().(*[]byte)
	if !ok {
		return 0, nil, errors.New("wrap: buffer pool returned invalid type")
	}
	buf := *bp
	need := len(p) + wrapOverhead
	if cap(buf) < need {
		buf = make([]byte, need)
		*bp = buf
	}
	defer bufPool.Put(bp)

	n, addr, err := c.inner.ReadFrom(buf[:cap(buf)])
	if err != nil {
		return 0, addr, err
	}
	wire := buf[:n]
	if len(wire) < wrapOverhead {
		return 0, addr, errors.New("wrap: packet too short")
	}
	nonce := wire[wrapRTPHdrLen : wrapRTPHdrLen+wrapNonceLen]
	aad := wire[:wrapHeaderLen]
	ct := wire[wrapHeaderLen:]

	plain, err := c.ws.aead.Open(ct[:0], nonce, ct, aad)
	if err != nil {
		return 0, addr, fmt.Errorf("wrap: AEAD open: %w", err)
	}
	if len(plain) > len(p) {
		return 0, addr, errors.New("wrap: dst buffer too small")
	}
	copy(p[:len(plain)], plain)
	return len(plain), addr, nil
}

func (c *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	wireLen := wrapOverhead + len(p)

	bp, ok := bufPool.Get().(*[]byte)
	if !ok {
		return 0, errors.New("wrap: buffer pool returned invalid type")
	}
	out := *bp
	if cap(out) < wireLen {
		out = make([]byte, wireLen)
		*bp = out
	}
	out = out[:wireLen]
	defer bufPool.Put(bp)

	out[0] = wrapRTPVersion
	out[1] = wrapRTPPT
	seq := uint16(c.seq.Add(1) - 1)
	binary.BigEndian.PutUint16(out[2:4], seq)
	ts := c.timestamp.Add(wrapTSStep) - wrapTSStep
	binary.BigEndian.PutUint32(out[4:8], ts)
	copy(out[8:12], c.ssrc[:])

	noncePos := wrapRTPHdrLen
	copy(out[noncePos:noncePos+4], c.sessionID[:])
	ctr := c.counter.Add(1) - 1
	binary.BigEndian.PutUint64(out[noncePos+4:noncePos+wrapNonceLen], ctr)

	nonce := out[noncePos : noncePos+wrapNonceLen]
	aad := out[:wrapHeaderLen]
	ctPos := wrapHeaderLen
	copy(out[ctPos:], p)
	c.ws.aead.Seal(out[ctPos:ctPos], nonce, out[ctPos:ctPos+len(p)], aad)

	if _, err := c.inner.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wrapPacketConn) Close() error                       { return c.inner.Close() }
func (c *wrapPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrapPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrapPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrapPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
