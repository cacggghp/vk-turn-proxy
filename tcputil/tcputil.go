package tcputil

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// dtlsPacketConn adapts a DTLS net.Conn to net.PacketConn for KCP.
// It does not own the underlying transport; callers must close dtlsConn
// through the cleanup function returned by NewKCPOverDTLS.
type dtlsPacketConn struct {
	conn net.Conn
}

func (d *dtlsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := d.conn.Read(b)
	return n, d.conn.RemoteAddr(), err
}

func (d *dtlsPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return d.conn.Write(b)
}

func (d *dtlsPacketConn) Close() error {
	return nil
}

func (d *dtlsPacketConn) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

func (d *dtlsPacketConn) SetDeadline(t time.Time) error {
	return d.conn.SetDeadline(t)
}

func (d *dtlsPacketConn) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

func (d *dtlsPacketConn) SetWriteDeadline(t time.Time) error {
	return d.conn.SetWriteDeadline(t)
}

// NewKCPOverDTLS creates a KCP session over a DTLS connection and returns
// an idempotent cleanup function for the entire KCP-over-DTLS transport.
// After a successful call, the caller should use the returned cleanup instead
// of closing dtlsConn directly.
//
// isServer: true for server-side (listener), false for client-side (dialer).
func NewKCPOverDTLS(dtlsConn net.Conn, isServer bool) (_ *kcp.UDPSession, cleanup func() error, err error) {
	var (
		listener  *kcp.Listener
		sess      *kcp.UDPSession
		closeErr  error
		closeOnce sync.Once
	)
	transportCleanup := func() error {
		closeOnce.Do(func() {
			var errs []error
			if sess != nil {
				if err := sess.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
					errs = append(errs, err)
				}
			}
			if listener != nil {
				if err := listener.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
					errs = append(errs, err)
				}
			}
			if err := dtlsConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
				errs = append(errs, err)
			}
			closeErr = errors.Join(errs...)
		})
		return closeErr
	}
	defer func() {
		if err == nil {
			return
		}
		if cleanupErr := transportCleanup(); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()

	block, err := kcp.NewNoneBlockCrypt(nil) // DTLS already encrypts
	if err != nil {
		return nil, nil, err
	}

	if isServer {
		// Server: listen on the PacketConn and accept one session
		listener, err = kcp.ServeConn(block, 0, 0, &dtlsPacketConn{conn: dtlsConn})
		if err != nil {
			return nil, nil, err
		}
		if err = listener.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return nil, nil, err
		}
		sess, err = listener.AcceptKCP()
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Client: dial through the PacketConn
		sess, err = kcp.NewConn2(dtlsConn.RemoteAddr(), block, 0, 0, &dtlsPacketConn{conn: dtlsConn})
		if err != nil {
			return nil, nil, err
		}
	}

	// Tune KCP for TURN tunnel:
	// - NoDelay mode for lower latency
	// - Window sizes suitable for ~5Mbit/s
	sess.SetNoDelay(1, 20, 2, 1) // nodelay, interval(ms), resend, nc
	sess.SetWindowSize(256, 256)
	sess.SetMtu(1200) // conservative MTU to fit inside DTLS+TURN
	sess.SetACKNoDelay(true)

	return sess, transportCleanup, nil
}

// DefaultSmuxConfig returns smux config tuned for TURN tunnel.
func DefaultSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.MaxReceiveBuffer = 4 * 1024 * 1024
	cfg.MaxStreamBuffer = 1 * 1024 * 1024
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	return cfg
}
