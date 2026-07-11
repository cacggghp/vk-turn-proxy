package tcputil

import (
	"net"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// DtlsPacketConn wraps a net.Conn (DTLS) as a net.PacketConn for KCP.
// Each DTLS Read/Write preserves message boundaries (datagram semantics).
type DtlsPacketConn struct {
	conn net.Conn
}

func NewDtlsPacketConn(conn net.Conn) *DtlsPacketConn {
	return &DtlsPacketConn{conn: conn}
}

func (d *DtlsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := d.conn.Read(b)
	return n, d.conn.RemoteAddr(), err
}

func (d *DtlsPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return d.conn.Write(b)
}

func (d *DtlsPacketConn) Close() error {
	return d.conn.Close()
}

func (d *DtlsPacketConn) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

func (d *DtlsPacketConn) SetDeadline(t time.Time) error {
	return d.conn.SetDeadline(t)
}

func (d *DtlsPacketConn) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

func (d *DtlsPacketConn) SetWriteDeadline(t time.Time) error {
	return d.conn.SetWriteDeadline(t)
}

// NewKCPOverDTLS creates a KCP session over a DTLS connection.
// isServer: true for server-side (listener), false for client-side (dialer).
func NewKCPOverDTLS(dtlsConn net.Conn, isServer bool) (*kcp.UDPSession, error) {
	pc := NewDtlsPacketConn(dtlsConn)

	block, err := kcp.NewNoneBlockCrypt(nil) // DTLS already encrypts
	if err != nil {
		return nil, err
	}

	var sess *kcp.UDPSession

	if isServer {
		// Server: listen on the PacketConn and accept one session
		var listener *kcp.Listener
		listener, err = kcp.ServeConn(block, 0, 0, pc)
		if err != nil {
			return nil, err
		}
		if err = listener.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return nil, err
		}
		sess, err = listener.AcceptKCP()
		if err != nil {
			return nil, err
		}
	} else {
		// Client: dial through the PacketConn
		sess, err = kcp.NewConn2(dtlsConn.RemoteAddr(), block, 0, 0, pc)
		if err != nil {
			return nil, err
		}
	}

	// Tune KCP for TURN tunnel:
	// - NoDelay mode for lower latency
	// - Window sizes suitable for ~5Mbit/s
	sess.SetNoDelay(1, 20, 2, 1) // nodelay, interval(ms), resend, nc
	sess.SetWindowSize(256, 256)
	sess.SetMtu(1200) // conservative MTU to fit inside DTLS+TURN
	sess.SetACKNoDelay(true)

	return sess, nil
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
