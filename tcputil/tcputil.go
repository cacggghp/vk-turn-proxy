package tcputil

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type kcpProfile struct {
	nodelay    int
	interval   int
	resend     int
	nc         int
	sndWnd     int
	rcvWnd     int
	mtu        int
	ackNoDelay bool
}

func selectedKCPProfile() kcpProfile {
	profile := strings.ToLower(strings.TrimSpace(os.Getenv("VK_TURN_KCP_PROFILE")))
	var cfg kcpProfile
	switch profile {
	case "legacy", "fast":
		cfg = kcpProfile{
			nodelay:    1,
			interval:   10,
			resend:     2,
			nc:         1,
			sndWnd:     4096,
			rcvWnd:     4096,
			mtu:        1280,
			ackNoDelay: true,
		}
	case "cc", "balanced":
		cfg = kcpProfile{
			nodelay:    1,
			interval:   20,
			resend:     2,
			nc:         0,
			sndWnd:     512,
			rcvWnd:     512,
			mtu:        1200,
			ackNoDelay: true,
		}
	case "slow", "conservative":
		cfg = kcpProfile{
			nodelay:    0,
			interval:   40,
			resend:     2,
			nc:         0,
			sndWnd:     256,
			rcvWnd:     256,
			mtu:        1150,
			ackNoDelay: false,
		}
	default:
		cfg = kcpProfile{
			nodelay:    1,
			interval:   20,
			resend:     2,
			nc:         1,
			sndWnd:     512,
			rcvWnd:     512,
			mtu:        1200,
			ackNoDelay: true,
		}
	}

	cfg.nodelay = envInt("VK_TURN_KCP_NODELAY", cfg.nodelay)
	cfg.interval = envInt("VK_TURN_KCP_INTERVAL", cfg.interval)
	cfg.resend = envInt("VK_TURN_KCP_RESEND", cfg.resend)
	cfg.nc = envInt("VK_TURN_KCP_NC", cfg.nc)
	cfg.sndWnd = envInt("VK_TURN_KCP_SNDWND", cfg.sndWnd)
	cfg.rcvWnd = envInt("VK_TURN_KCP_RCVWND", cfg.rcvWnd)
	cfg.mtu = envInt("VK_TURN_KCP_MTU", cfg.mtu)
	cfg.ackNoDelay = envBool("VK_TURN_KCP_ACK_NODELAY", cfg.ackNoDelay)
	return cfg
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

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

	profile := selectedKCPProfile()
	sess.SetNoDelay(profile.nodelay, profile.interval, profile.resend, profile.nc)
	sess.SetWindowSize(profile.sndWnd, profile.rcvWnd)
	sess.SetMtu(profile.mtu)
	sess.SetACKNoDelay(profile.ackNoDelay)

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
