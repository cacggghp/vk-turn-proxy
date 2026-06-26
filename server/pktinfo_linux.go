//go:build linux

package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type packetInfoUDPConn struct {
	conn *net.UDPConn
	ipv4 *ipv4.PacketConn
	ipv6 *ipv6.PacketConn
	v6   bool

	mu       sync.RWMutex
	localIPs map[string]net.IP
}

func listenPacketInfoUDP(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}

	pc := &packetInfoUDPConn{
		conn:     conn,
		ipv4:     ipv4.NewPacketConn(conn),
		ipv6:     ipv6.NewPacketConn(conn),
		v6:       laddr != nil && laddr.IP != nil && laddr.IP.To4() == nil,
		localIPs: make(map[string]net.IP),
	}
	if pc.v6 {
		if err = pc.ipv6.SetControlMessage(ipv6.FlagDst, true); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("enable IPv6 packet info: %w", err)
		}
	} else if err = pc.ipv4.SetControlMessage(ipv4.FlagDst, true); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("enable IPv4 packet info: %w", err)
	}

	return pc, nil
}

func (c *packetInfoUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.v6 {
		n, cm, addr, err := c.ipv6.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if udpAddr, ok := addr.(*net.UDPAddr); ok && cm != nil && cm.Dst != nil {
			c.rememberLocalIP(udpAddr.String(), cm.Dst)
		}
		return n, addr, nil
	}

	n, cm, addr, err := c.ipv4.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok && cm != nil && cm.Dst != nil {
		c.rememberLocalIP(udpAddr.String(), cm.Dst)
	}
	return n, addr, nil
}

func (c *packetInfoUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("packet info write: expected *net.UDPAddr, got %T", addr)
	}

	localIP := c.localIPFor(udpAddr.String())
	if localIP == nil {
		return c.conn.WriteTo(p, addr)
	}
	if localIP.To4() != nil {
		return c.ipv4.WriteTo(p, &ipv4.ControlMessage{Src: localIP}, addr)
	}
	return c.ipv6.WriteTo(p, &ipv6.ControlMessage{Src: localIP}, addr)
}

func (c *packetInfoUDPConn) Close() error {
	return c.conn.Close()
}

func (c *packetInfoUDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *packetInfoUDPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *packetInfoUDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *packetInfoUDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *packetInfoUDPConn) rememberLocalIP(remote string, ip net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localIPs[remote] = append(net.IP(nil), ip...)
}

func (c *packetInfoUDPConn) localIPFor(remote string) net.IP {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ip := c.localIPs[remote]
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}
