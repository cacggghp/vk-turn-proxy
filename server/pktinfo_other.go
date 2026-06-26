//go:build !linux

package main

import "net"

func listenPacketInfoUDP(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	return net.ListenUDP(network, laddr)
}
