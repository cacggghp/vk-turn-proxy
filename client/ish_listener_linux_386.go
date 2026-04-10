//go:build linux && 386
package main

import (
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

type ishListener struct {
	net.Listener
	fd int
}

// wrapISHListener overrides the standard net.Listener with a legacy syscall listener
// designed specifically for the iSH simulator on iOS, which lacks modern `accept4`.
func wrapISHListener(ln net.Listener) (net.Listener, error) {
	tl, ok := ln.(*net.TCPListener)
	if !ok {
		return ln, nil
	}
	f, err := tl.File()
	if err != nil {
		return nil, err
	}
	
	return &ishListener{Listener: ln, fd: int(f.Fd())}, nil
}

func (l *ishListener) Accept() (net.Conn, error) {
	for {
		addr := make([]byte, 128)
		addrlen := uintptr(128)
		
		// i386 network syscalls are multiplexed via socketcall (102). 
		// SYS_ACCEPT is subcall 5.
		args := [3]uintptr{uintptr(l.fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(unsafe.Pointer(&addrlen))}
		
		r1, _, errno := syscall.Syscall(102, 5, uintptr(unsafe.Pointer(&args)), 0)
		if errno != 0 {
			if errno == syscall.EAGAIN || errno == syscall.EINTR || errno == syscall.EWOULDBLOCK {
				time.Sleep(50 * time.Millisecond) // Just in case it's non-blocking somehow
				continue
			}
			return nil, errno
		}
		
		nfd := int(r1)
		
		// Wrap raw FD into os.File, then into a net.Conn.
		// fileConn duplicates the fd again.
		f := os.NewFile(uintptr(nfd), "ish-conn")
		conn, err := net.FileConn(f)
		f.Close()
		
		if err != nil {
			syscall.Close(nfd)
			return nil, err
		}
		
		return conn, nil
	}
}

func (l *ishListener) Close() error {
	err1 := syscall.Close(l.fd)
	err2 := l.Listener.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
