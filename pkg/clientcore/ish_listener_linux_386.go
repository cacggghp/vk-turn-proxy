//go:build linux && 386

package clientcore

import (
	"io"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

type ishListener struct {
	net.Listener
	f  *os.File
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

	// Keep a reference to *os.File so the garbage collector doesn't close the FD.
	return &ishListener{Listener: ln, f: f, fd: int(f.Fd())}, nil
}

func (l *ishListener) Accept() (net.Conn, error) {
	// Set the listener socket to blocking mode. Go makes it non-blocking by default.
	// This avoids using time.Sleep in a spin-loop, which triggers futex_time64 SIGSYS in modern Go on iSH.
	if err := syscall.SetNonblock(l.fd, false); err != nil {
		return nil, err
	}

	for {
		addr := make([]byte, 128)
		addrlen := uintptr(128)

		// i386 network syscalls are multiplexed via socketcall (102).
		// SYS_ACCEPT is subcall 5.
		args := [3]uintptr{uintptr(l.fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(unsafe.Pointer(&addrlen))}

		// Use Syscall6 to ensure we have enough arguments registers for the platform.
		r1, _, errno := syscall.Syscall6(102, 5, uintptr(unsafe.Pointer(&args)), 0, 0, 0, 0)
		if errno != 0 {
			if errno == syscall.EINTR {
				continue
			}
			return nil, errno
		}

		nfd := int(r1)
		_ = syscall.SetsockoptInt(nfd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
		_ = syscall.SetsockoptInt(nfd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256*1024)
		_ = syscall.SetsockoptInt(nfd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 256*1024)

		// We avoid Go's net.FileConn because it tries to register the fd with Go's epoll poller,
		// which in iSH emulator consistency fails with EEXIST (file exists).
		// Instead, we return a custom blocking net.Conn wrapper.
		conn := &ishConn{fd: nfd}
		return conn, nil
	}
}

func (l *ishListener) Close() error {
	// Close both the duplicated FD and the original listener.
	err1 := l.f.Close()
	err2 := l.Listener.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// ishConn bypasses Go's network poller to prevent EEXIST bugs in iSH
type ishConn struct {
	fd int
}

func (c *ishConn) Read(b []byte) (n int, err error) {
	for {
		n, err = syscall.Read(c.fd, b)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return n, err
		}
		if n == 0 {
			return 0, os.ErrClosed
		}
		return n, nil
	}
}

func (c *ishConn) Write(b []byte) (n int, err error) {
	for n < len(b) {
		written, writeErr := syscall.Write(c.fd, b[n:])
		if writeErr == syscall.EINTR {
			continue
		}
		if writeErr != nil {
			return n, writeErr
		}
		if written == 0 {
			return n, io.ErrShortWrite
		}
		n += written
	}
	return n, nil
}

func (c *ishConn) Close() error {
	return syscall.Close(c.fd)
}

func (c *ishConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
}

func (c *ishConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *ishConn) SetDeadline(t time.Time) error      { return nil }
func (c *ishConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *ishConn) SetWriteDeadline(t time.Time) error { return nil }
