//go:build !(linux && 386)

package main

import "net"

// wrapISHListener is a no-op for architectures that don't need the legacy socketcall accept bypass.
func wrapISHListener(ln net.Listener) (net.Listener, error) {
	return ln, nil
}
