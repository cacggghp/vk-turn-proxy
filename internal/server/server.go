package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	piondtls "github.com/pion/dtls/v3"

	"github.com/cacggghp/vk-turn-proxy/internal/dtls"
)

// Config holds the configuration for the Server
type Config struct {
	ListenAddr     string
	ConnectAddr    string
	Secret         string
	HandshakeLimit int
}

// Server handles listening for obfuscated DTLS packets and tunneling them
type Server struct {
	config Config
}

// New creates a new Server with the given configuration
func New(config Config) *Server {
	return &Server{
		config: config,
	}
}

// Run starts the server and blocks until the context is canceled
func (s *Server) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve listen address %q: %v", s.config.ListenAddr, err)
	}

	dtlsConfig, err := dtls.ServerConfig(s.config.Secret)
	if err != nil {
		return fmt.Errorf("failed to configure DTLS server: %v", err)
	}

	listener, err := dtls.Listen("udp", addr, dtlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start DTLS listener on %s: %v", addr, err)
	}

	context.AfterFunc(ctx, func() {
		if err := listener.Close(); err != nil {
			log.Printf("failed to close DTLS listener: %v", err)
		}
	})

	if s.config.Secret != "" {
		log.Println("Listening with PSK authentication")
	} else {
		log.Println("Listening with self-signed certificate")
	}

	limit := s.config.HandshakeLimit
	if limit <= 0 {
		limit = 100 // default fallback
	}
	sem := make(chan struct{}, limit)

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("failed to accept connection: %v\n", err)
				continue
			}
		}

		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { <-sem }()
				s.handleConnection(ctx, c)
			}(conn)
		default:
			log.Printf("Rate limit exceeded for Handshakes, dropping incoming connection attempt")
			_ = conn.Close()
		}
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("failed to close incoming connection: %s", closeErr)
		}
	}()

	log.Printf("Connection from %s\n", conn.RemoteAddr())

	dtlsConn, ok := conn.(*piondtls.Conn)
	if !ok {
		log.Println("Type error: expected dtls.Conn")
		return
	}

	// Perform the handshake with a 5-second timeout to mitigate DoS attempts
	ctx1, cancel1 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel1()
	
	log.Println("Start handshake")
	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		log.Println("Handshake failed:", err)
		return
	}
	log.Println("Handshake done")

	serverConn, err := net.Dial("udp", s.config.ConnectAddr)
	if err != nil {
		log.Printf("failed to dial upstream: %v\n", err)
		return
	}
	defer func() {
		if err := serverConn.Close(); err != nil {
			log.Printf("failed to close outgoing connection: %s", err)
		}
	}()

	s.relay(ctx, conn, serverConn)
	log.Printf("Connection closed: %s\n", conn.RemoteAddr())
}

func (s *Server) relay(ctx context.Context, clientConn net.Conn, upstreamConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()

	context.AfterFunc(ctx2, func() {
		if err := clientConn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set incoming deadline: %s", err)
		}
		if err := upstreamConn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set outgoing deadline: %s", err)
		}
	})

	pump := func(src, dst net.Conn) {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			
			if err := src.SetReadDeadline(time.Now().Add(time.Minute * 30)); err != nil {
				log.Printf("Failed: %v", err)
				return
			}
			n, err := src.Read(buf)
			if err != nil {
				log.Printf("Failed: %v", err)
				return
			}

			if err := dst.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err != nil {
				log.Printf("Failed: %v", err)
				return
			}
			_, err = dst.Write(buf[:n])
			if err != nil {
				log.Printf("Failed: %v", err)
				return
			}
		}
	}

	go pump(clientConn, upstreamConn)
	go pump(upstreamConn, clientConn)

	wg.Wait()
}
