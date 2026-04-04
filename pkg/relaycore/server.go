// SPDX-License-Identifier: GPL-3.0-only

package relaycore

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

type Server struct {
	cfg    ServerConfig
	logger *log.Logger
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.withDefaults(); err != nil {
		return nil, err
	}

	return &Server{
		cfg:    cfg,
		logger: getLogger(cfg.Logger),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve listen address: %w", err)
	}

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return fmt.Errorf("generate certificate: %w", err)
	}

	listener, err := dtls.Listen("udp", addr, &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	})
	if err != nil {
		return fmt.Errorf("listen for DTLS: %w", err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		if closeErr := listener.Close(); closeErr != nil {
			s.logger.Printf("failed to close listener: %s", closeErr)
		}
	}()

	s.logger.Printf("listening on %s", s.cfg.ListenAddr)

	var wg sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			s.logger.Printf("accept failed: %s", err)
			continue
		}

		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			s.handleConn(ctx, conn)
		}(conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			s.logger.Printf("failed to close incoming connection: %s", closeErr)
		}
	}()

	s.logger.Printf("connection from %s", conn.RemoteAddr())
	ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel1()

	dtlsConn, ok := conn.(*dtls.Conn)
	if !ok {
		s.logger.Printf("unexpected connection type: %T", conn)
		return
	}

	s.logger.Printf("start handshake")
	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		s.logger.Printf("handshake failed: %s", err)
		return
	}
	s.logger.Printf("handshake done")

	serverConn, err := net.Dial("udp", s.cfg.ConnectAddr)
	if err != nil {
		s.logger.Printf("dial upstream failed: %s", err)
		return
	}
	defer func() {
		if closeErr := serverConn.Close(); closeErr != nil {
			s.logger.Printf("failed to close outgoing connection: %s", closeErr)
		}
	}()

	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()

	context.AfterFunc(ctx2, func() {
		if err := conn.SetDeadline(time.Now()); err != nil {
			s.logger.Printf("failed to set incoming deadline: %s", err)
		}
		if err := serverConn.SetDeadline(time.Now()); err != nil {
			s.logger.Printf("failed to set outgoing deadline: %s", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel2()
		forwardPackets(conn, serverConn, s.logger)
	}()
	go func() {
		defer wg.Done()
		defer cancel2()
		forwardPackets(serverConn, conn, s.logger)
	}()
	wg.Wait()
	s.logger.Printf("connection closed: %s", conn.RemoteAddr())
}

func forwardPackets(src net.Conn, dst net.Conn, logger *log.Logger) {
	buf := make([]byte, 1600)
	for {
		if err := src.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
			logger.Printf("set read deadline failed: %s", err)
			return
		}
		n, err := src.Read(buf)
		if err != nil {
			logger.Printf("read failed: %s", err)
			return
		}

		if err := dst.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
			logger.Printf("set write deadline failed: %s", err)
			return
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			logger.Printf("write failed: %s", err)
			return
		}
	}
}
