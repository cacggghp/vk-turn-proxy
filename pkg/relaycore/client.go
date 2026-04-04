// SPDX-License-Identifier: GPL-3.0-only

package relaycore

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

type Client struct {
	cfg    ClientConfig
	logger *log.Logger
}

type turnParams struct {
	host     string
	port     string
	link     string
	udp      bool
	provider CredentialProvider
	output   io.Writer
	logger   *log.Logger
}

type connectedUDPConn struct {
	*net.UDPConn
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if err := cfg.withDefaults(); err != nil {
		return nil, err
	}

	return &Client{
		cfg:    cfg,
		logger: getLogger(cfg.Logger),
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	peer, err := resolvePeerAddr(c.cfg.PeerAddr)
	if err != nil {
		return fmt.Errorf("resolve peer address: %w", err)
	}

	link := normalizeInviteLink(c.cfg.InviteKind, c.cfg.InviteLink)
	params := &turnParams{
		host:     c.cfg.TurnHost,
		port:     c.cfg.TurnPort,
		link:     link,
		udp:      c.cfg.UseTURNUDP,
		provider: PoolCredentials(c.cfg.CredentialProvider, c.cfg.ConnectionCount, c.logger),
		output:   c.cfg.RouteOutput,
		logger:   c.logger,
	}

	listenConn, err := net.ListenPacket("udp", c.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", c.cfg.ListenAddr, err)
	}
	defer listenConn.Close()

	listenConnChan := make(chan net.PacketConn)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenConnChan <- listenConn:
			}
		}
	}()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var wg sync.WaitGroup
	if c.cfg.DisableDTLS {
		for i := 0; i < c.cfg.ConnectionCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				oneTurnConnectionLoop(ctx, params, peer, listenConnChan, ticker.C)
			}()
		}
	} else {
		okchan := make(chan struct{})
		connchan := make(chan net.PacketConn)

		wg.Add(1)
		go func() {
			defer wg.Done()
			oneDTLSConnectionLoop(ctx, peer, listenConnChan, connchan, okchan, c.logger)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			oneTurnConnectionLoop(ctx, params, peer, connchan, ticker.C)
		}()

		select {
		case <-okchan:
		case <-ctx.Done():
		}

		for i := 0; i < c.cfg.ConnectionCount-1; i++ {
			connchan := make(chan net.PacketConn)
			wg.Add(1)
			go func() {
				defer wg.Done()
				oneDTLSConnectionLoop(ctx, peer, listenConnChan, connchan, nil, c.logger)
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				oneTurnConnectionLoop(ctx, params, peer, connchan, ticker.C)
			}()
		}
	}

	<-ctx.Done()
	if err := listenConn.SetDeadline(time.Now()); err != nil {
		c.logger.Printf("failed to unblock local listener: %s", err)
	}
	wg.Wait()

	return nil
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

func dtlsClient(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Client(conn, peer, config)
	if err != nil {
		return nil, err
	}

	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}

func oneDTLSConnection(
	ctx context.Context,
	peer *net.UDPAddr,
	listenConn net.PacketConn,
	connchan chan<- net.PacketConn,
	okchan chan<- struct{},
	logger *log.Logger,
	c chan<- error,
) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error
	defer func() { c <- err }()

	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()

	conn1, conn2 := connutil.AsyncPacketPipe()
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case connchan <- conn2:
			}
		}
	}()

	dtlsConn, err := dtlsClient(dtlsctx, conn1, peer)
	if err != nil {
		err = fmt.Errorf("failed to connect DTLS: %w", err)
		return
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close DTLS connection: %w", closeErr)
			return
		}
		logger.Printf("closed DTLS connection")
	}()
	logger.Printf("established DTLS connection")

	if okchan != nil {
		go func() {
			select {
			case okchan <- struct{}{}:
			case <-dtlsctx.Done():
			}
		}()
	}

	var clientWGAddr atomic.Value
	var wg sync.WaitGroup
	wg.Add(2)
	context.AfterFunc(dtlsctx, func() {
		if deadlineErr := listenConn.SetDeadline(time.Now()); deadlineErr != nil {
			logger.Printf("failed to set listener deadline: %s", deadlineErr)
		}
		if deadlineErr := dtlsConn.SetDeadline(time.Now()); deadlineErr != nil {
			logger.Printf("failed to set DTLS deadline: %s", deadlineErr)
		}
	})

	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, addr1, readErr := listenConn.ReadFrom(buf)
			if readErr != nil {
				logger.Printf("local read failed: %s", readErr)
				return
			}

			clientWGAddr.Store(addr1)

			if _, writeErr := dtlsConn.Write(buf[:n]); writeErr != nil {
				logger.Printf("DTLS write failed: %s", writeErr)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, readErr := dtlsConn.Read(buf)
			if readErr != nil {
				logger.Printf("DTLS read failed: %s", readErr)
				return
			}

			addr1, ok := clientWGAddr.Load().(net.Addr)
			if !ok {
				continue
			}

			if _, writeErr := listenConn.WriteTo(buf[:n], addr1); writeErr != nil {
				logger.Printf("local write failed: %s", writeErr)
				return
			}
		}
	}()

	wg.Wait()
	if clearErr := listenConn.SetDeadline(time.Time{}); clearErr != nil {
		logger.Printf("failed to clear listener deadline: %s", clearErr)
	}
	if clearErr := dtlsConn.SetDeadline(time.Time{}); clearErr != nil {
		logger.Printf("failed to clear DTLS deadline: %s", clearErr)
	}
}

func oneTurnConnection(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, c chan<- error) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error
	defer func() { c <- err }()

	creds, err := turnParams.provider.GetCredentials(ctx, turnParams.link)
	if err != nil {
		err = fmt.Errorf("failed to get TURN credentials: %w", err)
		return
	}

	urlhost, urlport, err := net.SplitHostPort(creds.Address)
	if err != nil {
		err = fmt.Errorf("failed to parse TURN server address: %w", err)
		return
	}
	if turnParams.host != "" {
		urlhost = turnParams.host
	}
	if turnParams.port != "" {
		urlport = turnParams.port
	}

	turnServerAddr := net.JoinHostPort(urlhost, urlport)
	turnServerUDPAddr, err := net.ResolveUDPAddr("udp", turnServerAddr)
	if err != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %w", err)
		return
	}
	turnServerAddr = turnServerUDPAddr.String()
	if turnParams.output != nil {
		if _, writeErr := fmt.Fprintln(turnParams.output, turnServerUDPAddr.IP); writeErr != nil {
			turnParams.logger.Printf("failed to write route output: %s", writeErr)
		}
	}

	var turnConn net.PacketConn
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if turnParams.udp {
		conn, dialErr := net.DialUDP("udp", nil, turnServerUDPAddr)
		if dialErr != nil {
			err = fmt.Errorf("failed to connect to TURN server: %w", dialErr)
			return
		}
		defer conn.Close()
		turnConn = &connectedUDPConn{conn}
	} else {
		var d net.Dialer
		conn, dialErr := d.DialContext(ctx1, "tcp", turnServerAddr)
		if dialErr != nil {
			err = fmt.Errorf("failed to connect to TURN server: %w", dialErr)
			return
		}
		defer conn.Close()
		turnConn = turn.NewSTUNConn(conn)
	}

	addrFamily := turn.RequestedAddressFamilyIPv6
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	}

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Net:                    newDirectNet(),
		Username:               creds.Username,
		Password:               creds.Password,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		err = fmt.Errorf("failed to create TURN client: %w", err)
		return
	}
	defer client.Close()

	if err = client.Listen(); err != nil {
		err = fmt.Errorf("failed to listen on TURN client: %w", err)
		return
	}

	relayConn, err := client.Allocate()
	if err != nil {
		err = fmt.Errorf("failed to allocate TURN relay: %w", err)
		return
	}
	defer relayConn.Close()

	turnParams.logger.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	turnctx, turncancel := context.WithCancel(ctx)
	defer turncancel()
	context.AfterFunc(turnctx, func() {
		if deadlineErr := relayConn.SetDeadline(time.Now()); deadlineErr != nil {
			turnParams.logger.Printf("failed to set relay deadline: %s", deadlineErr)
		}
		if deadlineErr := conn2.SetDeadline(time.Now()); deadlineErr != nil {
			turnParams.logger.Printf("failed to set upstream deadline: %s", deadlineErr)
		}
	})

	var internalPipeAddr atomic.Value
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, addr1, readErr := conn2.ReadFrom(buf)
			if readErr != nil {
				turnParams.logger.Printf("upstream read failed: %s", readErr)
				return
			}

			internalPipeAddr.Store(addr1)

			if _, writeErr := relayConn.WriteTo(buf[:n], peer); writeErr != nil {
				turnParams.logger.Printf("relay write failed: %s", writeErr)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, _, readErr := relayConn.ReadFrom(buf)
			if readErr != nil {
				turnParams.logger.Printf("relay read failed: %s", readErr)
				return
			}
			addr1, ok := internalPipeAddr.Load().(net.Addr)
			if !ok {
				turnParams.logger.Printf("relay has no internal listener address yet")
				return
			}

			if _, writeErr := conn2.WriteTo(buf[:n], addr1); writeErr != nil {
				turnParams.logger.Printf("upstream write failed: %s", writeErr)
				return
			}
		}
	}()

	wg.Wait()
	if clearErr := relayConn.SetDeadline(time.Time{}); clearErr != nil {
		turnParams.logger.Printf("failed to clear relay deadline: %s", clearErr)
	}
	if clearErr := conn2.SetDeadline(time.Time{}); clearErr != nil {
		turnParams.logger.Printf("failed to clear upstream deadline: %s", clearErr)
	}
}

func oneDTLSConnectionLoop(
	ctx context.Context,
	peer *net.UDPAddr,
	listenConnChan <-chan net.PacketConn,
	connchan chan<- net.PacketConn,
	okchan chan<- struct{},
	logger *log.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case listenConn := <-listenConnChan:
			c := make(chan error)
			go oneDTLSConnection(ctx, peer, listenConn, connchan, okchan, logger, c)
			if err := <-c; err != nil && ctx.Err() == nil {
				logger.Printf("%s", err)
			}
		}
	}
}

func oneTurnConnectionLoop(
	ctx context.Context,
	turnParams *turnParams,
	peer *net.UDPAddr,
	connchan <-chan net.PacketConn,
	t <-chan time.Time,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
			case <-ctx.Done():
				return
			}
			c := make(chan error)
			go oneTurnConnection(ctx, turnParams, peer, conn2, c)
			if err := <-c; err != nil && ctx.Err() == nil {
				turnParams.logger.Printf("%s", err)
			}
		}
	}
}

func normalizeInviteLink(kind InviteKind, raw string) string {
	normalized := raw
	switch kind {
	case InviteKindVK:
		parts := strings.Split(normalized, "join/")
		normalized = parts[len(parts)-1]
	case InviteKindYandex:
		parts := strings.Split(normalized, "j/")
		normalized = parts[len(parts)-1]
	}

	if idx := strings.IndexAny(normalized, "/?#"); idx != -1 {
		normalized = normalized[:idx]
	}

	return normalized
}
