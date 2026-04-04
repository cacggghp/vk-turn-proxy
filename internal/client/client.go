package client

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	piondtls "github.com/pion/dtls/v3"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/cacggghp/vk-turn-proxy/internal/dtls"
)

type GetCredsFunc func() (string, string, string, error)

type Config struct {
	ListenAddr string
	PeerAddr   *net.UDPAddr
	Secret     string
	Threads    int
	UseUDP     bool
	NoDTLS     bool
	GetCreds   GetCredsFunc
	TurnHost   string
	TurnPort   string
}

type turnParams struct {
	host     string
	port     string
	udp      bool
	getCreds GetCredsFunc
}

type Client struct {
	config Config
	params *turnParams
}

func New(config Config) *Client {
	return &Client{
		config: config,
		params: &turnParams{
			host:     config.TurnHost,
			port:     config.TurnPort,
			udp:      config.UseUDP,
			getCreds: config.GetCreds,
		},
	}
}

func (c *Client) Run(ctx context.Context) error {
	listenConnChan := make(chan net.PacketConn)
	listenConn, err := net.ListenPacket("udp", c.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", c.config.ListenAddr, err)
	}
	defer func() {
		if err := listenConn.Close(); err != nil {
			log.Printf("failed to close local connection: %v", err)
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenConnChan <- listenConn:
			}
		}
	}()

	var wg1 sync.WaitGroup
	t := time.Tick(200 * time.Millisecond)

	if c.config.NoDTLS {
		log.Println("WARNING: Running without DTLS obfuscation")
		for i := 0; i < c.config.Threads; i++ {
			wg1.Add(1)
			go func() {
				defer wg1.Done()
				c.turnConnectionLoop(ctx, listenConnChan, t)
			}()
		}
	} else {
		log.Printf("Starting proxy with %d TURN threads and DTLS obfuscation...\n", c.config.Threads)
		okchan := make(chan struct{})
		connchan := make(chan net.PacketConn)

		wg1.Add(1)
		go func() {
			defer wg1.Done()
			c.dtlsConnectionLoop(ctx, listenConnChan, connchan, okchan)
		}()

		wg1.Add(1)
		go func() {
			defer wg1.Done()
			c.turnConnectionLoop(ctx, connchan, t)
		}()

		select {
		case <-okchan:
			log.Println("First DTLS layer successfully established")
		case <-ctx.Done():
			return ctx.Err()
		}

		for i := 0; i < c.config.Threads-1; i++ {
			chanN := make(chan net.PacketConn)
			wg1.Add(1)
			go func() {
				defer wg1.Done()
				c.dtlsConnectionLoop(ctx, listenConnChan, chanN, nil)
			}()
			wg1.Add(1)
			go func() {
				defer wg1.Done()
				c.turnConnectionLoop(ctx, chanN, t)
			}()
		}
	}

	wg1.Wait()
	return nil
}

func (c *Client) dtlsFunc(ctx context.Context, conn net.PacketConn) (net.Conn, error) {
	config, err := dtls.ClientConfig(c.config.Secret)
	if err != nil {
		return nil, err
	}
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	dtlsConn, err := dtls.Client(conn, c.config.PeerAddr, config)
	if err != nil {
		return nil, err
	}

	if err := dtlsConn.(*piondtls.Conn).HandshakeContext(ctx1); err != nil {
		_ = dtlsConn.Close()
		return nil, err
	}
	return dtlsConn, nil
}

func (c *Client) dtlsConnectionLoop(ctx context.Context, listenConnChan <-chan net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case listenConn := <-listenConnChan:
			errChan := make(chan error)
			go c.oneDtlsConnection(ctx, listenConn, connchan, okchan, errChan)
			err := <-errChan
			if err != nil {
				log.Printf("DTLS connection error: %v. Reconnecting in %v...\n", err, backoff)
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return
				}
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			} else {
				backoff = time.Second // Reset backoff on success
			}
		}
	}
}

func (c *Client) oneDtlsConnection(ctx context.Context, listenConn net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, errChan chan<- error) {
	var err error
	defer func() { errChan <- err }()

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

	dtlsConn, err1 := c.dtlsFunc(dtlsctx, conn1)
	if err1 != nil {
		err = fmt.Errorf("failed to connect DTLS: %w", err1)
		return
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close DTLS connection: %w", closeErr)
			return
		}
	}()
	log.Printf("Established DTLS connection to %s\n", c.config.PeerAddr)

	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case okchan <- struct{}{}:
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	context.AfterFunc(dtlsctx, func() {
		_ = listenConn.SetDeadline(time.Now())
		_ = dtlsConn.SetDeadline(time.Now())
	})

	var addr atomic.Value

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
			n, addr1, err1 := listenConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("listenConn read failed: %v", err1)
				return
			}
			addr.Store(addr1)

			if _, err1 = dtlsConn.Write(buf[:n]); err1 != nil {
				log.Printf("dtlsConn write failed: %v", err1)
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
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				log.Printf("dtlsConn read failed: %v", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				log.Printf("failed: no listener ip")
				return
			}

			if _, err1 = listenConn.WriteTo(buf[:n], addr1); err1 != nil {
				log.Printf("listenConn write failed: %v", err1)
				return
			}
		}
	}()

	wg.Wait()
	_ = listenConn.SetDeadline(time.Time{})
	_ = dtlsConn.SetDeadline(time.Time{})
}

func (c *Client) turnConnectionLoop(ctx context.Context, connchan <-chan net.PacketConn, t <-chan time.Time) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t: // throttle baseline spawn rate
				errChan := make(chan error)
				go c.oneTurnConnection(ctx, conn2, errChan)
				err := <-errChan
				if err != nil {
					log.Printf("TURN connection error: %v. Reconnecting in %v...\n", err, backoff)
					select {
					case <-time.After(backoff):
					case <-ctx.Done():
						return
					}
					backoff *= 2
					if backoff > 30*time.Second {
						backoff = 30 * time.Second
					}
				} else {
					backoff = time.Second // Reset backoff on success
				}
			case <-ctx.Done():
				return
			}
		}
	}
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (conn *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return conn.Write(p)
}

func (c *Client) oneTurnConnection(ctx context.Context, conn2 net.PacketConn, errChan chan<- error) {
	var err error
	defer func() { errChan <- err }()

	user, pass, url, err1 := c.params.getCreds()
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %w", err1)
		return
	}

	urlhost, urlport, err1 := net.SplitHostPort(url)
	if err1 != nil {
		err = fmt.Errorf("failed to parse TURN server address: %w", err1)
		return
	}
	if c.params.host != "" {
		urlhost = c.params.host
	}
	if c.params.port != "" {
		urlport = c.params.port
	}

	turnServerAddr := net.JoinHostPort(urlhost, urlport)
	turnServerUdpAddr, err1 := net.ResolveUDPAddr("udp", turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %w", err1)
		return
	}
	turnServerAddr = turnServerUdpAddr.String()

	var turnConn net.PacketConn
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if c.params.udp {
		udpConn, err2 := net.DialUDP("udp", nil, turnServerUdpAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect UDP to TURN: %w", err2)
			return
		}
		defer func() { _ = udpConn.Close() }()
		turnConn = &connectedUDPConn{udpConn}
	} else {
		var d net.Dialer
		tcpConn, err2 := d.DialContext(ctx1, "tcp", turnServerAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect TCP to TURN: %w", err2)
			return
		}
		defer func() { _ = tcpConn.Close() }()
		turnConn = turn.NewSTUNConn(tcpConn)
	}

	addrFamily := turn.RequestedAddressFamilyIPv4
	if c.config.PeerAddr.IP.To4() == nil {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}

	client, err1 := turn.NewClient(cfg)
	if err1 != nil {
		err = fmt.Errorf("failed to create TURN client: %w", err1)
		return
	}
	defer client.Close()

	if err1 = client.Listen(); err1 != nil {
		err = fmt.Errorf("failed to start TURN client listener: %w", err1)
		return
	}

	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = fmt.Errorf("failed to allocate relay: %w", err1)
		return
	}
	defer func() {
		if err := relayConn.Close(); err != nil {
			log.Printf("failed to close relay connection: %v\n", err)
		}
	}()

	log.Printf("TURN Relayed address: %s", relayConn.LocalAddr().String())

	var wg sync.WaitGroup
	wg.Add(2)

	turnctx, turncancel := context.WithCancel(ctx)
	defer turncancel()

	context.AfterFunc(turnctx, func() {
		_ = relayConn.SetDeadline(time.Now())
		_ = conn2.SetDeadline(time.Now())
	})

	var addr atomic.Value

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
			n, addr1, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				log.Printf("conn2 read failed: %v", err1)
				return
			}
			addr.Store(addr1)
			if _, err1 = relayConn.WriteTo(buf[:n], c.config.PeerAddr); err1 != nil {
				log.Printf("relay write failed: %v", err1)
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
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("relay read failed: %v", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				log.Printf("failed: no listener ip")
				return
			}
			if _, err1 = conn2.WriteTo(buf[:n], addr1); err1 != nil {
				log.Printf("conn2 write failed: %v", err1)
				return
			}
		}
	}()

	wg.Wait()
	_ = relayConn.SetDeadline(time.Time{})
	_ = conn2.SetDeadline(time.Time{})
}
