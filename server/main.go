package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/internal/cliutil"
	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/xtaci/smux"
)

type serverOptions struct {
	listen    string
	connect   string
	vlessMode bool
}

func newServerFlagSet(program string, output io.Writer) (*flag.FlagSet, *serverOptions) {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	fs.SetOutput(output)

	opts := &serverOptions{}
	fs.StringVar(&opts.listen, "listen", "0.0.0.0:56000", "listen on ip:port")
	fs.StringVar(&opts.connect, "connect", "", "connect to ip:port")
	fs.BoolVar(&opts.vlessMode, "vless", false, "VLESS mode: forward TCP connections (for VLESS) instead of UDP packets")
	fs.Usage = func() {
		cliutil.Fprintf(fs.Output(), "Usage:\n  %s -connect <ip:port> [flags]\n\n", program)
		cliutil.Fprintln(fs.Output(), "Examples:")
		cliutil.Fprintf(fs.Output(), "  %s -connect 127.0.0.1:51820\n", program)
		cliutil.Fprintf(fs.Output(), "  %s -listen 0.0.0.0:56000 -connect 127.0.0.1:51820 -vless\n\n", program)
		cliutil.Fprintln(fs.Output(), "Flags:")
		fs.PrintDefaults()
	}

	return fs, opts
}

func parseServerOptions(args []string, program string, stdout, stderr io.Writer) (serverOptions, int) {
	return cliutil.Parse(args, program, stdout, stderr, newServerFlagSet, func(opts *serverOptions) error {
		if opts.connect == "" {
			return fmt.Errorf("-connect is required")
		}
		return nil
	})
}

func main() {
	opts, exitCode := parseServerOptions(os.Args[1:], filepath.Base(os.Args[0]), os.Stdout, os.Stderr)
	if exitCode != cliutil.ContinueExecution {
		os.Exit(exitCode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	addr, err := net.ResolveUDPAddr("udp", opts.listen)
	if err != nil {
		panic(err)
	}
	// Generate a certificate and private key to secure the connection
	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	// Connect to a DTLS server
	listener, err := dtls.ListenWithOptions(
		"udp",
		addr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		if err = listener.Close(); err != nil {
			panic(err)
		}
	})

	cliutil.Fprintln(os.Stdout, "Listening")

	wg1 := sync.WaitGroup{}
	for {
		select {
		case <-ctx.Done():
			wg1.Wait()
			return
		default:
		}
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		wg1.Add(1)
		go func(conn net.Conn) {
			defer wg1.Done()
			closeConn := true
			defer func() {
				if !closeConn {
					return
				}
				if closeErr := conn.Close(); closeErr != nil {
					log.Printf("failed to close incoming connection: %s", closeErr)
				}
			}()
			log.Printf("Connection from %s\n", conn.RemoteAddr())

			// Perform the handshake with a 30-second timeout
			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			defer cancel1()

			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error: expected *dtls.Conn")
				return
			}
			log.Println("Start handshake")
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Printf("Handshake failed: %v", err)
				return
			}
			log.Println("Handshake done")

			if opts.vlessMode {
				closeConn = false
				handleVLESSConnection(ctx, dtlsConn, opts.connect)
			} else {
				handleUDPConnection(ctx, conn, opts.connect)
			}

			log.Printf("Connection closed: %s\n", conn.RemoteAddr())
		}(conn)
	}
}

// handleUDPConnection forwards DTLS packets to a UDP backend (WireGuard).
func handleUDPConnection(ctx context.Context, conn net.Conn, connectAddr string) {
	serverConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer func() {
		if err = serverConn.Close(); err != nil {
			log.Printf("failed to close outgoing connection: %s", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	ctx2, cancel2 := context.WithCancel(ctx)
	context.AfterFunc(ctx2, func() {
		if err := conn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set incoming deadline: %s", err)
		}
		if err := serverConn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set outgoing deadline: %s", err)
		}
	})
	startPacketForwarder(ctx2, &wg, cancel2, conn, serverConn)
	startPacketForwarder(ctx2, &wg, cancel2, serverConn, conn)
	wg.Wait()
}

// handleVLESSConnection creates a KCP+smux session over DTLS and forwards
// each smux stream as a TCP connection to the backend (Xray/VLESS).
// It takes ownership of dtlsConn and closes it through the KCP cleanup path.
func handleVLESSConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string) {
	// 1. Create KCP session over DTLS
	kcpSess, cleanupKCP, err := tcputil.NewKCPOverDTLS(dtlsConn, true)
	if err != nil {
		log.Printf("KCP session error: %s", err)
		return
	}
	defer func() {
		if err := cleanupKCP(); err != nil {
			log.Printf("failed to close KCP-over-DTLS transport: %v", err)
		}
	}()
	log.Printf("KCP session established (server)")

	// 2. Create smux server session over KCP
	smuxSess, err := smux.Server(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		log.Printf("smux server error: %s", err)
		return
	}
	defer func() {
		if err := smuxSess.Close(); err != nil {
			log.Printf("failed to close smux session: %v", err)
		}
	}()
	log.Printf("smux session established (server)")

	// 3. Accept smux streams and forward to backend via TCP
	var wg sync.WaitGroup
	for {
		stream, err := smuxSess.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				log.Printf("smux accept error: %s", err)
			}
			break
		}

		wg.Add(1)
		go func(s *smux.Stream) {
			defer wg.Done()

			defer func() {
				if err := s.Close(); err != nil && !errors.Is(err, smux.ErrGoAway) {
					log.Printf("failed to close smux stream: %v", err)
				}
			}()

			// Connect to backend (Xray/VLESS)
			backendConn, err := net.DialTimeout("tcp", connectAddr, 10*time.Second)
			if err != nil {
				log.Printf("backend dial error: %s", err)
				return
			}
			defer func() {
				if err := backendConn.Close(); err != nil {
					log.Printf("failed to close backend connection: %v", err)
				}
			}()

			// Bidirectional copy
			pipeConn(ctx, s, backendConn)
		}(stream)
	}
	wg.Wait()
}

// pipeConn copies data bidirectionally between two connections.
func pipeConn(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	context.AfterFunc(ctx2, func() {
		if err := c1.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c1: %v", err)
		}
		if err := c2.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c2: %v", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)
	startStreamCopy(&wg, cancel, c1, c2, "pipeConn: c1<-c2")
	startStreamCopy(&wg, cancel, c2, c1, "pipeConn: c2<-c1")

	wg.Wait()

	// Reset deadlines
	_ = c1.SetDeadline(time.Time{})
	_ = c2.SetDeadline(time.Time{})
}

func startPacketForwarder(ctx context.Context, wg *sync.WaitGroup, cancel context.CancelFunc, src, dst net.Conn) {
	go func() {
		defer wg.Done()
		defer cancel()

		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if err := src.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			n, err := src.Read(buf)
			if err != nil {
				log.Printf("Failed: %s", err)
				return
			}

			if err = dst.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			if _, err = dst.Write(buf[:n]); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
		}
	}()
}

func startStreamCopy(wg *sync.WaitGroup, cancel context.CancelFunc, dst, src net.Conn, label string) {
	go func() {
		defer wg.Done()
		defer cancel()

		if _, err := io.Copy(dst, src); err != nil {
			log.Printf("%s copy error: %v", label, err)
		}
	}()
}
