package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/xtaci/smux"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	vlessMode := flag.Bool("vless", false, "VLESS mode: forward TCP connections (for VLESS) instead of UDP packets")
	flag.Parse()

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

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}
	if len(*connect) == 0 {
		log.Panicf("server address is required")
	}
	// Generate a certificate and private key to secure the connection
	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(err)
	}

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	// Listen for DTLS connections
	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		if err = listener.Close(); err != nil {
			panic(err)
		}
	})

	fmt.Println("Listening")

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
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					log.Printf("failed to close incoming connection: %s", closeErr)
				}
			}()
			log.Printf("Connection from %s\n", conn.RemoteAddr())

			// Perform the handshake with a 30-second timeout
			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error")
				cancel1()
				return
			}
			log.Println("Start handshake")
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Println(err)
				cancel1()
				return
			}
			cancel1()
			log.Println("Handshake done")

			if *vlessMode {
				handleVLESSConnection(ctx, dtlsConn, *connect)
			} else {
				handleUDPConnection(ctx, conn, *connect)
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
	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err1 := conn.SetReadDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			n, err1 := conn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			if err1 = serverConn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			_, err1 = serverConn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err1 := serverConn.SetReadDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			n, err1 := serverConn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			if err1 = conn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			_, err1 = conn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	wg.Wait()
}

// handleVLESSConnection creates a KCP+smux session over DTLS and forwards
// each smux stream as a TCP connection to the backend (Xray/VLESS).
func handleVLESSConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string) {
	// 1. Create KCP session over DTLS
	kcpSess, err := tcputil.NewKCPOverDTLS(dtlsConn, true)
	if err != nil {
		log.Printf("KCP session error: %s", err)
		return
	}
	defer kcpSess.Close()
	log.Printf("KCP session established (server)")

	// 2. Create smux server session over KCP
	smuxSess, err := smux.Server(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		log.Printf("smux server error: %s", err)
		return
	}
	defer smuxSess.Close()
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
			defer s.Close()

			// Connect to backend (Xray/VLESS)
			backendConn, err := net.DialTimeout("tcp", connectAddr, 10*time.Second)
			if err != nil {
				log.Printf("backend dial error: %s", err)
				return
			}
			defer backendConn.Close()

			// Bidirectional copy
			pipeConn(ctx, s, backendConn)
		}(stream)
	}
	wg.Wait()
}

// pipeConn copies data bidirectionally between two connections.
func pipeConn(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
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
	go func() {
		defer wg.Done()
		defer cancel()
		if _, err := io.Copy(c1, c2); err != nil {
			log.Printf("pipeConn: c1<-c2 copy error: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		if _, err := io.Copy(c2, c1); err != nil {
			log.Printf("pipeConn: c2<-c1 copy error: %v", err)
		}
	}()
	wg.Wait()
	if err := c1.SetDeadline(time.Time{}); err != nil {
		log.Printf("pipeConn: failed to reset deadline c1: %v", err)
	}
	if err := c2.SetDeadline(time.Time{}); err != nil {
		log.Printf("pipeConn: failed to reset deadline c2: %v", err)
	}
}
