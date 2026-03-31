package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: vk-turn-proxy-server [options]\n\n")
		fmt.Fprintf(os.Stderr, "VK TURN Proxy server — accepts obfuscated DTLS connections and forwards\n")
		fmt.Fprintf(os.Stderr, "them to a local WireGuard/UDP endpoint.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  vk-turn-proxy-server -listen 0.0.0.0:56000 -connect 127.0.0.1:51820\n")
	}

	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port (required)")
	flag.Parse()

	if *connect == "" {
		fmt.Fprintf(os.Stderr, "error: -connect is required\n\n")
		flag.Usage()
		os.Exit(1)
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

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("failed to resolve listen address %q: %v", *listen, err)
	}
	// Generate a certificate and private key to secure the connection
	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		log.Fatalf("failed to generate self-signed certificate: %v", genErr)
	}

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	// Connect to a DTLS server
	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		log.Fatalf("failed to start DTLS listener on %s: %v", addr, err)
	}
	context.AfterFunc(ctx, func() {
		if err = listener.Close(); err != nil {
			log.Printf("failed to close DTLS listener: %v", err)
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
			var err error = nil
			log.Printf("Connection from %s\n", conn.RemoteAddr())
			// `conn` is of type `net.Conn` but may be casted to `dtls.Conn`
			// using `dtlsConn := conn.(*dtls.Conn)` in order to to expose
			// functions like `ConnectionState` etc.

			// Perform the handshake with a 30-second timeout
			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error")
				cancel1()
				return
			}
			log.Println("Start handshake")
			if err = dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Println(err)
				cancel1()
				return
			}
			cancel1()
			log.Println("Handshake done")

			serverConn, err := net.Dial("udp", *connect)
			if err != nil {
				log.Println(err)
				return
			}
			defer func() {
				if err = serverConn.Close(); err != nil {
					log.Printf("failed to close outgoing connection: %s", err)
					return
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

					if err1 := serverConn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
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

					if err1 := conn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
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
			log.Printf("Connection closed: %s\n", conn.RemoteAddr())
		}(conn)
	}
}
