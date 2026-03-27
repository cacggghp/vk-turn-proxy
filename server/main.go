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

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func closeWithLog(closer io.Closer, msg string) {
	if err := closer.Close(); err != nil {
		log.Printf("%s: %v", msg, err)
	}
}

func setDeadlineWithLog(conn interface{ SetDeadline(time.Time) error }, t time.Time, msg string) {
	if err := conn.SetDeadline(t); err != nil {
		log.Printf("%s: %v", msg, err)
	}
}

func setReadDeadlineWithLog(conn interface{ SetReadDeadline(time.Time) error }, t time.Time, msg string) {
	if err := conn.SetReadDeadline(t); err != nil {
		log.Printf("%s: %v", msg, err)
	}
}

func setWriteDeadlineWithLog(conn interface{ SetWriteDeadline(time.Time) error }, t time.Time, msg string) {
	if err := conn.SetWriteDeadline(t); err != nil {
		log.Printf("%s: %v", msg, err)
	}
}

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
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
			defer closeWithLog(conn, "failed to close incoming connection")
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
				setDeadlineWithLog(conn, time.Now(), "failed to set incoming deadline")
				setDeadlineWithLog(serverConn, time.Now(), "failed to set outgoing deadline")
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
					setReadDeadlineWithLog(conn, time.Now().Add(30*time.Minute), "failed to set incoming read deadline")
					n, err1 := conn.Read(buf)
					if err1 != nil {
						log.Printf("Failed: %s", err1)
						return
					}

					setWriteDeadlineWithLog(serverConn, time.Now().Add(30*time.Minute), "failed to set outgoing write deadline")
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
					setReadDeadlineWithLog(serverConn, time.Now().Add(30*time.Minute), "failed to set outgoing read deadline")
					n, err1 := serverConn.Read(buf)
					if err1 != nil {
						log.Printf("Failed: %s", err1)
						return
					}

					setWriteDeadlineWithLog(conn, time.Now().Add(30*time.Minute), "failed to set incoming write deadline")
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
