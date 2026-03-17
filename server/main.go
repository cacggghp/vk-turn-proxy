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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

type UserSession struct {
	ID          string
	Conns       []net.Conn
	BackendConn net.Conn
	LastUsed    uint32
	Lock        sync.RWMutex
	Ctx         context.Context
	Cancel      context.CancelFunc
	Manager     *SessionManager
}

type SessionManager struct {
	Sessions map[string]*UserSession
	Lock     sync.RWMutex
}

func (s *SessionManager) GetOrCreate(ctx context.Context, id string, connectAddr string) (*UserSession, error) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if session, ok := s.Sessions[id]; ok {
		return session, nil
	}

	backendConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		return nil, err
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	session := &UserSession{
		ID:          id,
		BackendConn: backendConn,
		Manager:     s,
		Ctx:         sessionCtx,
		Cancel:      cancel,
	}

	s.Sessions[id] = session
	go session.backendReaderLoop()

	return session, nil
}

func (s *UserSession) backendReaderLoop() {
	defer s.Cleanup()
	buf := make([]byte, 1600)
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
		}

		s.BackendConn.SetReadDeadline(time.Now().Add(time.Minute * 5))
		n, err := s.BackendConn.Read(buf)
		if err != nil {
			log.Printf("Session %s backend read error: %v", s.ID, err)
			return
		}

		s.Lock.RLock()
		if len(s.Conns) == 0 {
			s.Lock.RUnlock()
			continue
		}
		// Round-robin selection of DTLS connection
		idx := atomic.AddUint32(&s.LastUsed, 1) % uint32(len(s.Conns))
		conn := s.Conns[idx]
		s.Lock.RUnlock()

		conn.SetWriteDeadline(time.Now().Add(time.Second * 10))
		_, err = conn.Write(buf[:n])
		if err != nil {
			log.Printf("Session %s DTLS write error: %v", s.ID, err)
			// Connection will be removed by its own reader loop
		}
	}
}

func (s *UserSession) AddConn(conn net.Conn) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	s.Conns = append(s.Conns, conn)
}

func (s *UserSession) RemoveConn(conn net.Conn) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	for i, c := range s.Conns {
		if c == conn {
			s.Conns = append(s.Conns[:i], s.Conns[i+1:]...)
			break
		}
	}
	// If all connections are gone, we might want to start a timer to cleanup the session
	// but for now we'll keep it alive until backendReaderLoop fails or context is cancelled.
}

func (s *UserSession) Cleanup() {
	s.Cancel()
	s.BackendConn.Close()

	s.Manager.Lock.Lock()
	delete(s.Manager.Sessions, s.ID)
	s.Manager.Lock.Unlock()

	s.Lock.Lock()
	for _, c := range s.Conns {
		c.Close()
	}
	s.Conns = nil
	s.Lock.Unlock()
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

	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		listener.Close()
	})

	manager := &SessionManager{
		Sessions: make(map[string]*UserSession),
	}

	log.Printf("Listening on %s, forwarding to %s", *listen, *connect)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Println("Accept error:", err)
				continue
			}
		}

		go func(conn net.Conn) {
			defer conn.Close()

			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				return
			}

			handshakeCtx, hCancel := context.WithTimeout(ctx, 30*time.Second)
			defer hCancel()

			if err := dtlsConn.HandshakeContext(handshakeCtx); err != nil {
				log.Println("Handshake failed:", err)
				return
			}

			// Phase 1: Read Session ID (16 bytes)
			idBuf := make([]byte, 16)
			conn.SetReadDeadline(time.Now().Add(time.Second * 5))
			_, err := io.ReadFull(conn, idBuf)
			if err != nil {
				log.Println("Failed to read session ID:", err)
				return
			}
			sessionID := fmt.Sprintf("%x", idBuf)

			session, err := manager.GetOrCreate(ctx, sessionID, *connect)
			if err != nil {
				log.Println("Failed to get/create session:", err)
				return
			}

			session.AddConn(conn)
			defer session.RemoveConn(conn)

			log.Printf("New stream for session %s from %s", sessionID, conn.RemoteAddr())

			// Upstream Loop: DTLS -> Backend
			buf := make([]byte, 1600)
			for {
				conn.SetReadDeadline(time.Now().Add(time.Minute * 10))
				n, err := conn.Read(buf)
				if err != nil {
					log.Printf("Stream %s closed: %v", sessionID, err)
					return
				}

				session.BackendConn.SetWriteDeadline(time.Now().Add(time.Second * 5))
				_, err = session.BackendConn.Write(buf[:n])
				if err != nil {
					log.Printf("Session %s backend write error: %v", sessionID, err)
					return
				}
			}
		}(conn)
	}
}
