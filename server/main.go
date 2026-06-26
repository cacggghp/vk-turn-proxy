package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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

	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/xtaci/smux"
)

var isDebug bool

func debugf(format string, v ...any) {
	if isDebug {
		log.Printf(format, v...)
	}
}

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	vlessMode := flag.Bool("vless", false, "VLESS mode: forward TCP connections (for VLESS) instead of UDP packets")
	vlessBond := flag.Bool("vless-bond", false, "bond one VLESS TCP connection across all active smux sessions")
	wrapMode := flag.Bool("wrap", false, "WRAP mode: SRTP-like AEAD obfuscation for DTLS packets before they reach TURN ChannelData")
	wrapKeyHex := flag.String("wrap-key", "", "32-byte hex-encoded shared key for -wrap (64 hex chars)")
	genWrapKey := flag.Bool("gen-wrap-key", false, "print a fresh 64-character hex key for -wrap-key and exit")
	debugFlag := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()
	isDebug = *debugFlag

	if *genWrapKey {
		key := make([]byte, wrapKeyLen)
		if _, err := rand.Read(key); err != nil {
			log.Panicf("gen-wrap-key: rand.Read: %v", err)
		}
		fmt.Println(hex.EncodeToString(key))
		return
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
		panic(err)
	}
	if len(*connect) == 0 {
		log.Panicf("server address is required")
	}
	var wrapKey []byte
	if *wrapMode {
		if *wrapKeyHex == "" {
			log.Panicf("-wrap requires -wrap-key")
		}
		wrapKey, err = hex.DecodeString(*wrapKeyHex)
		if err != nil {
			log.Panicf("-wrap-key invalid hex: %v", err)
		}
		if len(wrapKey) != wrapKeyLen {
			log.Panicf("-wrap-key must decode to %d bytes (got %d)", wrapKeyLen, len(wrapKey))
		}
	}
	log.Printf("Starting server listen=%s connect=%s vless=%t vless-bond=%t wrap=%t bond-autodetect=true", *listen, *connect, *vlessMode, *vlessBond, *wrapMode)
	// Generate a certificate and private key to secure the connection
	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	dtlsOpts := []dtls.ServerOption{
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	}
	var listener net.Listener
	if *wrapMode {
		log.Printf("WRAP mode enabled: listener only accepts clients with matching -wrap-key")
		wrapListener, werr := listenWrapped(addr, wrapKey)
		if werr != nil {
			panic(werr)
		}
		listener, err = dtls.NewListenerWithOptions(wrapListener, dtlsOpts...)
	} else {
		udpListener, lerr := listenUDPForDTLS(addr)
		if lerr != nil {
			panic(lerr)
		}
		listener, err = dtls.NewListenerWithOptions(udpListener, dtlsOpts...)
	}
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
			debugf("Connection from %s\n", conn.RemoteAddr())

			// Perform the handshake with a 30-second timeout
			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			defer cancel1()

			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error: expected *dtls.Conn")
				return
			}
			debugf("Start handshake")
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Printf("Handshake failed: %v", err)
				return
			}
			debugf("Handshake done")

			if *vlessMode {
				handleVLESSConnection(ctx, dtlsConn, *connect, *vlessBond)
			} else {
				handleUDPConnection(ctx, conn, *connect)
			}

			debugf("Connection closed: %s\n", conn.RemoteAddr())
		}(conn)
	}
}

type throughputStats struct {
	tx atomic.Uint64
	rx atomic.Uint64
}

func (s *throughputStats) addTx(n int) {
	if n > 0 {
		s.tx.Add(uint64(n))
	}
}

func (s *throughputStats) addRx(n int) {
	if n > 0 {
		s.rx.Add(uint64(n))
	}
}

func (s *throughputStats) logEvery(ctx context.Context, label, txName, rxName string) {
	if !isDebug {
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var prevTx, prevRx uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tx := s.tx.Load()
			rx := s.rx.Load()
			deltaTx := tx - prevTx
			deltaRx := rx - prevRx
			prevTx = tx
			prevRx = rx

			if deltaTx == 0 && deltaRx == 0 {
				continue
			}

			debugf(
				"%s throughput: %s=%s %s=%s total_%s=%s total_%s=%s",
				label,
				txName,
				formatBitsPerSecond(deltaTx, 5*time.Second),
				rxName,
				formatBitsPerSecond(deltaRx, 5*time.Second),
				txName,
				formatByteCount(tx),
				rxName,
				formatByteCount(rx),
			)
		}
	}
}

func formatBitsPerSecond(bytes uint64, interval time.Duration) string {
	if interval <= 0 {
		interval = time.Second
	}

	bps := float64(bytes*8) / interval.Seconds()
	if bps >= 1_000_000 {
		return fmt.Sprintf("%.2f Mbit/s", bps/1_000_000)
	}
	if bps >= 1_000 {
		return fmt.Sprintf("%.1f kbit/s", bps/1_000)
	}
	return fmt.Sprintf("%.0f bit/s", bps)
}

func formatByteCount(bytes uint64) string {
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.2f MiB", float64(bytes)/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%.1f KiB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%d B", bytes)
}

type countingConn struct {
	net.Conn
	stats *throughputStats
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.stats.addRx(n)
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.stats.addTx(n)
	return n, err
}

const (
	bondVersion = 1
	bondMagic   = "VLB1"

	bondFrameData byte = 1
	bondFrameFIN  byte = 2

	bondMaxChunk = 16 * 1024

	bondLaneAttachTimeout = 300 * time.Millisecond
)

type bondHello struct {
	connID    uint64
	laneIndex uint16
	laneCount uint16
}

type bondFrame struct {
	typ  byte
	seq  uint64
	data []byte
}

func readBondHelloAfterMagic(r io.Reader, magic [4]byte) (bondHello, error) {
	var hdr [17]byte
	copy(hdr[0:4], magic[:])
	if _, err := io.ReadFull(r, hdr[4:]); err != nil {
		return bondHello{}, err
	}
	return parseBondHelloHeader(hdr[:])
}

func parseBondHelloHeader(hdr []byte) (bondHello, error) {
	if len(hdr) != 17 {
		return bondHello{}, fmt.Errorf("bad bond hello size: %d", len(hdr))
	}
	if string(hdr[0:4]) != bondMagic {
		return bondHello{}, fmt.Errorf("bad bond magic")
	}
	if hdr[4] != bondVersion {
		return bondHello{}, fmt.Errorf("unsupported bond version: %d", hdr[4])
	}
	return bondHello{
		connID:    binary.BigEndian.Uint64(hdr[5:13]),
		laneIndex: binary.BigEndian.Uint16(hdr[13:15]),
		laneCount: binary.BigEndian.Uint16(hdr[15:17]),
	}, nil
}

func writeBondFrame(w io.Writer, typ byte, seq uint64, data []byte) error {
	var hdr [13]byte
	hdr[0] = typ
	binary.BigEndian.PutUint64(hdr[1:9], seq)
	binary.BigEndian.PutUint32(hdr[9:13], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	_, err := w.Write(data)
	return err
}

func readBondFrame(r io.Reader) (bondFrame, error) {
	var hdr [13]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return bondFrame{}, err
	}
	size := binary.BigEndian.Uint32(hdr[9:13])
	if size > 4*1024*1024 {
		return bondFrame{}, fmt.Errorf("bond frame too large: %d", size)
	}
	f := bondFrame{
		typ: hdr[0],
		seq: binary.BigEndian.Uint64(hdr[1:9]),
	}
	if size > 0 {
		f.data = make([]byte, size)
		if _, err := io.ReadFull(r, f.data); err != nil {
			return bondFrame{}, err
		}
	}
	return f, nil
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		if err := cw.CloseWrite(); err != nil {
			debugf("CloseWrite failed: %v", err)
		}
	}
}

type bondServerLane struct {
	index  uint16
	stream *smux.Stream
	mu     sync.Mutex
}

type bondServerConn struct {
	id          uint64
	connectAddr string
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}

	lanesMu sync.RWMutex
	lanes   []*bondServerLane
	want    uint16
	ready   chan struct{}

	recvCh chan bondFrame
	once   sync.Once
}

type bondRegistry struct {
	mu    sync.Mutex
	conns map[uint64]*bondServerConn
}

var globalBondRegistry = &bondRegistry{conns: make(map[uint64]*bondServerConn)}

func (r *bondRegistry) get(ctx context.Context, id uint64, connectAddr string) *bondServerConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.conns[id]; c != nil {
		return c
	}
	connCtx, cancel := context.WithCancel(ctx)
	c := &bondServerConn{
		id:          id,
		connectAddr: connectAddr,
		ctx:         connCtx,
		cancel:      cancel,
		done:        make(chan struct{}),
		ready:       make(chan struct{}, 1),
		recvCh:      make(chan bondFrame, 1024),
	}
	r.conns[id] = c
	go func() {
		<-c.done
		r.mu.Lock()
		if r.conns[id] == c {
			delete(r.conns, id)
		}
		r.mu.Unlock()
	}()
	return c
}

func (c *bondServerConn) addLane(l *bondServerLane, laneCount uint16) {
	c.lanesMu.Lock()
	if laneCount > c.want {
		c.want = laneCount
	}
	c.lanes = append(c.lanes, l)
	count := len(c.lanes)
	c.lanesMu.Unlock()
	debugf("[bond %d] lane %d attached (lanes=%d)", c.id, l.index, count)
	select {
	case c.ready <- struct{}{}:
	default:
	}

	go c.readLane(l)
	c.once.Do(func() {
		go c.run()
	})
}

func (c *bondServerConn) snapshotLanes() []*bondServerLane {
	c.lanesMu.RLock()
	defer c.lanesMu.RUnlock()
	out := make([]*bondServerLane, len(c.lanes))
	copy(out, c.lanes)
	return out
}

func (c *bondServerConn) removeLane(l *bondServerLane) int {
	c.lanesMu.Lock()
	defer c.lanesMu.Unlock()
	for i, lane := range c.lanes {
		if lane == l {
			c.lanes = append(c.lanes[:i], c.lanes[i+1:]...)
			break
		}
	}
	return len(c.lanes)
}

func (c *bondServerConn) waitForInitialLanes() {
	timer := time.NewTimer(bondLaneAttachTimeout)
	defer timer.Stop()
	for {
		c.lanesMu.RLock()
		count := len(c.lanes)
		want := int(c.want)
		c.lanesMu.RUnlock()
		if want <= 0 || count >= want {
			return
		}
		select {
		case <-c.ctx.Done():
			return
		case <-c.ready:
		case <-timer.C:
			debugf("[bond %d] starting with %d/%d lanes after attach timeout", c.id, count, want)
			return
		}
	}
}

func (c *bondServerConn) readLane(l *bondServerLane) {
	for {
		f, err := readBondFrame(l.stream)
		if err != nil {
			left := c.removeLane(l)
			select {
			case <-c.ctx.Done():
			default:
				if err != io.EOF {
					debugf("[bond %d] lane %d read error: %v (lanes=%d)", c.id, l.index, err, left)
				}
				if left == 0 {
					c.cancel()
				}
			}
			return
		}
		select {
		case c.recvCh <- f:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *bondServerConn) run() {
	defer close(c.done)
	defer c.cancel()

	c.waitForInitialLanes()

	backendConn, err := net.DialTimeout("tcp", c.connectAddr, 10*time.Second)
	if err != nil {
		log.Printf("[bond %d] backend dial error: %s", c.id, err)
		return
	}
	defer func() {
		if err := backendConn.Close(); err != nil {
			log.Printf("[bond %d] failed to close backend connection: %v", c.id, err)
		}
	}()
	context.AfterFunc(c.ctx, func() {
		now := time.Now()
		if err := backendConn.SetDeadline(now); err != nil {
			log.Printf("[bond %d] backend deadline error: %v", c.id, err)
		}
		for _, lane := range c.snapshotLanes() {
			if err := lane.stream.SetDeadline(now); err != nil {
				log.Printf("[bond %d] lane %d deadline error: %v", c.id, lane.index, err)
			}
		}
	})
	debugf("[bond %d] backend connected", c.id)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.copyBondToBackend(backendConn)
	}()
	go func() {
		defer wg.Done()
		defer c.cancel()
		c.copyBackendToBond(backendConn)
	}()
	wg.Wait()
}

func (c *bondServerConn) copyBondToBackend(backendConn net.Conn) {
	pending := make(map[uint64][]byte)
	var expect uint64
	var finSeq *uint64

	for {
		if finSeq != nil && expect == *finSeq {
			closeWrite(backendConn)
			debugf("[bond %d] upload to backend finished chunks=%d", c.id, expect)
			return
		}

		select {
		case <-c.ctx.Done():
			return
		case f := <-c.recvCh:
			switch f.typ {
			case bondFrameData:
				pending[f.seq] = f.data
			case bondFrameFIN:
				v := f.seq
				if finSeq == nil || v < *finSeq {
					finSeq = &v
				}
			default:
				log.Printf("[bond %d] unknown frame type %d", c.id, f.typ)
				return
			}

			for {
				data, ok := pending[expect]
				if !ok {
					break
				}
				delete(pending, expect)
				if len(data) > 0 {
					if _, err := backendConn.Write(data); err != nil {
						log.Printf("[bond %d] backend write error: %v", c.id, err)
						return
					}
				}
				expect++
			}
		}
	}
}

func (c *bondServerConn) copyBackendToBond(backendConn net.Conn) {
	buf := make([]byte, bondMaxChunk)
	var seq uint64
	var laneIdx uint64
	for {
		n, err := backendConn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			if writeErr := c.writeToNextLane(bondFrameData, seq, data, &laneIdx); writeErr != nil {
				log.Printf("[bond %d] lane write data error: %v", c.id, writeErr)
				return
			}
			seq++
		}
		if err != nil {
			lanes := c.snapshotLanes()
			for _, lane := range lanes {
				lane.mu.Lock()
				writeErr := writeBondFrame(lane.stream, bondFrameFIN, seq, nil)
				lane.mu.Unlock()
				if writeErr != nil && c.ctx.Err() == nil {
					log.Printf("[bond %d] lane %d write FIN error: %v", c.id, lane.index, writeErr)
				}
			}
			debugf("[bond %d] download from backend finished chunks=%d", c.id, seq)
			return
		}
		select {
		case <-c.ctx.Done():
			return
		default:
		}
	}
}

func (c *bondServerConn) writeToNextLane(typ byte, seq uint64, data []byte, laneIdx *uint64) error {
	for {
		lanes := c.snapshotLanes()
		for attempts := 0; attempts < len(lanes); attempts++ {
			lane := lanes[*laneIdx%uint64(len(lanes))]
			(*laneIdx)++
			lane.mu.Lock()
			err := writeBondFrame(lane.stream, typ, seq, data)
			lane.mu.Unlock()
			if err == nil {
				return nil
			}
			left := c.removeLane(lane)
			log.Printf("[bond %d] lane %d write error: %v (lanes=%d)", c.id, lane.index, err, left)
			if left == 0 {
				return err
			}
		}
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func handleBondServerStreamAfterMagic(ctx context.Context, stream *smux.Stream, connectAddr string, magic [4]byte) {
	handleBondServerStreamWithHello(ctx, stream, connectAddr, func(r io.Reader) (bondHello, error) {
		return readBondHelloAfterMagic(r, magic)
	})
}

func handleBondServerStreamWithHello(ctx context.Context, stream *smux.Stream, connectAddr string, readHello func(io.Reader) (bondHello, error)) {
	defer func() {
		if err := stream.Close(); err != nil && err != smux.ErrGoAway {
			log.Printf("failed to close bond smux stream: %v", err)
		}
	}()

	hello, err := readHello(stream)
	if err != nil {
		log.Printf("bond hello error: %v", err)
		return
	}

	conn := globalBondRegistry.get(ctx, hello.connID, connectAddr)
	conn.addLane(&bondServerLane{
		index:  hello.laneIndex,
		stream: stream,
	}, hello.laneCount)

	select {
	case <-ctx.Done():
	case <-conn.done:
	}
}

type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
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
	stats := &throughputStats{}
	go stats.logEvery(
		ctx2,
		fmt.Sprintf("[DTLS %s]", conn.RemoteAddr()),
		"dtls-to-backend",
		"backend-to-dtls",
	)

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
			written, err1 := serverConn.Write(buf[:n])
			stats.addTx(written)
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
			written, err1 := conn.Write(buf[:n])
			stats.addRx(written)
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
func handleVLESSConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string, bond bool) {
	// 1. Create KCP session over DTLS
	statsCtx, statsCancel := context.WithCancel(ctx)
	defer statsCancel()
	stats := &throughputStats{}
	go stats.logEvery(
		statsCtx,
		fmt.Sprintf("[VLESS %s]", dtlsConn.RemoteAddr()),
		"to-client",
		"from-client",
	)

	kcpSess, err := tcputil.NewKCPOverDTLS(&countingConn{Conn: dtlsConn, stats: stats}, true)
	if err != nil {
		log.Printf("KCP session error: %s", err)
		return
	}
	defer func() {
		if closeErr := kcpSess.Close(); closeErr != nil {
			log.Printf("failed to close KCP session: %v", closeErr)
		}
	}()
	debugf("KCP session established (server)")

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
	debugf("smux session established (server)")

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

			var prefix [4]byte
			if _, err := io.ReadFull(s, prefix[:]); err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					log.Printf("smux stream prefix read error: %v", err)
				}
				_ = s.Close()
				return
			}
			if string(prefix[:]) == bondMagic {
				debugf("auto-detected bond smux stream")
				handleBondServerStreamAfterMagic(ctx, s, connectAddr, prefix)
				return
			}
			if bond {
				log.Printf("non-bond smux stream accepted while -vless-bond is enabled")
			}

			defer func() {
				if err := s.Close(); err != nil && err != smux.ErrGoAway {
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
			pipeConn(ctx, &prefixedConn{Conn: s, prefix: prefix[:]}, backendConn)
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
			debugf("pipeConn: failed to set deadline c1: %v", err)
		}
		if err := c2.SetDeadline(time.Now()); err != nil {
			debugf("pipeConn: failed to set deadline c2: %v", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c1, c2); err != nil {
			debugf("pipeConn: c1<-c2 copy error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c2, c1); err != nil {
			debugf("pipeConn: c2<-c1 copy error: %v", err)
		}
	}()

	wg.Wait()

	// Reset deadlines (best-effort; connection may already be closed)
	if err := c1.SetDeadline(time.Time{}); err != nil {
		debugf("pipeConn: failed to reset deadline c1: %v", err)
	}
	if err := c2.SetDeadline(time.Time{}); err != nil {
		debugf("pipeConn: failed to reset deadline c2: %v", err)
	}
}
