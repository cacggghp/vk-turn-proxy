package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/transport/v4/deadline"
	"github.com/pion/transport/v4/packetio"
)

const udpReceiveMTU = 8192

var errUDPPacketListenerClosed = errors.New("udp packet listener closed")

type udpAcceptFilter func([]byte) bool

type udpPacketListener struct {
	pConn        net.PacketConn
	acceptFilter udpAcceptFilter

	accepting atomic.Bool
	acceptCh  chan *udpPacketConn
	doneCh    chan struct{}
	doneOnce  sync.Once

	connLock sync.Mutex
	conns    map[string]*udpPacketConn
	connWG   sync.WaitGroup

	readDoneCh chan struct{}
	readWG     sync.WaitGroup
	errRead    atomic.Value
	errClose   atomic.Value
}

func listenUDPForDTLS(addr *net.UDPAddr) (dtlsnet.PacketListener, error) {
	pConn, err := listenPacketInfoUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return newUDPPacketListener(pConn, isDTLSHandshakePacket), nil
}

func newUDPPacketListener(pConn net.PacketConn, acceptFilter udpAcceptFilter) dtlsnet.PacketListener {
	l := &udpPacketListener{
		pConn:        pConn,
		acceptFilter: acceptFilter,
		acceptCh:     make(chan *udpPacketConn, 128),
		doneCh:       make(chan struct{}),
		conns:        make(map[string]*udpPacketConn),
		readDoneCh:   make(chan struct{}),
	}
	l.accepting.Store(true)
	l.connWG.Add(1)
	l.readWG.Add(2)
	go l.readLoop()
	go func() {
		l.connWG.Wait()
		if err := l.pConn.Close(); err != nil {
			l.errClose.Store(err)
		}
		l.readWG.Done()
	}()
	return l
}

func (l *udpPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	select {
	case c := <-l.acceptCh:
		l.connWG.Add(1)
		return c, c.rAddr, nil
	case <-l.readDoneCh:
		if err, ok := l.errRead.Load().(error); ok {
			return nil, nil, err
		}
		return nil, nil, errUDPPacketListenerClosed
	case <-l.doneCh:
		return nil, nil, errUDPPacketListenerClosed
	}
}

func (l *udpPacketListener) Close() error {
	var err error
	l.doneOnce.Do(func() {
		l.accepting.Store(false)
		close(l.doneCh)

		l.connLock.Lock()
		for {
			select {
			case c := <-l.acceptCh:
				close(c.doneCh)
				delete(l.conns, c.rAddr.String())
			default:
				l.connLock.Unlock()
				l.connWG.Done()
				l.readWG.Wait()
				if errClose, ok := l.errClose.Load().(error); ok {
					err = errClose
				}
				return
			}
		}
	})
	return err
}

func (l *udpPacketListener) Addr() net.Addr {
	return l.pConn.LocalAddr()
}

func (l *udpPacketListener) readLoop() {
	defer l.readWG.Done()
	defer close(l.readDoneCh)

	buf := make([]byte, udpReceiveMTU)
	for {
		n, raddr, err := l.pConn.ReadFrom(buf)
		if err != nil {
			l.errRead.Store(err)
			return
		}
		l.dispatchMsg(raddr, buf[:n])
	}
}

func (l *udpPacketListener) dispatchMsg(raddr net.Addr, buf []byte) {
	conn, ok := l.getConn(raddr, buf)
	if ok {
		if _, err := conn.buffer.Write(buf); err != nil {
			debugf("udp listener buffer write failed: %v", err)
		}
	}
}

func (l *udpPacketListener) getConn(raddr net.Addr, buf []byte) (*udpPacketConn, bool) {
	l.connLock.Lock()
	defer l.connLock.Unlock()

	conn, ok := l.conns[raddr.String()]
	if !ok {
		if !l.accepting.Load() {
			return nil, false
		}
		if l.acceptFilter != nil && !l.acceptFilter(buf) {
			return nil, false
		}
		conn = &udpPacketConn{
			listener:      l,
			rAddr:         raddr,
			buffer:        packetio.NewBuffer(),
			doneCh:        make(chan struct{}),
			writeDeadline: deadline.New(),
		}
		select {
		case l.acceptCh <- conn:
			l.conns[raddr.String()] = conn
		default:
			return nil, false
		}
	}
	return conn, true
}

type udpPacketConn struct {
	listener *udpPacketListener
	rAddr    net.Addr
	buffer   *packetio.Buffer

	doneCh   chan struct{}
	doneOnce sync.Once

	writeDeadline *deadline.Deadline
}

func (c *udpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.buffer.Read(p)
	return n, c.rAddr, err
}

func (c *udpPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.writeDeadline.Done():
		return 0, context.DeadlineExceeded
	default:
	}
	return c.listener.pConn.WriteTo(p, c.rAddr)
}

func (c *udpPacketConn) Close() error {
	var err error
	c.doneOnce.Do(func() {
		c.listener.connWG.Done()
		close(c.doneCh)
		c.listener.connLock.Lock()
		delete(c.listener.conns, c.rAddr.String())
		c.listener.connLock.Unlock()
		if errBuf := c.buffer.Close(); errBuf != nil {
			err = errBuf
		}
	})
	return err
}

func (c *udpPacketConn) LocalAddr() net.Addr {
	return c.listener.pConn.LocalAddr()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return c.SetReadDeadline(t)
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	return c.buffer.SetReadDeadline(t)
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}

func isDTLSHandshakePacket(packet []byte) bool {
	pkts, err := recordlayer.UnpackDatagram(packet)
	if err != nil || len(pkts) == 0 {
		return false
	}
	h := &recordlayer.Header{}
	if err := h.Unmarshal(pkts[0]); err != nil {
		return false
	}
	return h.ContentType == protocol.ContentTypeHandshake
}
