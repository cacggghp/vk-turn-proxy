// DNS-over-HTTPS resolver for mobile networks where UDP/53 is blocked or
// spoofed.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	// Embedded Mozilla CA roots for CGO_ENABLED=0 builds (Android).
	_ "golang.org/x/crypto/x509roots/fallback"
)

const (
	dohQueryTimeout     = 6 * time.Second
	dohCacheMinTTL      = 10 * time.Second
	dohCacheMaxTTL      = 1 * time.Hour
	dohMaxResponseBytes = 64 * 1024
	dohContentType      = "application/dns-message"

	dohDialerTimeout   = 5 * time.Second
	dohDialerKeepAlive = 30 * time.Second
	appDialerTimeout   = 20 * time.Second
	appDialerKeepAlive = 30 * time.Second

	forwarderUDPBufSize = 4096
	forwarderTCPReadDL  = 30 * time.Second
	forwarderTCPWriteDL = 10 * time.Second
	autoUDPBudget       = 1500 * time.Millisecond
)

// DohEndpoint describes a single DNS-over-HTTPS server together with the IPs
// we bootstrap to — so that resolving the endpoint hostname does not itself
// require DNS.
type DohEndpoint struct {
	URL          string
	Hostname     string
	BootstrapIPs []string
}

// Yandex is tried first because it tends to stay reachable on RU mobile
// operators even when international resolvers get blocked; Google and
// Cloudflare follow as fallbacks.
var defaultDohEndpoints = []DohEndpoint{
	{"https://common.dot.dns.yandex.net/dns-query", "common.dot.dns.yandex.net", []string{"77.88.8.8", "77.88.8.1"}},
	{"https://secure.dot.dns.yandex.net/dns-query", "secure.dot.dns.yandex.net", []string{"77.88.8.88", "77.88.8.2"}},
	{"https://family.dot.dns.yandex.net/dns-query", "family.dot.dns.yandex.net", []string{"77.88.8.7", "77.88.8.3"}},
	{"https://dns.google/dns-query", "dns.google", []string{"8.8.8.8", "8.8.4.4"}},
	{"https://cloudflare-dns.com/dns-query", "cloudflare-dns.com", []string{"1.1.1.1", "1.0.0.1"}},
}

// DohResolver resolves hostnames to IPs via DNS-over-HTTPS (RFC 8484).
type DohResolver struct {
	endpoints []DohEndpoint
	client    *http.Client
	cache     *dohCache
}

// NewDohResolver constructs a resolver using defaultDohEndpoints if endpoints
// is nil. Endpoint hostnames are dialed by IP using BootstrapIPs, so the DoH
// transport never depends on the system resolver.
func NewDohResolver(endpoints []DohEndpoint) *DohResolver {
	if len(endpoints) == 0 {
		endpoints = defaultDohEndpoints
	}
	return &DohResolver{
		endpoints: endpoints,
		client:    &http.Client{Timeout: dohQueryTimeout, Transport: newBootstrapTransport(endpoints)},
		cache:     newDohCache(),
	}
}

// newDohResolverWithClient is a test hook that skips the bootstrap transport.
func newDohResolverWithClient(endpoints []DohEndpoint, client *http.Client) *DohResolver {
	return &DohResolver{endpoints: endpoints, client: client, cache: newDohCache()}
}

// newBootstrapTransport returns an http.Transport whose DialContext only
// knows how to reach the configured DoH endpoint hostnames, by mapping each
// to its BootstrapIPs.
func newBootstrapTransport(endpoints []DohEndpoint) *http.Transport {
	bootstrap := make(map[string][]string, len(endpoints))
	for _, ep := range endpoints {
		bootstrap[ep.Hostname] = ep.BootstrapIPs
	}
	dialer := &net.Dialer{Timeout: dohDialerTimeout, KeepAlive: dohDialerKeepAlive}

	return &http.Transport{
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, ok := bootstrap[host]
			if !ok {
				return nil, fmt.Errorf("doh: no bootstrap IPs for %q", host)
			}
			var lastErr error
			for _, ip := range ips {
				conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if derr == nil {
					return conn, nil
				}
				lastErr = derr
			}
			return nil, lastErr
		},
	}
}

// LookupIPAddr resolves host to a combined list of A+AAAA IPs (IPv4 first).
// Cached results bypass the network entirely.
func (r *DohResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if ips, ok := r.cache.get(host); ok {
		return ips, nil
	}

	type res struct {
		ips []net.IP
		ttl time.Duration
		err error
	}
	results := make(chan res, 2)
	for _, qt := range [...]uint16{dns.TypeA, dns.TypeAAAA} {
		go func(qtype uint16) {
			ips, ttl, err := r.queryIPs(ctx, host, qtype)
			results <- res{ips, ttl, err}
		}(qt)
	}

	var (
		all     []net.IP
		lastErr error
		minTTL  = dohCacheMaxTTL
	)
	for range 2 {
		rr := <-results
		if rr.err != nil {
			lastErr = rr.err
			continue
		}
		all = append(all, rr.ips...)
		if rr.ttl > 0 && rr.ttl < minTTL {
			minTTL = rr.ttl
		}
	}
	if len(all) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("doh: no records for %s", host)
		}
		return nil, lastErr
	}

	// IPv4 before IPv6 — better compat with mobile IPv4-only CGNAT.
	sort.SliceStable(all, func(i, j int) bool {
		return (all[i].To4() != nil) && (all[j].To4() == nil)
	})

	if minTTL < dohCacheMinTTL {
		minTTL = dohCacheMinTTL
	}
	r.cache.set(host, all, minTTL)
	return all, nil
}

// queryIPs issues one DoH query for qtype, walking endpoints until one
// succeeds, and parses the wire reply into IPs + min TTL.
func (r *DohResolver) queryIPs(ctx context.Context, host string, qtype uint16) ([]net.IP, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.Id = 0 // RFC 8484 §4.1 — zero ID is cache-friendly on shared caches.
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("doh: pack query: %w", err)
	}

	body, ep, err := r.forwardRaw(ctx, wire)
	if err != nil {
		return nil, 0, err
	}
	ips, ttl, err := parseAnswer(body)
	if err != nil {
		return nil, 0, fmt.Errorf("doh: parse %s: %w", ep.Hostname, err)
	}
	log.Printf("[DoH] %s %s via %s → %d IPs (ttl %s)", host, dns.TypeToString[qtype], ep.Hostname, len(ips), ttl)
	return ips, ttl, nil
}

// parseAnswer decodes a DNS wire reply into A/AAAA records and the minimum TTL.
func parseAnswer(body []byte) ([]net.IP, time.Duration, error) {
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("unpack: %w", err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("rcode %s", dns.RcodeToString[reply.Rcode])
	}
	var (
		ips    []net.IP
		minTTL uint32
	)
	updateTTL := func(ttl uint32) {
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	for _, ans := range reply.Answer {
		switch a := ans.(type) {
		case *dns.A:
			ips = append(ips, a.A)
			updateTTL(a.Hdr.Ttl)
		case *dns.AAAA:
			ips = append(ips, a.AAAA)
			updateTTL(a.Hdr.Ttl)
		}
	}
	return ips, time.Duration(minTTL) * time.Second, nil
}

// forwardRaw POSTs an opaque DNS-wire query to the configured DoH endpoints
// in order and returns the first successful raw response together with the
// endpoint that produced it. No parsing — useful for the local forwarder
// which needs to pass through whatever the upstream resolver answers
// (RESINFO/HTTPS/SVCB/EDNS options/…).
func (r *DohResolver) forwardRaw(ctx context.Context, query []byte) ([]byte, DohEndpoint, error) {
	if len(r.endpoints) == 0 {
		return nil, DohEndpoint{}, errors.New("doh: no endpoints configured")
	}
	var lastErr error
	for _, ep := range r.endpoints {
		body, err := r.postWire(ctx, ep, query)
		if err != nil {
			log.Printf("[DoH] %s: %v", ep.Hostname, err)
			lastErr = err
			continue
		}
		return body, ep, nil
	}
	return nil, DohEndpoint{}, lastErr
}

// postWire performs a single application/dns-message POST to one endpoint.
func (r *DohResolver) postWire(ctx context.Context, ep DohEndpoint, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", ep.URL, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

type dohCacheEntry struct {
	ips    []net.IP
	expiry time.Time
}

type dohCache struct {
	mu sync.RWMutex
	m  map[string]dohCacheEntry
}

func newDohCache() *dohCache {
	return &dohCache{m: make(map[string]dohCacheEntry)}
}

func (c *dohCache) get(host string) ([]net.IP, bool) {
	c.mu.RLock()
	e, ok := c.m[host]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	out := make([]net.IP, len(e.ips))
	copy(out, e.ips)
	return out, true
}

func (c *dohCache) set(host string, ips []net.IP, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	if ttl > dohCacheMaxTTL {
		ttl = dohCacheMaxTTL
	}
	cp := make([]net.IP, len(ips))
	copy(cp, ips)
	c.mu.Lock()
	c.m[host] = dohCacheEntry{ips: cp, expiry: time.Now().Add(ttl)}
	c.mu.Unlock()
}

// Go's net.Resolver dials this stub like a regular nameserver, which avoids
// the many edge cases of a fake-net.Conn approach (RESINFO probes, EDNS
// handshakes, truncation, …). Whatever it reads on UDP/TCP is sent verbatim
// to a DoH endpoint and the wire response is sent back to the client.

type dohForwarder struct {
	udpAddr string
	tcpAddr string
}

var (
	dohForwarderOnce sync.Once
	dohForwarderInst *dohForwarder
	dohForwarderErr  error
)

// sharedDohForwarder lazily starts a process-wide forwarder bound to the
// supplied resolver. The first caller wins; subsequent callers reuse the
// same forwarder regardless of what they pass in.
func sharedDohForwarder(r *DohResolver) (*dohForwarder, error) {
	dohForwarderOnce.Do(func() {
		dohForwarderInst, dohForwarderErr = startDohForwarder(r)
	})
	return dohForwarderInst, dohForwarderErr
}

func startDohForwarder(r *DohResolver) (_ *dohForwarder, err error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("doh forwarder: listen UDP: %w", err)
	}
	defer func() {
		if err != nil {
			_ = udpConn.Close()
		}
	}()
	tcpLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("doh forwarder: listen TCP: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tcpLn.Close()
		}
	}()

	fwd := &dohForwarder{
		udpAddr: udpConn.LocalAddr().String(),
		tcpAddr: tcpLn.Addr().String(),
	}
	log.Printf("[DoH] forwarder listening udp=%s tcp=%s", fwd.udpAddr, fwd.tcpAddr)

	go fwd.serveUDP(udpConn, r)
	go fwd.serveTCP(tcpLn, r)
	return fwd, nil
}

func (f *dohForwarder) serveUDP(conn *net.UDPConn, r *DohResolver) {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, forwarderUDPBufSize)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[DoH] udp read: %v", err)
			return
		}
		query := append([]byte(nil), buf[:n]...)
		go func(q []byte, c *net.UDPAddr) {
			ctx, cancel := context.WithTimeout(context.Background(), dohQueryTimeout)
			defer cancel()
			resp, _, err := r.forwardRaw(ctx, q)
			if err != nil {
				log.Printf("[DoH] udp forward failed: %v", err)
				return
			}
			if _, err := conn.WriteToUDP(resp, c); err != nil {
				log.Printf("[DoH] udp write: %v", err)
			}
		}(query, client)
	}
}

func (f *dohForwarder) serveTCP(ln *net.TCPListener, r *DohResolver) {
	defer func() { _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[DoH] tcp accept: %v", err)
			return
		}
		go handleDohForwarderTCP(conn, r)
	}
}

func handleDohForwarderTCP(conn net.Conn, r *DohResolver) {
	defer func() { _ = conn.Close() }()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(forwarderTCPReadDL))
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		qlen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if qlen == 0 || qlen > forwarderUDPBufSize {
			return
		}
		query := make([]byte, qlen)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), dohQueryTimeout)
		resp, _, err := r.forwardRaw(ctx, query)
		cancel()
		if err != nil {
			log.Printf("[DoH] tcp forward failed: %v", err)
			return
		}
		out := make([]byte, 2+len(resp))
		out[0] = byte(len(resp) >> 8)
		out[1] = byte(len(resp))
		copy(out[2:], resp)
		_ = conn.SetWriteDeadline(time.Now().Add(forwarderTCPWriteDL))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// dohForwarderDial returns a Resolver.Dial that connects to the local DoH
// forwarder over UDP or TCP (whichever the resolver asked for).
func dohForwarderDial(r *DohResolver) dialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		fwd, err := sharedDohForwarder(r)
		if err != nil {
			return nil, err
		}
		var d net.Dialer
		switch network {
		case "tcp", "tcp4", "tcp6":
			return d.DialContext(ctx, "tcp", fwd.tcpAddr)
		default:
			return d.DialContext(ctx, "udp", fwd.udpAddr)
		}
	}
}

const (
	DNSModeUDP  = "udp"
	DNSModeDoH  = "doh"
	DNSModeAuto = "auto"
)

var udpDNSServers = []string{
	"77.88.8.8:53", "77.88.8.1:53",
	"8.8.8.8:53", "8.8.4.4:53",
	"1.1.1.1:53", "1.0.0.1:53",
}

type dialFunc = func(context.Context, string, string) (net.Conn, error)

// buildDialer returns a net.Dialer whose internal Go resolver uses the
// chosen DNS transport. In "auto" mode the first total-failure of UDP/53
// sticks the process onto DoH for the rest of its lifetime.
func buildDialer(mode string, r *DohResolver) net.Dialer {
	switch mode {
	case DNSModeUDP:
		return newAppDialer(udpDNSDial)
	case DNSModeDoH:
		return newAppDialer(dohForwarderDial(r))
	case DNSModeAuto:
		return newAppDialer(autoDial(r))
	default:
		log.Panicf("unknown DNS mode %q", mode)
		return net.Dialer{}
	}
}

// newAppDialer wraps a Resolver.Dial with the timeouts used everywhere in
// the app for outbound TCP/HTTP connections.
func newAppDialer(dial dialFunc) net.Dialer {
	return net.Dialer{
		Timeout:   appDialerTimeout,
		KeepAlive: appDialerKeepAlive,
		Resolver:  &net.Resolver{PreferGo: true, Dial: dial},
	}
}

// udpDNSDial picks the first reachable UDP/53 resolver from udpDNSServers.
func udpDNSDial(ctx context.Context, _ string, _ string) (net.Conn, error) {
	var (
		d       net.Dialer
		lastErr error
	)
	for _, s := range udpDNSServers {
		conn, err := d.DialContext(ctx, "udp", s)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no UDP DNS servers available")
	}
	return nil, lastErr
}

// autoDial returns a Dial that probes UDP/53 once with a real DNS round-trip;
// if the probe fails it latches onto DoH for the rest of the process. Built
// for Android, where the network can flip between Wi-Fi (UDP/53 works) and
// mobile (UDP/53 blocked).
//
// A simple dial-timeout doesn't work for UDP because UDP "dial" is
// connectionless and always succeeds instantly. The only way to know whether
// UDP/53 actually works is to send a real query and wait for a response.
func autoDial(r *DohResolver) dialFunc {
	var (
		probed sync.Once
		useDoH atomic.Bool
		doh    = dohForwarderDial(r)
	)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		probed.Do(func() {
			if udpProbe(autoUDPBudget) {
				log.Printf("[DNS] UDP/53 probe OK, using UDP")
			} else {
				log.Printf("[DNS] UDP/53 unreachable; sticky-switching to DoH")
				useDoH.Store(true)
			}
		})
		if useDoH.Load() {
			return doh(ctx, network, addr)
		}
		return udpDNSDial(ctx, network, addr)
	}
}

// udpProbe sends a real DNS A query for a well-known domain via UDP and
// checks whether any response arrives within the deadline. We try the first
// two servers from udpDNSServers under a shared deadline — if neither
// responds, UDP/53 is blocked.
func udpProbe(timeout time.Duration) bool {
	m := new(dns.Msg)
	m.SetQuestion("dns.google.", dns.TypeA)
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		return false
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 512)
	limit := min(len(udpDNSServers), 2)
	for _, server := range udpDNSServers[:limit] {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		conn, err := net.DialTimeout("udp", server, remaining)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(deadline)
		_, _ = conn.Write(wire)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err == nil && n > 12 {
			return true
		}
	}
	return false
}
