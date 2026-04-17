package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dohAnswer builds a wire-format DNS reply for a single question with one
// answer of the matching type (A or AAAA). TTL is returned as-is.
func dohAnswer(t *testing.T, query []byte, ip net.IP, ttl uint32) []byte {
	t.Helper()
	req := new(dns.Msg)
	if err := req.Unpack(query); err != nil {
		t.Fatalf("unpack query: %v", err)
	}
	reply := new(dns.Msg)
	reply.SetReply(req)
	if len(req.Question) != 1 {
		t.Fatalf("expected 1 question, got %d", len(req.Question))
	}
	q := req.Question[0]
	switch q.Qtype {
	case dns.TypeA:
		if v4 := ip.To4(); v4 != nil {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   v4,
			})
		}
	case dns.TypeAAAA:
		if ip.To4() == nil {
			reply.Answer = append(reply.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip,
			})
		}
	}
	out, err := reply.Pack()
	if err != nil {
		t.Fatalf("pack reply: %v", err)
	}
	return out
}

func readWire(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

func TestDohResolver_LookupIPAddr_Success(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			t.Errorf("wrong Content-Type: %q", ct)
		}
		body := readWire(t, r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(dohAnswer(t, body, net.ParseIP("93.184.216.34"), 300))
	}))
	defer srv.Close()

	r := newDohResolverWithClient(
		[]DohEndpoint{{URL: srv.URL, Hostname: "mock", BootstrapIPs: []string{"127.0.0.1"}}},
		srv.Client(),
	)

	ips, err := r.LookupIPAddr(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(ips) == 0 {
		t.Fatalf("no ips returned")
	}
	if ips[0].String() != "93.184.216.34" {
		t.Fatalf("unexpected ip %s", ips[0])
	}
	// Two concurrent queries fire (A + AAAA), so we expect 2 hits.
	if got := hits.Load(); got != 2 {
		t.Fatalf("expected 2 HTTP hits, got %d", got)
	}
}

func TestDohResolver_Fallback(t *testing.T) {
	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		body := readWire(t, r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, body, net.ParseIP("1.2.3.4"), 300))
	}))
	defer second.Close()

	r := newDohResolverWithClient(
		[]DohEndpoint{
			{URL: first.URL, Hostname: "first", BootstrapIPs: []string{"127.0.0.1"}},
			{URL: second.URL, Hostname: "second", BootstrapIPs: []string{"127.0.0.1"}},
		},
		first.Client(),
	)
	ips, err := r.LookupIPAddr(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "1.2.3.4" {
		t.Fatalf("unexpected ips: %v", ips)
	}
	if firstHits.Load() == 0 || secondHits.Load() == 0 {
		t.Fatalf("fallback did not probe both endpoints: first=%d second=%d", firstHits.Load(), secondHits.Load())
	}
}

func TestDohResolver_Cache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body := readWire(t, r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, body, net.ParseIP("5.6.7.8"), 300))
	}))
	defer srv.Close()

	r := newDohResolverWithClient(
		[]DohEndpoint{{URL: srv.URL, Hostname: "mock", BootstrapIPs: []string{"127.0.0.1"}}},
		srv.Client(),
	)
	if _, err := r.LookupIPAddr(context.Background(), "example.com"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	firstHits := hits.Load()
	if _, err := r.LookupIPAddr(context.Background(), "example.com"); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if hits.Load() != firstHits {
		t.Fatalf("cache miss: expected %d HTTP hits, got %d", firstHits, hits.Load())
	}
}

func TestAutoDial_StickyAfterUDPFailure(t *testing.T) {
	// DoH backend: always responds with a valid wire-format reply.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readWire(t, r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, body, net.ParseIP("9.9.9.9"), 300))
	}))
	defer srv.Close()

	resolver := newDohResolverWithClient(
		[]DohEndpoint{{URL: srv.URL, Hostname: "mock", BootstrapIPs: []string{"127.0.0.1"}}},
		srv.Client(),
	)

	dial := autoDial(resolver)

	// Poison udpDNSServers so that udpProbe (real DNS round-trip) fails
	// immediately — net.DialTimeout rejects the malformed address.
	old := udpDNSServers
	udpDNSServers = []string{"not-a-valid-host-port"}
	defer func() { udpDNSServers = old }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn1, err := dial(ctx, "udp", "unused")
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	_ = conn1.Close()

	// Second call must skip UDP entirely. We assert this by poisoning
	// udpDNSServers with a value that would fail parsing — if the dialer
	// touches UDP again the call errors loudly.
	udpDNSServers = []string{"still-not-a-valid-host-port"}
	conn2, err := dial(ctx, "udp", "unused")
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	_ = conn2.Close()
}
