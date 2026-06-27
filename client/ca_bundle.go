package main

import (
	"crypto/x509"
	_ "embed"
	"log"
	"os"
	"strings"
)

//go:embed certs/cacert.pem
var mozillaCABundlePEM []byte

// loadCABundle returns a *x509.CertPool that can verify VK (and any other
// TLS site) even on platforms where the system certificate store is empty
// or unavailable — most notably Android apps that ship without /etc/ssl/certs
// and have no access to the OS cert store.
//
// Strategy:
//  1. Try x509.SystemCertPool(). If it returns a non-empty pool, use it
//     (this is the normal case on Linux/macOS/Windows desktops and servers).
//  2. If SystemCertPool is unavailable or empty, fall back to the embedded
//     Mozilla CA bundle (cacert.pem, the same one curl ships). This contains
//     every CA in the Mozilla trust program, including HARICA TLS RSA/ECC
//     Root CA 2021 which VK uses for *.vk.com since mid-2026.
//  3. Also honor the SSL_CERT_FILE / SSL_CERT_DIR env vars if set, so users
//     can override on unusual systems.
//
// Without this, on Android the tls-client (bogdanfinn) leaves RootCAs == nil,
// which makes Go fall back to SystemCertPool — and on Android that pool is
// empty, so every HTTPS request fails with:
//
//	tls: failed to verify certificate: x509: certificate signed by unknown authority
//
// See: https://github.com/cacggghp/vk-turn-proxy/issues/182 (and follow-ups).
func loadCABundle() *x509.CertPool {
	// 1. Honor explicit env overrides first (mirrors crypto/x509 behavior).
	if file := os.Getenv("SSL_CERT_FILE"); file != "" {
		if p, err := loadPoolFromFile(file); err == nil && p != nil {
			log.Printf("[CABundle] using SSL_CERT_FILE=%s", file)
			return p
		}
	}

	// 2. Try the system pool.
	if sys, err := x509.SystemCertPool(); err == nil && sys != nil && len(sys.Subjects()) > 0 {
		log.Printf("[CABundle] using system cert pool (%d roots)", len(sys.Subjects()))
		return sys
	}

	// 3. Fall back to the embedded Mozilla bundle.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mozillaCABundlePEM) {
		log.Printf("[CABundle] WARNING: embedded Mozilla bundle did not parse; HTTPS will likely fail")
	} else {
		log.Printf("[CABundle] using embedded Mozilla CA bundle (%d bytes)", len(mozillaCABundlePEM))
	}
	return pool
}

// loadPoolFromFile loads a PEM file with one or more certificates into a fresh
// CertPool. Returns nil if the file contained no usable certificates.
func loadPoolFromFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, nil
	}
	return pool, nil
}

// hasHTTPSInsecureEnv returns true if the user explicitly requested skipping
// TLS verification (useful for debugging MITM proxies or stale CA bundles).
// This is intentionally NOT exposed as a CLI flag — production should always
// verify.
func hasHTTPSInsecureEnv() bool {
	v := strings.ToLower(os.Getenv("VKTURN_INSECURE_TLS"))
	return v == "1" || v == "true" || v == "yes"
}
