package dtls

import (
	"crypto/tls"
	"fmt"
	"net"

	piondtls "github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

// ServerConfig generates reading configuration for the Pion DTLS server.
// If secret is set, it utilizes PSK (Pre-Shared Key) mitigating MitM attacks.
// Otherwise, it falls back to a self-signed certificate.
func ServerConfig(secret string) (*piondtls.Config, error) {
	config := &piondtls.Config{
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
		ConnectionIDGenerator: piondtls.RandomCIDGenerator(8),
	}

	if secret != "" {
		config.PSK = func(hint []byte) ([]byte, error) {
			return []byte(secret), nil
		}
		config.PSKIdentityHint = []byte("vk-turn-proxy")
		config.CipherSuites = []piondtls.CipherSuiteID{piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256}
	} else {
		// Generate a dummy self-signed cert for obfuscation
		certificate, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
		config.CipherSuites = []piondtls.CipherSuiteID{piondtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	}

	return config, nil
}

// ClientConfig generates configuration for the Pion DTLS client.
// If secret is set, it utilizes PSK (Pre-Shared Key).
func ClientConfig(secret string) (*piondtls.Config, error) {
	config := &piondtls.Config{
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
		ConnectionIDGenerator: piondtls.OnlySendCIDGenerator(),
	}

	if secret != "" {
		config.PSK = func(hint []byte) ([]byte, error) {
			return []byte(secret), nil
		}
		config.PSKIdentityHint = []byte("vk-turn-proxy")
		config.CipherSuites = []piondtls.CipherSuiteID{piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256}
	} else {
		// Generate a dummy self-signed cert to complete the handshake.
		certificate, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, fmt.Errorf("failed to generate client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
		config.CipherSuites = []piondtls.CipherSuiteID{piondtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		// Insecure mode is active when no secret is provided because we trust any generated cert.
		config.InsecureSkipVerify = true
	}

	return config, nil
}

// Client wraps an established connection into a DTLS connection.
func Client(conn net.PacketConn, peer net.Addr, config *piondtls.Config) (net.Conn, error) {
	return piondtls.Client(conn, peer, config)
}

// Listen acts as a DTLS multiplexing listener on top of a single UDP listener.
func Listen(network string, laddr *net.UDPAddr, config *piondtls.Config) (net.Listener, error) {
	return piondtls.Listen(network, laddr, config)
}
