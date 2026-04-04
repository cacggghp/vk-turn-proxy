package dtls

import (
	"fmt"
	"net"

	piondtls "github.com/pion/dtls/v3"
)

// ServerConfig generates reading configuration for the Pion DTLS server.
// If secret is set, it utilizes PSK (Pre-Shared Key) mitigating MitM attacks.
// Otherwise, it falls back to a self-signed certificate.
func ServerConfig(secret string) (*piondtls.Config, error) {
	config := &piondtls.Config{
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
		ConnectionIDGenerator: piondtls.RandomCIDGenerator(8),
	}

	if secret == "" {
		return nil, fmt.Errorf("DTLS secret (--secret) is strictly required for secure authentication")
	}

	config.PSK = func(hint []byte) ([]byte, error) {
		return []byte(secret), nil
	}
	config.PSKIdentityHint = []byte("vk-turn-proxy")
	config.CipherSuites = []piondtls.CipherSuiteID{piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256}

	return config, nil
}

// ClientConfig generates configuration for the Pion DTLS client.
// If secret is set, it utilizes PSK (Pre-Shared Key).
func ClientConfig(secret string) (*piondtls.Config, error) {
	config := &piondtls.Config{
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
		ConnectionIDGenerator: piondtls.OnlySendCIDGenerator(),
	}

	if secret == "" {
		return nil, fmt.Errorf("DTLS secret (--secret) is strictly required for secure authentication")
	}

	config.PSK = func(hint []byte) ([]byte, error) {
		return []byte(secret), nil
	}
	config.PSKIdentityHint = []byte("vk-turn-proxy")
	config.CipherSuites = []piondtls.CipherSuiteID{piondtls.TLS_PSK_WITH_AES_128_GCM_SHA256}

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
