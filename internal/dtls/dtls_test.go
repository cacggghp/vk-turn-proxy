package dtls

import (
	"testing"
)

func TestServerConfig(t *testing.T) {
	// 1. Should fail when secret is empty
	_, err := ServerConfig("")
	if err == nil {
		t.Errorf("Expected ServerConfig to fail when secret is empty, but it returned nil error")
	}

	// 2. Should succeed when secret is provided
	config, err := ServerConfig("my-secure-password")
	if err != nil {
		t.Errorf("Expected ServerConfig to succeed with secret, got error: %v", err)
	}
	if config == nil {
		t.Errorf("Expected ServerConfig to return valid config, got nil")
	}
}

func TestClientConfig(t *testing.T) {
	// 1. Should fail when secret is empty
	_, err := ClientConfig("")
	if err == nil {
		t.Errorf("Expected ClientConfig to fail when secret is empty, but it returned nil error")
	}

	// 2. Should succeed when secret is provided
	config, err := ClientConfig("my-secure-password")
	if err != nil {
		t.Errorf("Expected ClientConfig to succeed with secret, got error: %v", err)
	}
	if config == nil {
		t.Errorf("Expected ClientConfig to return valid config, got nil")
	}
}
