package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerConfigAutogenSecret(t *testing.T) {
	tempDir := t.TempDir()
	yamlPath := filepath.Join(tempDir, "server.yaml")

	initialYaml := `listen: 0.0.0.0:56000
connect: 127.0.0.1:51820
secret: ""
`
	if err := os.WriteFile(yamlPath, []byte(initialYaml), 0644); err != nil {
		t.Fatalf("Failed to write mock yaml: %v", err)
	}

	cfg, err := LoadServerConfig(yamlPath)
	if err != nil {
		t.Fatalf("Failed to LoadServerConfig: %v", err)
	}

	if cfg.Secret == "" {
		t.Fatalf("Expected Secret to be auto-generated, got empty string")
	}
	if len(cfg.Secret) != 32 {
		t.Errorf("Expected auto-generated secret to be 32 chars hex string, got %d chars: %s", len(cfg.Secret), cfg.Secret)
	}

	// Make sure it wrote back to the file
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("Failed to read updated yaml: %v", err)
	}

	if string(data) == initialYaml {
		t.Errorf("Expected YAML file to be modified with new secret")
	}
}

func TestLoadServerConfigExistingSecret(t *testing.T) {
	tempDir := t.TempDir()
	yamlPath := filepath.Join(tempDir, "server_existing.yaml")

	initialYaml := `listen: 0.0.0.0:56000
connect: 127.0.0.1:51820
secret: "existing-psk"
`
	if err := os.WriteFile(yamlPath, []byte(initialYaml), 0644); err != nil {
		t.Fatalf("Failed to write mock yaml: %v", err)
	}

	cfg, err := LoadServerConfig(yamlPath)
	if err != nil {
		t.Fatalf("Failed to LoadServerConfig: %v", err)
	}

	if cfg.Secret != "existing-psk" {
		t.Fatalf("Expected Secret to be 'existing-psk', got %q", cfg.Secret)
	}
}
