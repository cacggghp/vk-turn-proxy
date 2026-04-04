package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Listen         string `yaml:"listen"`
	Connect        string `yaml:"connect"`
	Secret         string `yaml:"secret"`
	HandshakeLimit int    `yaml:"handshake_limit"`
}

type ClientConfig struct {
	Peer       string `yaml:"peer"`
	Listen     string `yaml:"listen"`
	Secret     string `yaml:"secret"`
	Threads    int    `yaml:"threads"`
	UDP        bool   `yaml:"udp"`
	NoDTLS     bool   `yaml:"no_dtls"`
	TurnHost   string `yaml:"turn"`
	TurnPort   string `yaml:"port"`
	VkLink     string `yaml:"vk_link"`
	YandexLink string `yaml:"yandex_link"`
}

// LoadServerConfig reads from the yaml file ONLY.
// To merge with CLI args, you parse flags in main, then explicitly overwrite populated yaml values,
// or apply explicit CLI flags over the loaded YAML.
func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := &ServerConfig{}
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && path == "" {
			return cfg, nil
		}
		return cfg, fmt.Errorf("could not read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse yaml: %w", err)
	}

	if cfg.Secret == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err == nil {
			cfg.Secret = hex.EncodeToString(b)
			log.Printf("Auto-generated secure DTLS secret. Saving to %s", path)
			if updatedYaml, err := yaml.Marshal(cfg); err == nil {
				_ = os.WriteFile(path, updatedYaml, 0600)
			}
		}
	}

	return cfg, nil
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg := &ClientConfig{}
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && path == "" {
			return cfg, nil
		}
		return cfg, fmt.Errorf("could not read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse yaml: %w", err)
	}

	if cfg.Secret == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err == nil {
			cfg.Secret = hex.EncodeToString(b)
			log.Printf("Auto-generated secure DTLS secret. Saving to %s", path)
			if updatedYaml, err := yaml.Marshal(cfg); err == nil {
				_ = os.WriteFile(path, updatedYaml, 0600)
			}
		}
	}

	return cfg, nil
}

// MergeFlagString overrides the val pointer if the flag was explicitly provided OR if the val is currently empty.
// If the flag was NOT provided but val has a yaml value, we return the yaml value.
func MergeFlagString(explicitFlags map[string]bool, flagName string, cliVal string, yamlVal string, defaultVal string) string {
	if explicitFlags[flagName] {
		return cliVal // User passed it explicitly via CLI
	}
	if yamlVal != "" {
		return yamlVal // User set it in YAML
	}
	return defaultVal // Fallback to program default
}

// MergeFlagInt overrides the val pointer
func MergeFlagInt(explicitFlags map[string]bool, flagName string, cliVal int, yamlVal int, defaultVal int) int {
	if explicitFlags[flagName] {
		return cliVal
	}
	if yamlVal != 0 {
		return yamlVal
	}
	return defaultVal
}

// MergeFlagBool overrides the truthy pointer
func MergeFlagBool(explicitFlags map[string]bool, flagName string, cliVal bool, yamlVal bool, defaultVal bool) bool {
	if explicitFlags[flagName] {
		return cliVal
	}
	return yamlVal || defaultVal
}

// GetExplicitFlags maps all flags that were provided by the user via command-line
func GetExplicitFlags() map[string]bool {
	explicit := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		explicit[f.Name] = true
	})
	return explicit
}
