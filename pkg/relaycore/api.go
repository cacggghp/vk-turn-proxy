// SPDX-License-Identifier: GPL-3.0-only

package relaycore

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
)

type InviteKind string

const (
	InviteKindVK     InviteKind = "vk"
	InviteKindYandex InviteKind = "yandex"
)

type TurnCredentials struct {
	Username string
	Password string
	Address  string
}

type CredentialProvider interface {
	GetCredentials(ctx context.Context, inviteLink string) (TurnCredentials, error)
}

type CredentialProviderFunc func(ctx context.Context, inviteLink string) (TurnCredentials, error)

func (f CredentialProviderFunc) GetCredentials(ctx context.Context, inviteLink string) (TurnCredentials, error) {
	return f(ctx, inviteLink)
}

type ClientConfig struct {
	ListenAddr         string
	PeerAddr           string
	InviteLink         string
	InviteKind         InviteKind
	ConnectionCount    int
	TurnHost           string
	TurnPort           string
	UseTURNUDP         bool
	DisableDTLS        bool
	CredentialProvider CredentialProvider
	Logger             *log.Logger
	RouteOutput        io.Writer
}

type ServerConfig struct {
	ListenAddr  string
	ConnectAddr string
	Logger      *log.Logger
}

func RunClient(ctx context.Context, cfg ClientConfig) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}

	return client.Run(ctx)
}

func RunServer(ctx context.Context, cfg ServerConfig) error {
	server, err := NewServer(cfg)
	if err != nil {
		return err
	}

	return server.Run(ctx)
}

func (cfg *ClientConfig) withDefaults() error {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:9000"
	}
	if cfg.PeerAddr == "" {
		return errors.New("peer address is required")
	}
	if cfg.InviteLink == "" {
		return errors.New("invite link is required")
	}
	if cfg.CredentialProvider == nil {
		switch cfg.InviteKind {
		case InviteKindVK:
			cfg.CredentialProvider = NewVKCredentialProvider(nil)
		case InviteKindYandex:
			cfg.CredentialProvider = NewYandexCredentialProvider()
		default:
			return errors.New("credential provider is required")
		}
	}
	if cfg.ConnectionCount <= 0 {
		if cfg.InviteKind == InviteKindYandex {
			cfg.ConnectionCount = 1
		} else {
			cfg.ConnectionCount = 10
		}
	}

	return nil
}

func (cfg *ServerConfig) withDefaults() error {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:56000"
	}
	if cfg.ConnectAddr == "" {
		return errors.New("connect address is required")
	}

	return nil
}

func resolvePeerAddr(addr string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", addr)
}
