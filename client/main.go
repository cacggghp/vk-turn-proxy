// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/relaycore"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	host := flag.String("turn", "", "override TURN server ip")
	port := flag.String("port", "", "override TURN port")
	listen := flag.String("listen", "127.0.0.1:9000", "listen on ip:port")
	vkLink := flag.String("vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	yandexLink := flag.String("yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	peerAddr := flag.String("peer", "", "peer server address (host:port)")
	connections := flag.Int("n", 0, "connections to TURN (default 10 for VK, 1 for Yandex)")
	udp := flag.Bool("udp", false, "connect to TURN with UDP")
	direct := flag.Bool("no-dtls", false, "connect without obfuscation. DO NOT USE")
	flag.Parse()

	cfg := relaycore.ClientConfig{
		ListenAddr:      *listen,
		PeerAddr:        *peerAddr,
		ConnectionCount: *connections,
		TurnHost:        *host,
		TurnPort:        *port,
		UseTURNUDP:      *udp,
		DisableDTLS:     *direct,
		RouteOutput:     os.Stdout,
	}

	switch {
	case *vkLink != "" && *yandexLink != "":
		log.Fatalf("need either vk-link or yandex-link, not both")
	case *vkLink != "":
		cfg.InviteKind = relaycore.InviteKindVK
		cfg.InviteLink = *vkLink
	case *yandexLink != "":
		cfg.InviteKind = relaycore.InviteKindYandex
		cfg.InviteLink = *yandexLink
	default:
		log.Fatalf("need either vk-link or yandex-link")
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- relaycore.RunClient(ctx, cfg)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("client failed: %v", err)
		}
	case <-ctx.Done():
		select {
		case err := <-errCh:
			if err != nil {
				log.Fatalf("client failed during shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			log.Fatalf("forced exit")
		}
	}
}
