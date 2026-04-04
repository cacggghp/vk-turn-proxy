// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/cacggghp/vk-turn-proxy/pkg/relaycore"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := relaycore.RunServer(ctx, relaycore.ServerConfig{
		ListenAddr:  *listen,
		ConnectAddr: *connect,
	}); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
