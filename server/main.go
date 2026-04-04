package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cacggghp/vk-turn-proxy/internal/config"
	"github.com/cacggghp/vk-turn-proxy/internal/server"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "=======================================================================\n")
		fmt.Fprintf(os.Stderr, " 🛡️ VK TURN Proxy Server\n")
		fmt.Fprintf(os.Stderr, "=======================================================================\n")
		fmt.Fprintf(os.Stderr, " Серверная часть прокси для обхода блокировок DPI через звонки VK/Яндекса.\n")
		fmt.Fprintf(os.Stderr, " Принимает зашифрованный DTLS 1.2 трафик (перенаправленный через TURN),\n")
		fmt.Fprintf(os.Stderr, " деобфусцирует его и передает на локальный UDP VPN сервер (WireGuard/Hysteria).\n\n")
		fmt.Fprintf(os.Stderr, " 📜 Использование:\n")
		fmt.Fprintf(os.Stderr, "   vk-turn-proxy-server [options]\n\n")
		fmt.Fprintf(os.Stderr, " 🔧 Доступные параметры:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n 🚀 Пример запуска:\n")
		fmt.Fprintf(os.Stderr, "   ./vk-turn-proxy-server -listen 0.0.0.0:56000 -connect 127.0.0.1:51820 -secret \"mypassword\"\n")
	}

	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port (required)")
	secret := flag.String("secret", "", "optional PSK (Pre-Shared Key) for DTLS authentication")
	cfgFile := flag.String("c", "", "path to config.yaml file")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	yamlConfig, err := config.LoadServerConfig(*cfgFile)
	if err != nil {
		log.Fatalf("failed to configure yaml: %v", err)
	}

	explicit := config.GetExplicitFlags()
	finalListen := config.MergeFlagString(explicit, "listen", *listen, yamlConfig.Listen, "0.0.0.0:56000")
	finalConnect := config.MergeFlagString(explicit, "connect", *connect, yamlConfig.Connect, "")
	finalSecret := config.MergeFlagString(explicit, "secret", *secret, yamlConfig.Secret, "")

	if finalConnect == "" {
		fmt.Fprintf(os.Stderr, "error: -connect or yaml config mapping is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if finalSecret == "" {
		fmt.Fprintf(os.Stderr, "error: DTLS secret is strictly required for secure authentication. Use -secret or specify it in the config file.\n\n")
		flag.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan // forceful exit if signal received twice
		log.Fatalf("Exit...\n")
	}()

	finalHandshakeLimit := config.MergeFlagInt(explicit, "handshake_limit", 0, yamlConfig.HandshakeLimit, 100)

	srv := server.New(server.Config{
		ListenAddr:     finalListen,
		ConnectAddr:    finalConnect,
		Secret:         finalSecret,
		HandshakeLimit: finalHandshakeLimit,
	})

	log.Printf("Starting VK TURN Proxy server...\n")
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("server exited with error: %v", err)
	}
}
