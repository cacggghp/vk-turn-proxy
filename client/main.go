package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bschaatsbergen/dnsdialer"

	"github.com/cacggghp/vk-turn-proxy/internal/api/vk"
	"github.com/cacggghp/vk-turn-proxy/internal/api/yandex"
	"github.com/cacggghp/vk-turn-proxy/internal/client"
	"github.com/cacggghp/vk-turn-proxy/internal/config"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "=======================================================================\n")
		fmt.Fprintf(os.Stderr, " 🛡️ VK TURN Proxy Client\n")
		fmt.Fprintf(os.Stderr, "=======================================================================\n")
		fmt.Fprintf(os.Stderr, " Клиентская часть прокси. Подключается к легитимному TURN-серверу\n")
		fmt.Fprintf(os.Stderr, " VK или Яндекса по ссылке-инвайту и маршрутизирует UDP трафик.\n")
		fmt.Fprintf(os.Stderr, " Обфусцирует трафик вашего туннеля (VPN), маскируя его под видеозвонок.\n\n")
		fmt.Fprintf(os.Stderr, " 📜 Использование:\n")
		fmt.Fprintf(os.Stderr, "   vk-turn-proxy-client [options]\n\n")
		fmt.Fprintf(os.Stderr, " 🔧 Доступные параметры:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n 🚀 Примеры запуска:\n")
		fmt.Fprintf(os.Stderr, "   [VK Calls - рекомендуется (открывается сразу 16 потоков)]\n")
		fmt.Fprintf(os.Stderr, "   ./vk-turn-proxy-client -peer 1.2.3.4:56000 -vk-link \"https://vk.com/call/join/123\" -secret \"mypassword\"\n\n")
		fmt.Fprintf(os.Stderr, "   [С конфигурационным файлом]\n")
		fmt.Fprintf(os.Stderr, "   ./vk-turn-proxy-client -c client.yaml\n\n")
		fmt.Fprintf(os.Stderr, " 🛠 Интеграция с WireGuard:\n")
		fmt.Fprintf(os.Stderr, "   Укажите в конфигурации WireGuard клиента:\n")
		fmt.Fprintf(os.Stderr, "   Endpoint = 127.0.0.1:9000 (или тот IP:порт, что указан в -listen)\n")
		fmt.Fprintf(os.Stderr, "   MTU = 1280 (обязательно для предотвращения фрагментации)\n")
	}

	host := flag.String("turn", "", "override TURN server ip")
	port := flag.String("port", "", "override TURN port")
	listen := flag.String("listen", "127.0.0.1:9000", "listen on ip:port")
	vklink := flag.String("vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	yalink := flag.String("yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	peerAddr := flag.String("peer", "", "peer server address (host:port) (required)")
	n := flag.Int("n", 0, "connections to TURN (default 16 for VK, 1 for Yandex)")
	udp := flag.Bool("udp", false, "connect to TURN with UDP")
	direct := flag.Bool("no-dtls", false, "connect without obfuscation. DO NOT USE")
	secret := flag.String("secret", "", "optional PSK (Pre-Shared Key) for DTLS authentication")
	cfgFile := flag.String("c", "", "path to config.yaml file")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	yamlConfig, err := config.LoadClientConfig(*cfgFile)
	if err != nil {
		log.Fatalf("failed to parse yaml config: %v", err)
	}

	explicit := config.GetExplicitFlags()
	finalListen := config.MergeFlagString(explicit, "listen", *listen, yamlConfig.Listen, "127.0.0.1:9000")
	finalPeer := config.MergeFlagString(explicit, "peer", *peerAddr, yamlConfig.Peer, "")
	finalHost := config.MergeFlagString(explicit, "turn", *host, yamlConfig.TurnHost, "")
	finalPort := config.MergeFlagString(explicit, "port", *port, yamlConfig.TurnPort, "")
	finalVkLink := config.MergeFlagString(explicit, "vk-link", *vklink, yamlConfig.VkLink, "")
	finalYaLink := config.MergeFlagString(explicit, "yandex-link", *yalink, yamlConfig.YandexLink, "")
	finalSecret := config.MergeFlagString(explicit, "secret", *secret, yamlConfig.Secret, "")
	finalN := config.MergeFlagInt(explicit, "n", *n, yamlConfig.Threads, 0)
	finalUDP := config.MergeFlagBool(explicit, "udp", *udp, yamlConfig.UDP, false)
	finalDirect := config.MergeFlagBool(explicit, "no-dtls", *direct, yamlConfig.NoDTLS, false)

	if finalPeer == "" {
		fmt.Fprintf(os.Stderr, "error: -peer or config.yaml peer is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	peer, err := net.ResolveUDPAddr("udp", finalPeer)
	if err != nil {
		log.Fatalf("failed to resolve peer address %q: %v", finalPeer, err)
	}

	if finalSecret == "" {
		fmt.Fprintf(os.Stderr, "error: DTLS secret is strictly required for secure authentication. Use -secret or specify it in the config file.\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if (finalVkLink == "") == (finalYaLink == "") {
		fmt.Fprintf(os.Stderr, "error: exactly one of -vk-link or -yandex-link is required (via flag or yaml)\n\n")
		flag.Usage()
		os.Exit(1)
	}

	var link string
	var getCreds client.GetCredsFunc

	if finalVkLink != "" {
		parts := strings.Split(finalVkLink, "join/")
		link = parts[len(parts)-1]
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}
		
		dialer := dnsdialer.New(
			dnsdialer.WithResolvers("77.88.8.8:53", "77.88.8.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"),
			dnsdialer.WithStrategy(dnsdialer.Fallback{}),
			dnsdialer.WithCache(100, 10*time.Hour, 10*time.Hour),
		)

		getCreds = func() (string, string, string, error) {
			return vk.GetCreds(link, dialer)
		}
		if finalN <= 0 {
			finalN = 16
		}
	} else {
		parts := strings.Split(finalYaLink, "j/")
		link = parts[len(parts)-1]
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}

		getCreds = func() (string, string, string, error) {
			return yandex.GetCreds(link)
		}
		if finalN <= 0 {
			finalN = 1
		}
	}

	cfg := client.Config{
		ListenAddr: finalListen,
		PeerAddr:   peer,
		Secret:     finalSecret,
		Threads:    finalN,
		UseUDP:     finalUDP,
		NoDTLS:     finalDirect,
		GetCreds:   getCreds,
		TurnHost:   finalHost,
		TurnPort:   finalPort,
	}

	cli := client.New(cfg)

	log.Printf("Starting VK TURN Proxy client on %s...\n", finalListen)
	if err := cli.Run(ctx); err != nil {
		log.Fatalf("client exited with error: %v", err)
	}
}
