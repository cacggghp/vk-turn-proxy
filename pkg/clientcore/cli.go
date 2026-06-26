//go:build !ios

package clientcore

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func RunCLI() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		select {
		case <-signalChan:
		case <-time.After(5 * time.Second):
		}
		log.Fatalf("Exit...\n")
	}()

	cfg := Config{}
	genWrapKey := flag.Bool("gen-wrap-key", false, "print a fresh 64-character hex key for -wrap-key and exit")
	flag.StringVar(&cfg.TURNHost, "turn", "", "override TURN server ip")
	flag.StringVar(&cfg.TURNPort, "port", "", "override TURN port")
	flag.StringVar(&cfg.Listen, "listen", "127.0.0.1:9000", "listen on ip:port")
	flag.StringVar(&cfg.VKLink, "vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	flag.StringVar(&cfg.YandexLink, "yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	flag.StringVar(&cfg.PeerAddr, "peer", "", "peer server address (host:port)")
	flag.IntVar(&cfg.NumStreams, "n", 0, "connections to TURN (default 10 for VK, 1 for Yandex)")
	flag.BoolVar(&cfg.UseUDP, "udp", false, "connect to TURN with UDP")
	flag.BoolVar(&cfg.NoDTLS, "no-dtls", false, "connect without obfuscation. DO NOT USE")
	flag.BoolVar(&cfg.VLESSMode, "vless", false, "VLESS mode: forward TCP connections (for VLESS) instead of UDP packets")
	flag.BoolVar(&cfg.VLESSBond, "vless-bond", false, "bond one VLESS TCP connection across all active smux sessions")
	flag.BoolVar(&cfg.WrapMode, "wrap", false, "WRAP mode: SRTP-like AEAD obfuscation for DTLS packets before they reach TURN ChannelData")
	flag.StringVar(&cfg.WrapKeyHex, "wrap-key", "", "32-byte hex-encoded shared key for -wrap (64 hex chars)")
	flag.IntVar(&cfg.StreamsPerCred, "streams-per-cred", streamsPerCache, "number of TURN streams sharing one VK credential cache")
	flag.BoolVar(&cfg.Debug, "debug", false, "enable debug logging")
	flag.BoolVar(&cfg.ManualCaptcha, "manual-captcha", false, "skip auto captcha solving, use manual mode immediately")
	flag.StringVar(&cfg.CaptchaSolver, "captcha-solver", "v2", "auto captcha solver implementation: v1|v2")
	flag.StringVar(&cfg.CaptchaHost, "captcha-host", "", "manual captcha host:port to expose in addition to localhost:8765")
	flag.Parse()

	if *genWrapKey {
		key, err := genWrapKeyHex()
		if err != nil {
			log.Panicf("%v", err)
		}
		fmt.Println(key)
		return
	}
	if err := Run(ctx, cfg); err != nil {
		log.Panicf("%v", err)
	}
}
