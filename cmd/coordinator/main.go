package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/koku-web3/go-koku/internal/coordinator/config"
	"github.com/koku-web3/go-koku/internal/coordinator/grpc"
	signerclient "github.com/koku-web3/go-koku/internal/coordinator/signer"
	log "github.com/koku-web3/go-koku/pkg/logko"
)

func main() {
	configPath := flag.String("config", config.DEFAULT_PATH, "path to config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if err := log.SetupFromTOML(cfg.Path); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup log: %v", err)
		os.Exit(1)
	}

	// 创建 Signer 客户端
	client, err := signerclient.NewClient(cfg.Signer.Address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Signer client: %v", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		quitCh := make(chan os.Signal, 1)
		signal.Notify(quitCh, syscall.SIGINT, syscall.SIGTERM)
		<-quitCh
		log.Info("Received shutdown signal, initiating graceful shutdown")
		cancel()
	}()

	// 启动 gRPC 服务
	server := grpc.NewServer(client, &cfg.GRPC)
	if err := server.Start(ctx); err != nil {
		log.Error("gRPC server error", "error", err)
	}
}
