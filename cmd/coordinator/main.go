package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/koku-web3/go-koku/internal/coordinator/chain"
	"github.com/koku-web3/go-koku/internal/coordinator/config"
	"github.com/koku-web3/go-koku/internal/coordinator/grpc"
	"github.com/koku-web3/go-koku/internal/coordinator/server"
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

	chainServ, err := chain.NewChainService(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Coordinator: %v", err)
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

	chainServ.StartTokenRefresh(ctx)

	if cfg.GRPC.Enable {
		grpcSrv := grpc.NewServer(chainServ, &cfg.GRPC)
		if err := grpcSrv.Start(ctx); err != nil {
			log.Error("gRPC server error", "error", err)
		}
	} else {
		srv := server.NewServer(chainServ, cfg.App.Host, cfg.App.Port, cfg.App.ReadHeaderTimeout)
		if err := srv.Start(ctx); err != nil {
			log.Error("HTTP server error", "error", err)
		}
	}
}
