package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/koku-web3/go-koku/internal/coordinator/config"
	grpcpkg "github.com/koku-web3/go-koku/internal/coordinator/grpc"
	"github.com/koku-web3/go-koku/internal/coordinator/infra/setup"
	"github.com/koku-web3/go-koku/internal/coordinator/mq"
	"github.com/koku-web3/go-koku/internal/coordinator/service"
	log "github.com/koku-web3/logko"
)

func main() {
	configPath := flag.String("config", config.DEFAULT_PATH, "path to config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fatalf("Failed to load config: %v\n", err)
	}

	if err := log.SetupFromTOML(cfg.Path); err != nil {
		fatalf("Failed to setup log: %v\n", err)
	}

	deps, err := setup.Wire(cfg)
	if err != nil {
		fatalf("Failed to wire denpendencies: %v\n", err)
	}

	keyMgr := service.NewKeyService(deps.Repo, deps.KeyCreator, deps.TxBuilder)
	transferSvc := service.NewTransferService(deps.Repo, deps.TxBuilder, deps.Signer)

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	grpcSrv := grpcpkg.NewServer(cfg, keyMgr, deps.Repo, deps.ServerTLS)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := grpcSrv.RunForever(ctx); err != nil {
			fatalf("gRPC server run failed: %v\n", err)
		}
	}()

	mqConsumer, err := mq.NewConsumer(ctx, cfg.MQ, transferSvc, deps.Repo)
	if err != nil {
		fatalf("Failed to create MQ Consumer: %v\n", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := mqConsumer.RunForever(); err != nil {
			fatalf("MQ Consumer run failed: %v\n", err)
		}
	}()

	go func() {
		quitCh := make(chan os.Signal, 1)
		signal.Notify(quitCh, syscall.SIGINT, syscall.SIGTERM)
		<-quitCh
		log.Info("Received shutdown signal, initiating graceful shutdown")
		cancel()
	}()

	wg.Wait()
	deps.Close()
	log.Info("Coordinator shutdown complete")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}
