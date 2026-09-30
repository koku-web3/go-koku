package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/koku-web3/go-koku/internal/signer/config"
	"github.com/koku-web3/go-koku/internal/signer/grpc"
	"github.com/koku-web3/go-koku/internal/signer/infra/setup"
	log "github.com/koku-web3/go-koku/pkg/logko"
	"github.com/koku-web3/go-koku/pkg/middleware"
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

	ctx, cancel := context.WithCancel(context.Background())
	deps, err := setup.Wire(ctx, cfg)
	if err != nil {
		fatalf("Failed to wire dependencies: %v\n", err)
	}
	defer deps.Close()

	signerSvc := grpc.NewSignerService(deps.KMS, cfg.GRPC.Host, cfg.GRPC.Port, deps.ServerTLS)

	go func() {
		quitCh := make(chan os.Signal, 1)
		signal.Notify(quitCh, syscall.SIGINT, syscall.SIGTERM)
		<-quitCh
		log.Info("Received shutdown signal, initiating graceful shutdown")
		cancel()
	}()

	if err := signerSvc.Start(ctx, middleware.UnaryServerInterceptor()); err != nil {
		panic(fmt.Errorf("gRPC server error:%v", err))
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}
