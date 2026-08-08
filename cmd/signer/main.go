package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/koku-web3/go-koku/internal/signer/config"

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
}
