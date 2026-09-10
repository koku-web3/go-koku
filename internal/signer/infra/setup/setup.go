package setup

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/koku-web3/go-koku/internal/signer/config"
	"github.com/koku-web3/go-koku/internal/signer/kms"
	log "github.com/koku-web3/go-koku/pkg/logko"
	"github.com/koku-web3/go-koku/pkg/tlsconfig"
)

// Dependencies 聚合启动时所需配置选
// ServerTLS 为 nil 表示 insecure 模式。
type Deps struct {
	KMS       *kms.KMS
	ServerTLS *tls.Config
}

// Wire 一次性完成：TLS 派生 + KMS client 构造。
// KMS client 内部已同步完成 Vault 首次认证，装配即就绪。
func Wire(ctx context.Context, cfg *config.Config) (*Deps, error) {
	srvTLS, err := buildTLS(cfg)
	if err != nil {
		return nil, err
	}

	kmsClient, err := kms.NewKMS(ctx, &cfg.Vault, &cfg.AWS)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}

	return &Deps{KMS: kmsClient, ServerTLS: srvTLS}, nil
}

// Close 关闭 KMS client
// 当前 kms.KMS（api.Client） 不暴露 Close, 无需处理
func (d *Deps) Close() {
	// KMS 关闭逻辑（待 vault client 提供 Close 后接入）
	log.Info("signer denpendencies closed")
}

// buildTLS 根据 cfg.TLS.Enable 派生服务端 tls.Config。
func buildTLS(cfg *config.Config) (*tls.Config, error) {
	if !cfg.TLS.Enable {
		return nil, nil
	}
	tlsCfg, err := tlsconfig.LoadServerConfig(tlsconfig.ServerConfig{
		CACertFile:     cfg.TLS.CACertFile,
		ServerCertFile: cfg.TLS.ServerCertFile,
		ServerKeyFile:  cfg.TLS.ServerKeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("load server TLS: %w", err)
	}
	return tlsCfg, nil
}
