package setup

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"

	"github.com/koku-web3/go-koku/internal/signer/config"
	"github.com/koku-web3/go-koku/internal/signer/kms"
	"github.com/koku-web3/go-koku/pkg/tlsconfig"
	log "github.com/koku-web3/logko"
)

// Dependencies 聚合启动时所需配置选
// ServerTLS 为 nil 表示 insecure 模式。
type Deps struct {
	KMS       *kms.KMS
	ServerTLS *tls.Config
}

// Wire 一次性完成：TLS 派生 + KMS client 构造。
// KMS client 内部已同步完成 Vault 首次认证，装配即就绪。
// AWS 凭证优先从环境变量获取。
func Wire(ctx context.Context, cfg *config.Config) (*Deps, error) {
	srvTLS, err := buildTLS(cfg)
	if err != nil {
		return nil, err
	}

	// 优先使用环境变量覆盖配置文件中的 AWS 凭证
	if accessKey := os.Getenv("AWS_ACCESS_KEY"); accessKey != "" {
		cfg.AWS.AccessKey = accessKey
		log.Warn("AWS access_key from environment variable overrides config file")
	}
	if secretKey := os.Getenv("AWS_SECRET_KEY"); secretKey != "" {
		cfg.AWS.SecretKey = secretKey
		log.Warn("AWS secret_key from environment variable overrides config file")
	}
	if roleARN := os.Getenv("AWS_ROLE_ARN"); roleARN != "" {
		cfg.AWS.RoleARN = roleARN
		log.Warn("AWS role_arn from environment variable overrides config file")
	}

	kmsClient, err := kms.NewKMS(ctx, &cfg.Vault, &cfg.AWS)
	if err != nil {
		return nil, fmt.Errorf("new kms client failed: %w", err)
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
