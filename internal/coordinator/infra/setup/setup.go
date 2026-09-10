package setup

import (
	"crypto/tls"
	"fmt"

	"github.com/koku-web3/go-koku/internal/coordinator/config"
	"github.com/koku-web3/go-koku/internal/coordinator/infra/db"
	"github.com/koku-web3/go-koku/internal/coordinator/infra/keycreator"
	"github.com/koku-web3/go-koku/internal/coordinator/infra/signer"
	"github.com/koku-web3/go-koku/internal/coordinator/infra/txbuilder"
	"github.com/koku-web3/go-koku/internal/coordinator/model"
	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	"github.com/koku-web3/go-koku/pkg/logko"
	"github.com/koku-web3/go-koku/pkg/tlsconfig"
)

// Dependencies 聚合了所有在 main 启动时所需的配置
// ServerTLS 为 nil 表示服务以 insecure 模式运行（TLS 禁用）。
type Deps struct {
	Repo       repository.KeyRepository
	KeyCreator *keycreator.Client
	Signer     *signer.Client
	TxBuilder  *txbuilder.Client
	ServerTLS  *tls.Config
}

// Wire 一次性完成所有资源的装配：数据库连接 → migrate → repository → TLS → 3 个 gRPC client。
func Wire(cfg *config.Config) (*Deps, error) {
	dbClient, err := db.NewClient(db.Config{
		Host:         cfg.DB.Host,
		Port:         cfg.DB.Port,
		User:         cfg.DB.User,
		Password:     cfg.DB.Password,
		Database:     cfg.DB.Database,
		MaxOpenConns: cfg.DB.MaxOpenConns,
		MaxIdleConns: cfg.DB.MaxIdleConns,
	})
	if err != nil {
		return nil, fmt.Errorf("db connect: %w", err)
	}
	if err := db.Migrate(dbClient, model.AllModels...); err != nil {
		return nil, fmt.Errorf("db migrate: %w", err)
	}
	// repo 依赖 dbClient，Migrate 成功后才会创建
	repo := repository.NewGORMKeyRepository(dbClient)

	// TLS 与 client 构造：任意失败均回滚已成功创建的 client
	srvTLS, kcTLS, signerTLS, err := buildTLS(cfg)
	if err != nil {
		return nil, err
	}

	kcCli, err := keycreator.NewClient(cfg.KeyCreator.Address, kcTLS)
	if err != nil {
		return nil, fmt.Errorf("keycreator client: %w", err)
	}
	signerCli, err := signer.NewClient(cfg.Signer.Address, signerTLS)
	if err != nil {
		_ = kcCli.Close()
		return nil, fmt.Errorf("signer client: %w", err)
	}
	txCli, err := txbuilder.NewClient(txbuilderConfig(cfg), txbuilder.NewChainProviderAdapter(repo))
	if err != nil {
		_ = kcCli.Close()
		_ = signerCli.Close()
		return nil, fmt.Errorf("txbuilder client: %w", err)
	}

	return &Deps{
		Repo:       repo,
		KeyCreator: kcCli,
		Signer:     signerCli,
		TxBuilder:  txCli,
		ServerTLS:  srvTLS,
	}, nil
}

// Close 所有客户端资源：txbuilder → signer → keycreator。
func (d *Deps) Close() {
	if err := d.TxBuilder.Close(); err != nil {
		logko.Error(fmt.Sprintf("close txbuilder: %v", err))
	}
	if err := d.Signer.Close(); err != nil {
		logko.Error(fmt.Sprintf("close signer: %v", err))
	}
	if err := d.KeyCreator.Close(); err != nil {
		logko.Error(fmt.Sprintf("close keycreator: %v", err))
	}
}

// buildTLS 根据 cfg.TLS.Enable 派生三套 tls.Config：
//   - srvTLS  用于 gRPC server（服务端证书）
//   - kcTLS   用于连接 key-creator（复用服务端证书为客户端证书）
//   - signerTLS 用于连接 signer（同样复用服务端证书）
//
// 不启用 TLS 时三者均为 nil。
func buildTLS(cfg *config.Config) (srvTLS, kcTLS, signerTLS *tls.Config, err error) {
	if !cfg.TLS.Enable {
		return nil, nil, nil, nil
	}

	srvTLS, err = tlsconfig.LoadServerConfig(tlsconfig.ServerConfig{
		CACertFile:     cfg.TLS.CACertFile,
		ServerCertFile: cfg.TLS.ServerCertFile,
		ServerKeyFile:  cfg.TLS.ServerKeyFile,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load server TLS: %w", err)
	}

	kcTLS, err = tlsconfig.LoadClientConfig(tlsconfig.ClientConfig{
		CACertFile:     cfg.TLS.CACertFile,
		ClientCertFile: cfg.TLS.ServerCertFile,
		ClientKeyFile:  cfg.TLS.ServerKeyFile,
		ServerName:     cfg.KeyCreator.TLSClient.ServerName,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keycreator TLS: %w", err)
	}

	signerTLS, err = tlsconfig.LoadClientConfig(tlsconfig.ClientConfig{
		CACertFile:     cfg.TLS.CACertFile,
		ClientCertFile: cfg.TLS.ServerCertFile,
		ClientKeyFile:  cfg.TLS.ServerKeyFile,
		ServerName:     cfg.Signer.TLSClient.ServerName,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("signer TLS: %w", err)
	}

	return srvTLS, kcTLS, signerTLS, nil
}

func txbuilderConfig(cfg *config.Config) txbuilder.Config {
	return txbuilder.Config{
		DialTimeout:             cfg.TxBuilder.DialTimeout,
		KeepaliveTime:           cfg.TxBuilder.Keepalive.Time,
		KeepaliveTimeout:        cfg.TxBuilder.Keepalive.Timeout,
		PermitWithoutStream:     cfg.TxBuilder.Keepalive.PermitWithoutStream,
		CircuitBreakerThreshold: cfg.TxBuilder.CircuitBreaker.FailureThreshold,
		CircuitBreakerWindow:    cfg.TxBuilder.CircuitBreaker.RecoveryWindow,
	}
}
