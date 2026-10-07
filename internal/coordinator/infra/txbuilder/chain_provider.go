package txbuilder

import (
	"context"
	"fmt"
	"strings"

	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	log "github.com/koku-web3/logko"
)

// chainProviderAdapter 用于将 KeyRepository 适配为 ChainProvider 接口
type chainProviderAdapter struct {
	repo *repository.GORMKeyRepository
}

// NewChainProviderAdapter 通过 KeyRepository 创建 ChainProvider 实例
func NewChainProviderAdapter(repo *repository.GORMKeyRepository) ChainProvider {
	return &chainProviderAdapter{repo: repo}
}

func (a *chainProviderAdapter) GetChainByCode(chainCode string) (string, error) {
	var chain, err = a.repo.GetChainByCode(context.Background(), chainCode)
	if err != nil {
		return "", err
	}
	if chain == nil {
		return "", fmt.Errorf("chain data(code=%s) from DB is empty", chainCode)
	}

	addr := chain.TxBuilderServGrpc
	log.Info("Get chain information from DB success", "chain_code", chainCode, "grpc_url", addr)
	if len(addr) == 0 || len(strings.TrimSpace(addr)) == 0 {
		return "", fmt.Errorf("tx_builder_serv_grpc data in chain (code=%s) is empty", chainCode)
	}
	return addr, nil
}
