package txbuilder

import (
	"context"
	"strings"

	"github.com/koku-web3/go-koku/internal/coordinator/repository"
)

// chainProviderAdapter 用于将 KeyRepository 适配为 ChainProvider 接口
type chainProviderAdapter struct {
	repo *repository.GORMKeyRepository
}

// NewChainProviderAdapter 通过 KeyRepository 创建 ChainProvider 实例
func NewChainProviderAdapter(repo *repository.GORMKeyRepository) ChainProvider {
	return &chainProviderAdapter{repo: repo}
}

func (a *chainProviderAdapter) GetChainByCode(chainCode string) (string, bool) {
	var chain, err = a.repo.GetChainByCode(context.Background(), chainCode)
	if err != nil || chain == nil {
		return "", false
	}

	addr := chain.TxBuilderServGRPC
	if len(addr) == 0 || len(strings.TrimSpace(addr)) == 0 {
		return "", false
	}
	return addr, true
}
