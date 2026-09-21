package key

import (
	"context"

	"github.com/koku-web3/go-koku/internal/coordinator/types"
	grpc "github.com/koku-web3/go-koku/pkg/proto/coordinator"
)

// KeyManager 定义密钥相关业务的接口
type KeyManager interface {
	Genesis(ctx context.Context, in *types.GenesisInput) error
	CreateKey(ctx context.Context, in *types.CreateKeyInput) ([]*grpc.AddressInfo, error)
	VerifyAddress(ctx context.Context, in *types.VerifyAddressInput) (bool, error)
	VerifyContractAddress(ctx context.Context, in *types.VerifyContractAddressInput) (bool, error)
	CheckSufficientBalance(ctx context.Context, in *types.BalanceInput) (*types.BalanceResult, error)
}
