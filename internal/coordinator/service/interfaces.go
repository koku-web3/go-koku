package service

import (
	"context"

	coordinator "github.com/koku-web3/go-koku/pkg/proto/coordinator"
)

// KeyService 定义密钥相关业务的接口
type KeyService interface {
	Genesis(ctx context.Context, in *GenesisInput) error
	CreateKey(ctx context.Context, in *CreateKeyInput) ([]*coordinator.AddressInfo, error)
	VerifyAddress(ctx context.Context, in *VerifyAddressInput) (bool, error)
	VerifyContractAddress(ctx context.Context, in *VerifyContractAddressInput) (bool, error)
	CheckSufficientBalance(ctx context.Context, in *BalanceInput) (*BalanceResult, error)
}

// TransferService 定义转账业务的接口
type TransferService interface {
	UniversalTransfer(ctx context.Context, in *UniversalTransferInput) (*UniversalTransferResult, error)
}
