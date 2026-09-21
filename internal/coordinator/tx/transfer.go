package tx

import (
	"context"

	"github.com/koku-web3/go-koku/internal/coordinator/types"
)

// TransferManager 转账业务的接口
type TransferManager interface {
	UniversalTransfer(ctx context.Context, in *types.UniversalTransferInput) (*types.UniversalTransferResult, error)
}
