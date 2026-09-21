package types

import "github.com/koku-web3/go-koku/pkg/keyutil"

type GenesisInput struct {
	TraceID   string
	ChainCode string
	KeyType   string
}

type CreateKeyInput struct {
	TraceID   string
	ChainCode string
	Usage     keyutil.AccountUsage
	Count     int32
}

type VerifyAddressInput struct {
	TraceID   string
	ChainCode string
	Address   string
}

type VerifyContractAddressInput struct {
	TraceID   string
	ChainCode string
	Address   string
}

type BalanceInput struct {
	TraceID     string
	ChainCode   string
	Coin        string
	IsBasicCoin bool
	FromAddress string
	Amount      string
	Contract    string
}

type BalanceResult struct {
	IsCoinSufficient  bool
	IsTokenSufficient bool
}
