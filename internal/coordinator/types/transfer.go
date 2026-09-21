package types

type UniversalTransferInput struct {
	BizID       string
	TraceID     string
	ChainCode   string
	Coin        string
	FromAddress string
	ToAddress   string
	Amount      string
	Contract    string
	KeyUsage    uint32
}

type UniversalTransferResult struct {
	TxHash string
}

func (u *UniversalTransferInput) IsContractTx() bool {
	return u.Contract != ""
}
