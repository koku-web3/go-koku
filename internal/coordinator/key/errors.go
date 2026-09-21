package key

import "errors"

var (
	ErrInvalidParam        = errors.New("invalid param")
	ErrKeyNotFound         = errors.New("key not found")
	ErrInsufficientBalance = errors.New("insufficient balance")
	ErrGenesisExists       = errors.New("genesis already exists")
	ErrNetwork             = errors.New("network error")
)
