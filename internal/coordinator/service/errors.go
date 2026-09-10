package service

import "errors"

var (
	ErrInvalidParam        = errors.New("invalid param")
	ErrKeyNotFound         = errors.New("key not found")
	ErrInsufficientBalance = errors.New("insufficient balance")
	ErrBroadcastFailed     = errors.New("broadcast failed")
	ErrSignFailed          = errors.New("sign failed")
	ErrGenesisExists       = errors.New("genesis already exists")
	ErrNetwork             = errors.New("network error")
)
