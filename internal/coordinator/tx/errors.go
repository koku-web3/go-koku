package tx

import "errors"

var (
	ErrInvalidParam        = errors.New("invalid param")
	ErrKeyNotFound         = errors.New("key not found")
	ErrBroadcastFailed     = errors.New("broadcast failed")
	ErrSignFailed          = errors.New("sign failed")
	ErrNetwork             = errors.New("network error")
	ErrInsufficientBalance = errors.New("insufficient balance")
)
