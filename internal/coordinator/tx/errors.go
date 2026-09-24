package tx

import "errors"

var (
	ErrInvalidParam        = errors.New("Invalid param")
	ErrKeyNotFound         = errors.New("Key not found")
	ErrBroadcastFailed     = errors.New("Broadcast failed")
	ErrSignFailed          = errors.New("Sign failed")
	ErrNetwork             = errors.New("Network error")
	ErrInsufficientBalance = errors.New("Insufficient balance")
)
