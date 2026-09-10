package mq

import "fmt"

// PermanentError 永久性错误，不应重试（如参数非法、地址不存在）
type PermanentError struct {
	Msg string
}

func (e *PermanentError) Error() string { return e.Msg }

func NewPermanentError(format string, args ...interface{}) *PermanentError {
	return &PermanentError{Msg: fmt.Sprintf(format, args...)}
}

func NewPermanentErrorFromError(err error) *PermanentError {
	return &PermanentError{Msg: err.Error()}
}

// TransientError 临时性错误，可以重试（如网络故障、超时）
type TransientError struct {
	Msg string
}

func (e *TransientError) Error() string { return e.Msg }

func NewTransientError(format string, args ...interface{}) *TransientError {
	return &TransientError{Msg: fmt.Sprintf(format, args...)}
}

func NewTransientErrorFromError(err error) *TransientError {
	return &TransientError{Msg: err.Error()}
}

// IsPermanent 判断是否为永久性错误
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*PermanentError)
	return ok
}

// IsTransient 判断是否为临时性错误
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*TransientError)
	return ok
}
