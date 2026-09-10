package txbuilder

import "errors"

var (
	ErrCircuitOpen = errors.New("circuit breaker is open")
	ErrPoolClosed  = errors.New("txbuilder client is closed")
	ErrNoAddress   = errors.New("no address found for chain")
)
