package txbuilder

import (
	"sync"
	"time"
)

type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

var stateNames = []string{"closed", "open", "half-open"}

func (s CircuitState) String() string {
	if s >= 0 && int(s) < len(stateNames) {
		return stateNames[s]
	}
	return "unknown"
}

type CircuitBreaker struct {
	mu            sync.RWMutex
	state         CircuitState
	failures      int
	threshold     int
	window        time.Duration
	lastFailure   time.Time
	halfOpenCount int
}

func NewCircuitBreaker(threshold int, windowSec int) *CircuitBreaker {
	return &CircuitBreaker{
		state:     StateClosed,
		threshold: threshold,
		window:    time.Duration(windowSec) * time.Second,
	}
}

func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateOpen:
		if time.Since(cb.lastFailure) > cb.window {
			cb.state = StateHalfOpen
			cb.halfOpenCount = 0
			return false
		}
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateHalfOpen:
		cb.halfOpenCount++
		if cb.halfOpenCount >= 2 {
			cb.state = StateClosed
			cb.failures = 0
		}
	case StateClosed:
		cb.failures = 0
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailure = time.Now()

	switch cb.state {
	case StateClosed:
		cb.failures++
		if cb.failures >= cb.threshold {
			cb.state = StateOpen
		}
	case StateHalfOpen:
		cb.state = StateOpen
	}
}

func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}
