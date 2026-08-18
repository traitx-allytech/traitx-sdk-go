package traitx

import (
	"sync"
	"time"
)

// BreakerState is the circuit breaker's current state.
type BreakerState string

const (
	BreakerClosed   BreakerState = "closed"
	BreakerOpen     BreakerState = "open"
	BreakerHalfOpen BreakerState = "half_open"
)

// CircuitBreaker counts transport failures only. Its whole purpose is that one
// unreachable dependency costs you one timeout, not a timeout on every login.
// See SPEC.md §10.
type CircuitBreaker struct {
	mu       sync.Mutex
	cfg      BreakerConfig
	clock    func() time.Time
	failures int
	openedAt time.Time
	probing  bool
}

// NewCircuitBreaker builds a breaker. clock may be nil, in which case time.Now
// is used.
func NewCircuitBreaker(cfg BreakerConfig, clock func() time.Time) *CircuitBreaker {
	if clock == nil {
		clock = time.Now
	}
	return &CircuitBreaker{cfg: cfg, clock: clock}
}

// State reports the current state.
func (b *CircuitBreaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stateLocked()
}

func (b *CircuitBreaker) stateLocked() BreakerState {
	if b.failures < b.cfg.FailureThreshold {
		return BreakerClosed
	}
	if b.clock().Sub(b.openedAt) >= b.cfg.ResetAfter {
		return BreakerHalfOpen
	}
	return BreakerOpen
}

// Allow reports whether the call may touch the network. In half-open exactly one
// probe is admitted; concurrent callers are short-circuited until it settles.
func (b *CircuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.stateLocked() {
	case BreakerClosed:
		return true
	case BreakerOpen:
		return false
	default:
		if b.probing {
			return false
		}
		b.probing = true
		return true
	}
}

// RecordSuccess resets the failure counter.
func (b *CircuitBreaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.openedAt = time.Time{}
	b.probing = false
}

// RecordFailure counts a transport failure and opens the breaker at the threshold.
func (b *CircuitBreaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
	b.failures++
	if b.failures >= b.cfg.FailureThreshold {
		b.openedAt = b.clock()
	}
}

// Reset returns the breaker to closed.
func (b *CircuitBreaker) Reset() { b.RecordSuccess() }
