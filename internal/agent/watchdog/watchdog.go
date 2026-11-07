// Package watchdog runs a deadline-driven rollback monitor independently of
// the node's desired-state polling process. It never applies new configurations.
package watchdog

import (
	"context"
	"errors"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
)

var ErrInvalidMonitor = errors.New("watchdog requires a protected journal, trusted recovery operator and bounded interval")

type Result string

const (
	Idle             Result = "idle"
	Armed            Result = "armed"
	Recovered        Result = "recovered"
	RecoveryRequired Result = "recovery_required"
)

type GuardStore interface {
	UnconfirmedActivation(context.Context) (*state.ActivationGuard, error)
	RecoverActivation(context.Context, state.RecoveryOperator) error
}

// Monitor does not accept a callback capable of mutating the journal. The
// observer callback receives only the status and error, never a secret config.
type Monitor struct {
	store    GuardStore
	operator state.RecoveryOperator
	interval time.Duration
	observe  func(Result, error)
}

func New(store GuardStore, operator state.RecoveryOperator, interval time.Duration, observe func(Result, error)) (*Monitor, error) {
	if store == nil || operator == nil || interval < 10*time.Millisecond || interval > 30*time.Second {
		return nil, ErrInvalidMonitor
	}
	return &Monitor{store: store, operator: operator, interval: interval, observe: observe}, nil
}

// Check is a single safe transition. Before the bounded commit deadline it
// must not interrupt a candidate. At or after expiry, it retries restoration
// until the protected SQLite guard is cleared by separately observed health.
func (m *Monitor) Check(ctx context.Context, now time.Time) (Result, error) {
	if m == nil || ctx == nil || now.IsZero() {
		return RecoveryRequired, ErrInvalidMonitor
	}
	if err := ctx.Err(); err != nil {
		return RecoveryRequired, err
	}
	guard, err := m.store.UnconfirmedActivation(ctx)
	if err != nil {
		return RecoveryRequired, err
	}
	if guard == nil {
		// Nothing pending is NOT proof that the current runtime is healthy.
		return Idle, nil
	}
	if guard.Deadline.IsZero() {
		return RecoveryRequired, state.ErrActivationDenied
	}
	if now.Before(guard.Deadline) {
		return Armed, nil
	}
	if err := m.store.RecoverActivation(ctx, m.operator); err != nil {
		return RecoveryRequired, err
	}
	return Recovered, nil
}

// Run performs the initial check synchronously on startup and then on a
// bounded cadence. A temporary journal/IPC/health failure never ends the
// watchdog or makes an unconfirmed lease disappear; it is retried continuously.
// Only cancellation is a normal shutdown.
func (m *Monitor) Run(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrInvalidMonitor
	}
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		status, err := m.Check(ctx, time.Now())
		if m.observe != nil {
			m.observe(status, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
