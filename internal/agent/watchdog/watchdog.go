// Package watchdog supplies a standalone recovery scheduler, independent of
// the node's polling process. It never initiates a native activation.
package watchdog

import (
	"context"
	"errors"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
)

var ErrUnavailable = errors.New("independent watchdog is not implemented")

type Result string

const (
	Idle Result = "idle"
	Armed Result = "armed"
	Recovered Result = "recovered"
	RecoveryRequired Result = "recovery_required"
)

type GuardStore interface {
	UnconfirmedActivation(context.Context) (*state.ActivationGuard, error)
	RecoverActivation(context.Context, state.RecoveryOperator) error
}

type Monitor struct{}

func New(_ GuardStore, _ state.RecoveryOperator, _ time.Duration, _ func(Result, error)) (*Monitor, error) {
	return nil, ErrUnavailable
}

func (m *Monitor) Check(_ context.Context, _ time.Time) (Result, error) {
	return RecoveryRequired, ErrUnavailable
}

func (m *Monitor) Run(_ context.Context) error {
	return ErrUnavailable
}
