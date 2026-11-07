package watchdog

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
)

type testGuardStore struct {
	mu sync.Mutex
	guard *state.ActivationGuard
	recoveryErr error
	readErr error
	recoveries int
}

func (s *testGuardStore) UnconfirmedActivation(_ context.Context) (*state.ActivationGuard, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return nil, s.readErr
	}
	if s.guard == nil {
		return nil, nil
	}
	copyOfGuard := *s.guard
	return &copyOfGuard, nil
}

func (s *testGuardStore) RecoverActivation(_ context.Context, op state.RecoveryOperator) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if op == nil {
		return errors.New("trusted operator missing")
	}
	s.recoveries++
	if s.recoveryErr != nil {
		return s.recoveryErr
	}
	s.guard = nil
	return nil
}

func (s *testGuardStore) recoverCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveries
}

type testRestorer struct{}

func (testRestorer) RestoreLastKnownGood(context.Context, string) error { return nil }
func (testRestorer) ObserveLastKnownGood(context.Context, string) (bool, error) {
	return true, nil
}

func TestWatchdogNeverRollsBackUnexpiredLeaseAndDoesNotTreatIdleAsHealth(t *testing.T) {
	now := time.Now()
	store := &testGuardStore{}
	watcher, err := New(store, testRestorer{}, 10*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := watcher.Check(context.Background(), now)
	if err != nil || result != Idle {
		t.Fatalf("no active lease must be idle, not healthy or recovered: %q %v", result, err)
	}
	store.guard = &state.ActivationGuard{
		StructuralSequence: 2,
		Deadline: now.Add(time.Minute),
	}
	result, err = watcher.Check(context.Background(), now)
	if err != nil || result != Armed || store.recoverCount() != 0 {
		t.Fatalf("unexpired commit-confirm lease must not be interrupted: %q %v, restorations=%d", result, err, store.recoverCount())
	}
}

func TestWatchdogRollsBackExpiredLeaseAndRetriesUntilObservedRecovery(t *testing.T) {
	now := time.Now()
	store := &testGuardStore{
		guard: &state.ActivationGuard{
			StructuralSequence: 2,
			Deadline: now.Add(-time.Second),
		},
		recoveryErr: errors.New("health witness unavailable"),
	}
	watcher, err := New(store, testRestorer{}, 10*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := watcher.Check(context.Background(), now)
	if err == nil || result != RecoveryRequired || store.recoverCount() != 1 {
		t.Fatalf("recovery failure must leave a retry requirement: %q %v", result, err)
	}
	if store.guard == nil {
		t.Fatal("unobserved rollback cleared its durable lease")
	}
	store.recoveryErr = nil
	result, err = watcher.Check(context.Background(), now)
	if err != nil || result != Recovered || store.recoverCount() != 2 {
		t.Fatalf("verified rollback was not retried: %q %v", result, err)
	}
	result, err = watcher.Check(context.Background(), now)
	if err != nil || result != Idle || store.recoverCount() != 2 {
		t.Fatal("watchdog must not trigger a repeated restore after confirmed recovery")
	}
}

func TestWatchdogRunRetriesAcrossFailuresAndStopsOnShutdown(t *testing.T) {
	store := &testGuardStore{
		guard: &state.ActivationGuard{
			StructuralSequence: 3,
			Deadline: time.Now().Add(-time.Second),
		},
		recoveryErr: errors.New("supervisor temporarily unavailable"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failed := 0
	healthy := false
	watcher, err := New(store, testRestorer{}, 10*time.Millisecond, func(outcome Result, failure error) {
		if outcome == RecoveryRequired && failure != nil {
			failed++
			if failed == 2 {
				store.mu.Lock()
				store.recoveryErr = nil
				store.mu.Unlock()
			}
		}
		if outcome == Recovered {
			healthy = true
			cancel()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Run(ctx); err != nil {
		t.Fatalf("graceful shutdown must not turn a recovery retry into success or failure: %v", err)
	}
	if failed < 2 || !healthy || store.recoverCount() < 3 {
		t.Fatalf("watchdog did not retry and recover across failed checks: failures=%d recovered=%t attempts=%d", failed, healthy, store.recoverCount())
	}
}

func TestWatchdogRejectsMissingDependenciesAndInvalidSchedule(t *testing.T) {
	store := &testGuardStore{}
	for _, tc := range []struct {
		name string
		store GuardStore
		op state.RecoveryOperator
		interval time.Duration
	}{
		{"nil journal", nil, testRestorer{}, time.Second},
		{"nil supervisor", store, nil, time.Second},
		{"zero period", store, testRestorer{}, 0},
		{"fast busy-spin", store, testRestorer{}, time.Nanosecond},
		{"unbounded interval", store, testRestorer{}, 2*time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.store, tc.op, tc.interval, nil); err == nil {
				t.Fatal("unsafe watchdog configuration accepted")
			}
		})
	}
	watcher, err := New(store, testRestorer{}, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := watcher.Check(ctx, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled watchdog operation must not touch journal: %v", err)
	}
	if err := watcher.Run(ctx); err != nil {
		t.Fatalf("cancelled watchdog runner must exit cleanly: %v", err)
	}
}

func TestWatchdogReadErrorsNeverCountAsRecovery(t *testing.T) {
	store := &testGuardStore{readErr: errors.New("SQLite unavailable")}
	watcher, err := New(store, testRestorer{}, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := watcher.Check(context.Background(), time.Now())
	if err == nil || result != RecoveryRequired || store.recoverCount() != 0 {
		t.Fatalf("journal read failure cannot be treated as a clean no-change: %q %v", result, err)
	}
}
