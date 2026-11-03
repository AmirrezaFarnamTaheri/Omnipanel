package sessions

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func newAuthorizedRegistry(t *testing.T, entitlements map[string]uint64) *Registry {
	t.Helper()
	registry := NewRegistry()
	if _, err := registry.ReconcileEntitlements(entitlements); err != nil {
		t.Fatalf("initialize entitlements: %v", err)
	}
	return registry
}

func TestRegisterRequiresAnActiveEndpointPrincipalAndCredentialGeneration(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register("session-a", "principal-a", 1, nil); !errors.Is(err, ErrPrincipalNotAuthorized) {
		t.Fatalf("expected unauthorized principal, got %v", err)
	}
	if _, err := registry.ReconcileEntitlements(map[string]uint64{"principal-a": 1}); err != nil { t.Fatal(err) }
	if err := registry.Register("", "principal-a", 1, nil); !errors.Is(err, ErrInvalidSession) { t.Fatalf("expected invalid session error, got %v", err) }
	if err := registry.Register("session-a", "", 1, nil); !errors.Is(err, ErrInvalidSession) { t.Fatalf("expected invalid session error, got %v", err) }
	if err := registry.Register("session-a", "principal-a", 0, nil); !errors.Is(err, ErrInvalidSession) { t.Fatalf("expected invalid session error, got %v", err) }
	if err := registry.Register("session-a", "principal-a", 1, nil); err != nil { t.Fatal(err) }
	if err := registry.Register("session-a", "principal-a", 1, nil); !errors.Is(err, ErrSessionExists) { t.Fatalf("expected duplicate session error, got %v", err) }
}

func TestRevokingPrincipalClosesAndRemovesTrackedSessions(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	closed := 0
	if err := registry.Register("session-a", "principal-a", 1, closerFunc(func() error { closed++; return nil })); err != nil { t.Fatal(err) }
	report, err := registry.ReconcileEntitlements(map[string]uint64{})
	if err != nil { t.Fatal(err) }
	if report.Blocked != 1 || report.Closed != 1 || report.Unclosable != 0 || len(report.CloseFailures) != 0 { t.Fatalf("unexpected revocation report: %+v", report) }
	if closed != 1 { t.Fatalf("closer called %d times, want 1", closed) }
	if registry.CanRoute("session-a") { t.Fatal("revoked session remains routable") }
	if got := registry.Snapshot(); len(got) != 0 { t.Fatalf("closed session should be removed: %+v", got) }
}

func TestSessionWithoutCloserIsMutedButNotReportedAsClosed(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	if err := registry.Register("session-a", "principal-a", 1, nil); err != nil { t.Fatal(err) }
	report, err := registry.ReconcileEntitlements(nil)
	if err != nil { t.Fatal(err) }
	if report.Blocked != 1 || report.Closed != 0 || report.Unclosable != 1 { t.Fatalf("unexpected report for session without a closer: %+v", report) }
	if registry.CanRoute("session-a") { t.Fatal("muted session opened another routed flow") }
	snapshot := registry.Snapshot()
	if len(snapshot) != 1 || !snapshot[0].Blocked || snapshot[0].HasCloser { t.Fatalf("expected a blocked, unclosable session to remain diagnosable: %+v", snapshot) }
}

func TestCloseFailureLeavesSessionBlocked(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	closeErr := errors.New("runtime close failed")
	if err := registry.Register("session-a", "principal-a", 1, closerFunc(func() error { return closeErr })); err != nil { t.Fatal(err) }
	report, err := registry.ReconcileEntitlements(nil)
	if err != nil { t.Fatal(err) }
	if report.Blocked != 1 || report.Closed != 0 || len(report.CloseFailures) != 1 { t.Fatalf("unexpected close failure report: %+v", report) }
	if !errors.Is(report.CloseFailures[0].Err, closeErr) { t.Fatalf("close error was not preserved: %+v", report.CloseFailures[0]) }
	if registry.CanRoute("session-a") { t.Fatal("session with failed close was allowed to route") }
}

func TestCredentialGenerationChangeRevokesStaleSessions(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	if err := registry.Register("old-session", "principal-a", 1, nil); err != nil { t.Fatal(err) }
	report, err := registry.ReconcileEntitlements(map[string]uint64{"principal-a": 2})
	if err != nil { t.Fatal(err) }
	if report.Blocked != 1 || report.Unclosable != 1 { t.Fatalf("credential rotation did not revoke the stale session: %+v", report) }
	if registry.CanRoute("old-session") { t.Fatal("session authenticated with the old credential generation remains routable") }
	if err := registry.Register("new-session", "principal-a", 2, nil); err != nil { t.Fatalf("new credential generation should be accepted: %v", err) }
}

func TestDisconnectPrincipalDoesNotRevokeFutureAuthentication(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	if err := registry.Register("session-a", "principal-a", 1, nil); err != nil { t.Fatal(err) }
	report, err := registry.DisconnectPrincipal("principal-a")
	if err != nil { t.Fatal(err) }
	if report.Blocked != 1 || report.Unclosable != 1 { t.Fatalf("unexpected disconnect report: %+v", report) }
	if registry.CanRoute("session-a") { t.Fatal("disconnected existing session remains routable") }
	if err := registry.Register("session-b", "principal-a", 1, nil); err != nil { t.Fatalf("disconnect must not revoke a still-authorized principal: %v", err) }
	if !registry.CanRoute("session-b") { t.Fatal("fresh session for an authorized principal should route") }
}

func TestRevokedSessionNeverRevivesWhenEntitlementReturns(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	if err := registry.Register("session-a", "principal-a", 1, nil); err != nil { t.Fatal(err) }
	if _, err := registry.ReconcileEntitlements(nil); err != nil { t.Fatal(err) }
	if _, err := registry.ReconcileEntitlements(map[string]uint64{"principal-a": 1}); err != nil { t.Fatal(err) }
	if registry.CanRoute("session-a") { t.Fatal("a previously revoked session must not revive") }
}

func TestCloserMayUnregisterSessionWithoutDeadlocking(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	closed := make(chan struct{})
	if err := registry.Register("session-a", "principal-a", 1, closerFunc(func() error { registry.Unregister("session-a"); close(closed); return nil })); err != nil { t.Fatal(err) }
	done := make(chan struct{})
	go func() { _, _ = registry.ReconcileEntitlements(nil); close(done) }()
	select { case <-closed: case <-time.After(time.Second): t.Fatal("closer could not re-enter registry; lock was held while closing") }
	select { case <-done: case <-time.After(time.Second): t.Fatal("revocation did not complete") }
}

func TestSnapshotIsStableAndSortedBySessionID(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	for _, id := range []string{"session-c", "session-a", "session-b"} { if err := registry.Register(id, "principal-a", 1, nil); err != nil { t.Fatal(err) } }
	first, second := registry.Snapshot(), registry.Snapshot()
	if len(first) != 3 || len(second) != 3 { t.Fatalf("unexpected snapshots: %+v / %+v", first, second) }
	for i, id := range []string{"session-a", "session-b", "session-c"} { if first[i].ID != id || second[i].ID != id { t.Fatalf("snapshots are not stably sorted: %+v / %+v", first, second) } }
}

func TestInvalidEntitlementSnapshotDoesNotReplaceCurrentState(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	if err := registry.Register("session-a", "principal-a", 1, nil); err != nil { t.Fatal(err) }
	if _, err := registry.ReconcileEntitlements(map[string]uint64{"principal-a": 0}); !errors.Is(err, ErrInvalidEntitlement) { t.Fatalf("expected invalid entitlement error, got %v", err) }
	if !registry.CanRoute("session-a") { t.Fatal("invalid entitlement update changed the current authorization state") }
}

func TestConcurrentSessionChecksAndMembershipReconciliation(t *testing.T) {
	registry := newAuthorizedRegistry(t, map[string]uint64{"principal-a": 1})
	for i := 0; i < 32; i++ { if err := registry.Register(string(rune('a'+i)), "principal-a", 1, nil); err != nil { t.Fatal(err) } }
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				id := string(rune('a' + iteration%32))
				registry.CanRoute(id)
				registry.Touch(id)
				if worker == 0 && iteration%10 == 0 {
					if iteration%20 == 0 { _, _ = registry.ReconcileEntitlements(map[string]uint64{"principal-a": 1}) } else { _, _ = registry.ReconcileEntitlements(nil) }
				}
				_ = registry.Snapshot()
			}
		}(worker)
	}
	wait.Wait()
}
