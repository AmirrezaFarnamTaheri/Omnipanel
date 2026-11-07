package state

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

func withVerifiedRollbackBaseline(t *testing.T) (*Store, string, manifest.Verified, string) {
	t.Helper()
	path := filepath.Join(privateTestDir(t), "recovery.sqlite")
	s, err := Open(path, testNode, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	rev := testRevision()
	ctx := context.Background()
	if _, err := s.RecordReceived(ctx, rev); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(ctx, rev.Manifest.StructuralSequence, rev.Digest, Verified); err != nil {
		t.Fatal(err)
	}
	// Test-only seed: production MUST obtain LKG from an independently
	// verified bootstrapped runtime; no setter is exposed by this change.
	lkg := "sha256:" + strings.Repeat("b", 64)
	if _, err := s.db.ExecContext(ctx, "UPDATE node_scope SET last_good_ref=? WHERE singleton=1", lkg); err != nil {
		t.Fatal(err)
	}
	return s, path, rev, lkg
}

func TestActivationGuardRequiresVerifiedJournalAndTrustedKnownGood(t *testing.T) {
	ctx := context.Background()
	s, _, revision, _ := withVerifiedRollbackBaseline(t)
	defer s.Close()
	if _, err := s.db.Exec("UPDATE node_scope SET last_good_ref='' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveActivation(ctx, revision, strings.Repeat("c", 64), time.Now().Add(time.Minute)); err == nil {
		t.Fatal("activation without verified rollback baseline must be denied")
	}
	if _, err := s.db.Exec("UPDATE node_scope SET last_good_ref=? WHERE singleton=1", "sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE revisions SET stage='RECEIVED' WHERE structural=?", revision.Manifest.StructuralSequence); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveActivation(ctx, revision, strings.Repeat("c", 64), time.Now().Add(time.Minute)); err == nil {
		t.Fatal("received-only intent must not authorize an activation")
	}
	if _, err := s.db.Exec("UPDATE revisions SET stage='VERIFIED' WHERE structural=?", revision.Manifest.StructuralSequence); err != nil {
		t.Fatal(err)
	}
	lease, err := s.ReserveActivation(ctx, revision, strings.Repeat("c", 64), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if lease.StructuralSequence != revision.Manifest.StructuralSequence ||
		lease.MembershipSequence != revision.Manifest.MembershipSequence ||
		lease.ManifestDigest != revision.Digest ||
		lease.CandidateDigest != strings.Repeat("c", 64) ||
		lease.RollbackRef != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("guard must bind exact verified revision and LKG: %+v", lease)
	}
	cursor, err := s.Cursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.StructuralSequence != 0 || cursor.MembershipSequence != 0 || cursor.Digest != "" {
		t.Fatalf("a reserved activation is not an applied acknowledgment: %+v", cursor)
	}
}

func TestUnconfirmedActivationSurvivesCrashAndRefusesReplacement(t *testing.T) {
	ctx := context.Background()
	s, path, rev, rollback := withVerifiedRollbackBaseline(t)
	lease, err := s.ReserveActivation(ctx, rev, strings.Repeat("c", 64), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testNode, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.UnconfirmedActivation(ctx)
	if err != nil || pending == nil {
		t.Fatalf("a process crash must leave a durable recovery guard: %+v %v", pending, err)
	}
	if pending.StructuralSequence != lease.StructuralSequence ||
		pending.ManifestDigest != lease.ManifestDigest ||
		pending.CandidateDigest != lease.CandidateDigest ||
		pending.RollbackRef != rollback ||
		!pending.Deadline.Equal(lease.Deadline) {
		t.Fatalf("rollback lease changed after process restart: want=%+v got=%+v", lease, pending)
	}
	if _, err := reopened.ReserveActivation(ctx, rev, strings.Repeat("d", 64), time.Now().Add(90*time.Second)); err == nil {
		t.Fatal("a second candidate must never replace or extend unconfirmed rollback")
	}
	unchanged, err := reopened.UnconfirmedActivation(ctx)
	if err != nil || *unchanged != *pending {
		t.Fatalf("refused replacement changed recovery guard: %+v %v", unchanged, err)
	}
}

func TestActivationGuardRejectsAmbiguousDigestsReplaysAndDeadlines(t *testing.T) {
	ctx := context.Background()
	s, _, rev, _ := withVerifiedRollbackBaseline(t)
	defer s.Close()
	cases := []struct {
		name string
		modify func(*manifest.Verified, *string, *time.Time)
	}{
		{"wrong manifest digest", func(v *manifest.Verified, _ *string, _ *time.Time) { v.Digest = strings.Repeat("d", 64) }},
		{"wrong membership", func(v *manifest.Verified, _ *string, _ *time.Time) { v.Manifest.MembershipSequence++ }},
		{"wrong structural", func(v *manifest.Verified, _ *string, _ *time.Time) { v.Manifest.StructuralSequence++ }},
		{"wrong node", func(v *manifest.Verified, _ *string, _ *time.Time) { v.Manifest.NodeID = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc" }},
		{"wrong epoch", func(v *manifest.Verified, _ *string, _ *time.Time) { v.Manifest.ControlPlaneEpoch = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc" }},
		{"unverified decision", func(v *manifest.Verified, _ *string, _ *time.Time) { v.Decision = "" }},
		{"candidate path not digest", func(_ *manifest.Verified, d *string, _ *time.Time) { *d = "../root/config.json" }},
		{"expired deadline", func(_ *manifest.Verified, _ *string, d *time.Time) { *d = time.Now().Add(-time.Second) }},
		{"far future deadline", func(_ *manifest.Verified, _ *string, d *time.Time) { *d = time.Now().Add(time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := rev
			digest := strings.Repeat("c", 64)
			deadline := time.Now().Add(time.Minute)
			tc.modify(&v, &digest, &deadline)
			if _, err := s.ReserveActivation(ctx, v, digest, deadline); err == nil {
				t.Fatal("unverified or unbounded activation must be refused")
			}
			active, err := s.UnconfirmedActivation(ctx)
			if err != nil || active != nil {
				t.Fatalf("invalid request must not leave an activation guard: %+v %v", active, err)
			}
		})
	}
}

type fakeRestorer struct {
	mu sync.Mutex
	refs []string
	checks []string
	restoreErr error
	observeErr error
	healthy bool
}

func (f *fakeRestorer) RestoreLastKnownGood(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refs = append(f.refs, ref)
	return f.restoreErr
}

func (f *fakeRestorer) ObserveLastKnownGood(_ context.Context, ref string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, ref)
	return f.healthy, f.observeErr
}

func TestRecoveryRequiresRestoredHealthBeforeClearingGuard(t *testing.T) {
	ctx := context.Background()
	s, _, rev, rollback := withVerifiedRollbackBaseline(t)
	defer s.Close()
	if _, err := s.ReserveActivation(ctx, rev, strings.Repeat("c", 64), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverActivation(ctx, nil); err == nil {
		t.Fatal("no recovery operator cannot dismiss a pending rollback")
	}
	op := &fakeRestorer{restoreErr: errors.New("supervisor unavailable")}
	if err := s.RecoverActivation(ctx, op); err == nil {
		t.Fatal("failed LKG restoration cannot release guard")
	}
	pending, err := s.UnconfirmedActivation(ctx)
	if err != nil || pending == nil {
		t.Fatalf("failed restoration lost rollback guard: %+v %v", pending, err)
	}
	op.restoreErr = nil
	if err := s.RecoverActivation(ctx, op); err == nil {
		t.Fatal("restore without observed healthy generation cannot release guard")
	}
	op.observeErr = errors.New("health observer unavailable")
	if err := s.RecoverActivation(ctx, op); err == nil {
		t.Fatal("observer transport failure cannot release guard")
	}
	op.observeErr = nil
	op.healthy = true
	if err := s.RecoverActivation(ctx, op); err != nil {
		t.Fatalf("observed recovered LKG must clear guard: %v", err)
	}
	pending, err = s.UnconfirmedActivation(ctx)
	if err != nil || pending != nil {
		t.Fatalf("recovery remained pending: %+v %v", pending, err)
	}
	if len(op.refs) != 4 || len(op.checks) != 3 {
		t.Fatalf("wrong recovery call ordering: restores=%v checks=%v", op.refs, op.checks)
	}
	for _, ref := range append(op.refs, op.checks...) {
		if ref != rollback {
			t.Fatalf("recovery requested a different runtime ref: %q", ref)
		}
	}
	if err := s.RecoverActivation(ctx, op); err != nil {
		t.Fatal(err)
	}
	if len(op.refs) != 4 {
		t.Fatal("cleared recovery guard triggered another restore")
	}
	cursor, err := s.Cursor(ctx)
	if err != nil || cursor.StructuralSequence != 0 || cursor.Digest != "" {
		t.Fatalf("recovery is not successful new revision application: %+v %v", cursor, err)
	}
}

func TestConcurrentActivationReservationsCannotBothWin(t *testing.T) {
	ctx := context.Background()
	s, _, rev, _ := withVerifiedRollbackBaseline(t)
	defer s.Close()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ReserveActivation(ctx, rev, strings.Repeat("c", 64), time.Now().Add(time.Minute))
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes, rejected := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			rejected++
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("only one unconfirmed activation lease may exist: success=%d rejected=%d", successes, rejected)
	}
}
