package state

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCandidateGuardBindingRequiresJournaledVerifiedIntentAndExactRollback(t *testing.T) {
	ctx := context.Background()
	store, _, revision, rollback := withVerifiedRollbackBaseline(t)
	defer store.Close()
	guard, err := store.ReserveActivation(ctx, revision, strings.Repeat("c", 64), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	binding := CandidateBinding{
		NodeID:             testNode,
		Epoch:              testEpoch,
		StructuralSequence: guard.StructuralSequence,
		MembershipSequence: guard.MembershipSequence,
		ManifestDigest:     guard.ManifestDigest,
		CandidateDigest:    guard.CandidateDigest,
		RollbackRef:        rollback,
	}
	if err := store.RequirePendingCandidate(ctx, binding); err != nil {
		t.Fatalf("exact verified pending candidate refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*CandidateBinding)
	}{
		{"node", func(b *CandidateBinding) { b.NodeID = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc" }},
		{"epoch", func(b *CandidateBinding) { b.Epoch = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc" }},
		{"structural sequence", func(b *CandidateBinding) { b.StructuralSequence++ }},
		{"membership sequence", func(b *CandidateBinding) { b.MembershipSequence++ }},
		{"manifest digest", func(b *CandidateBinding) { b.ManifestDigest = strings.Repeat("d", 64) }},
		{"candidate bytes", func(b *CandidateBinding) { b.CandidateDigest = strings.Repeat("d", 64) }},
		{"known-good rollback", func(b *CandidateBinding) { b.RollbackRef = "sha256:" + strings.Repeat("d", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrong := binding
			tc.change(&wrong)
			if err := store.RequirePendingCandidate(ctx, wrong); err == nil {
				t.Fatal("mismatched or cross-node witness scope authorized the rollback guard")
			}
		})
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE revisions SET stage='RECEIVED' WHERE epoch=? AND structural=?", testEpoch, guard.StructuralSequence); err != nil {
		t.Fatal(err)
	}
	if err := store.RequirePendingCandidate(ctx, binding); err == nil {
		t.Fatal("received-only intent was accepted after protected journal regression")
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE revisions SET stage='VERIFIED' WHERE epoch=? AND structural=?", testEpoch, guard.StructuralSequence); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE node_scope SET last_good_ref=? WHERE singleton=1", "sha256:"+strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.RequirePendingCandidate(ctx, binding); err == nil {
		t.Fatal("changed rollback baseline left a witness-eligible activation")
	}
}

func TestCandidateGuardBindingRequiresUnexpiredExclusiveGuardAndNeverAdvancesApplied(t *testing.T) {
	ctx := context.Background()
	store, _, revision, rollback := withVerifiedRollbackBaseline(t)
	defer store.Close()
	guard, err := store.ReserveActivation(ctx, revision, strings.Repeat("c", 64), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	binding := CandidateBinding{
		NodeID: testNode, Epoch: testEpoch,
		StructuralSequence: guard.StructuralSequence,
		MembershipSequence: guard.MembershipSequence,
		ManifestDigest: guard.ManifestDigest, CandidateDigest: guard.CandidateDigest,
		RollbackRef: rollback,
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE activation_guard SET deadline_ns=? WHERE singleton=1", time.Now().Add(-time.Second).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := store.RequirePendingCandidate(ctx, binding); err == nil {
		t.Fatal("expired watchdog lease still authorized a fresh external challenge")
	}
	if _, err := store.db.ExecContext(ctx, "DELETE FROM activation_guard WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RequirePendingCandidate(ctx, binding); err == nil {
		t.Fatal("cleared activation guard authorized an external witness")
	}
	cursor, err := store.Cursor(ctx)
	if err != nil || cursor.StructuralSequence != 0 || cursor.MembershipSequence != 0 || cursor.Digest != "" {
		t.Fatalf("witness gating must not mutate the applied cursor: %+v %v", cursor, err)
	}
}
