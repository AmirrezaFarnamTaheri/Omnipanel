package metering

import (
	"context"
	"testing"
)

// A sequence is an immutable drain observation within a runtime generation.
// Treating two different totals for the *current* sequence as an idempotent
// replay hides a counter inconsistency from upstream accounting.
func TestAccumulatorRejectsConflictingCurrentSequenceReplay(t *testing.T) {
	a := New()
	original := sample("alice", 7, 12, 100, 200)
	if err := a.Accept(original); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(original); err != nil {
		t.Fatalf("exact retry should be idempotent: %v", err)
	}
	for _, conflicting := range []Sample{
		sample("alice", 7, 12, 101, 200),
		sample("alice", 7, 12, 100, 201),
		sample("alice", 7, 12, 99, 200),
	} {
		if err := a.Accept(conflicting); err == nil {
			t.Fatalf("divergent current-sequence replay accepted: %+v", conflicting)
		}
		if got := a.Totals()["alice"]; got != (Usage{Uplink: 100, Downlink: 200}) {
			t.Fatalf("conflict changed metering totals: %+v", got)
		}
	}
	// Earlier sequences are replay history: only the latest observation
	// has an exact counter digest retained for equality comparison.
	if err := a.Accept(sample("alice", 7, 11, 50, 100)); err != nil {
		t.Fatalf("older, already incorporated sequence rejected: %v", err)
	}
	if err := a.Accept(sample("alice", 7, 13, 120, 230)); err != nil {
		t.Fatalf("honest subsequent sequence blocked: %v", err)
	}
	if got := a.Totals()["alice"]; got != (Usage{Uplink: 120, Downlink: 230}) {
		t.Fatalf("subsequent sequence was not counted: %+v", got)
	}
}

func TestDurableAccumulatorRejectsConflictingReplayAfterRehydration(t *testing.T) {
	ctx := context.Background()
	store := &fakeCheckpointStore{}
	acc, err := OpenDurable(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	original := sample("alice", 9, 3, 50, 80)
	if err := acc.AcceptDurable(ctx, original); err != nil {
		t.Fatal(err)
	}
	acc, err = OpenDurable(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := acc.AcceptDurable(ctx, sample("alice", 9, 3, 60, 80)); err == nil {
		t.Fatal("conflicting last sequence accepted after checkpoint reload")
	}
	acc, err = OpenDurable(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if got := acc.Totals()["alice"]; got != (Usage{Uplink: 50, Downlink: 80}) {
		t.Fatalf("conflicting replay mutated persisted totals: %+v", got)
	}
}
