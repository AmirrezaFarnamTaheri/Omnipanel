package metering

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func sample(user string, generation, seq, up, down uint64) Sample {
	return Sample{User: user, Generation: generation, Seq: seq, Counters: Counters{Uplink: up, Downlink: down}}
}

func TestAccumulatorFoldsCumulativeCounters(t *testing.T) {
	a := New()
	// The first drain may arrive mid-generation: cumulative counters must
	// recover the traffic observed before the accumulator started watching.
	if err := a.Accept(sample("alice", 1, 5, 100, 200)); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(sample("alice", 1, 6, 150, 260)); err != nil {
		t.Fatal(err)
	}
	if got := a.Totals()["alice"]; got != (Usage{Uplink: 150, Downlink: 260}) {
		t.Fatalf("cumulative fold wrong: %+v", got)
	}
}

func TestAccumulatorReplayIsIdempotent(t *testing.T) {
	a := New()
	for _, s := range []Sample{sample("alice", 1, 1, 10, 20), sample("alice", 1, 2, 30, 40)} {
		if err := a.Accept(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []Sample{sample("alice", 1, 1, 10, 20), sample("alice", 1, 2, 30, 40), sample("alice", 1, 2, 999, 999)} {
		if err := a.Accept(s); err != nil {
			t.Fatalf("replayed drain rejected instead of ignored: %v", err)
		}
	}
	if got := a.Totals()["alice"]; got != (Usage{Uplink: 30, Downlink: 40}) {
		t.Fatalf("replay double counted: %+v", got)
	}
}

func TestAccumulatorRefusesStaleGeneration(t *testing.T) {
	a := New()
	if err := a.Accept(sample("alice", 7, 1, 10, 10)); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(sample("alice", 6, 99, 500, 500)); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("old process generation accepted: %v", err)
	}
	if got := a.Totals()["alice"]; got != (Usage{Uplink: 10, Downlink: 10}) {
		t.Fatalf("stale generation mutated totals: %+v", got)
	}
}

func TestAccumulatorGenerationRestartAddsAbsoluteCounters(t *testing.T) {
	a := New()
	if err := a.Accept(sample("alice", 1, 9, 100, 200)); err != nil {
		t.Fatal(err)
	}
	// New process generation: counters restart from zero; the whole
	// observation is the delta and the drain sequence may restart too.
	if err := a.Accept(sample("alice", 2, 1, 40, 60)); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(sample("alice", 2, 2, 50, 70)); err != nil {
		t.Fatal(err)
	}
	if got := a.Totals()["alice"]; got != (Usage{Uplink: 150, Downlink: 270}) {
		t.Fatalf("generation restart accounting wrong: %+v", got)
	}
}

func TestAccumulatorRefusesCounterRegression(t *testing.T) {
	a := New()
	if err := a.Accept(sample("alice", 1, 1, 100, 200)); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(sample("alice", 1, 2, 90, 300)); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("uplink regression accepted: %v", err)
	}
	if err := a.Accept(sample("alice", 1, 2, 100, 199)); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("downlink regression accepted: %v", err)
	}
	if got := a.Totals()["alice"]; got != (Usage{Uplink: 100, Downlink: 200}) {
		t.Fatalf("regression mutated totals: %+v", got)
	}
	// The refused sequence number must remain usable with honest counters.
	if err := a.Accept(sample("alice", 1, 2, 110, 210)); err != nil {
		t.Fatal(err)
	}
}

func TestAccumulatorFailedFlushRetainsAndFoldsTraffic(t *testing.T) {
	a := New()
	ctx := context.Background()
	if err := a.Accept(sample("alice", 1, 1, 100, 200)); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(sample("bob", 1, 1, 5, 6)); err != nil {
		t.Fatal(err)
	}
	failing := func(map[string]Usage) error { return errors.New("storage busy") }
	if err := a.Flush(ctx, failing); err == nil {
		t.Fatal("failed store reported success")
	}
	if a.PendingUsers() != 2 {
		t.Fatal("failed flush dropped the pending window")
	}
	// More traffic folds into the retained window instead of appending an
	// unbounded backlog of batches.
	if err := a.Accept(sample("alice", 1, 2, 150, 260)); err != nil {
		t.Fatal(err)
	}
	if a.PendingUsers() != 2 {
		t.Fatal("folding grew the pending window")
	}
	var delivered map[string]Usage
	if err := a.Flush(ctx, func(totals map[string]Usage) error {
		delivered = totals
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]Usage{"alice": {Uplink: 150, Downlink: 260}, "bob": {Uplink: 5, Downlink: 6}}
	if len(delivered) != len(want) {
		t.Fatalf("retry delivered wrong window: %+v", delivered)
	}
	for user, usage := range want {
		if delivered[user] != usage {
			t.Fatalf("retry lost or double counted %s: %+v", user, delivered[user])
		}
	}
	if a.PendingUsers() != 0 {
		t.Fatal("successful flush left traffic pending")
	}
	// Nothing new: the store must not be called again.
	if err := a.Flush(ctx, func(map[string]Usage) error { return errors.New("unexpected empty flush") }); err != nil {
		t.Fatal(err)
	}
}

func TestAccumulatorCapacityIsExplicit(t *testing.T) {
	a := New()
	for i := 0; i < MaxPendingUsers; i++ {
		if err := a.Accept(sample(fmt.Sprintf("user-%d", i), 1, 1, 1, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Accept(sample("overflow-user", 1, 1, 1, 1)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("pending window overflow accepted: %v", err)
	}
	// Existing users keep folding while the window is full.
	if err := a.Accept(sample("user-0", 1, 2, 2, 2)); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(context.Background(), func(map[string]Usage) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(sample("overflow-user", 1, 1, 1, 1)); err != nil {
		t.Fatalf("capacity not released after commit: %v", err)
	}
}

func TestAccumulatorBoundsRetainedReplayStateAfterFlush(t *testing.T) {
	a := New()
	ctx := context.Background()
	for i := 0; i < MaxTrackedUsers; i++ {
		if err := a.Accept(sample(fmt.Sprintf("user-%d", i), 1, 1, 1, 1)); err != nil {
			t.Fatalf("accepted user %d: %v", i, err)
		}
		if (i+1)%MaxPendingUsers == 0 {
			if err := a.Flush(ctx, func(map[string]Usage) error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := a.Accept(sample("one-too-many", 1, 1, 1, 1)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("retained replay-state capacity was not bounded: %v", err)
	}
	if len(a.Totals()) != MaxTrackedUsers {
		t.Fatal("capacity refusal changed tracked user state")
	}
}

func TestAccumulatorRefusesOverflowAndInvalidTags(t *testing.T) {
	a := New()
	max := ^uint64(0)
	if err := a.Accept(sample("alice", 1, 1, max, max)); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(sample("alice", 2, 1, 1, 1)); !errors.Is(err, ErrInvalidSample) {
		t.Fatalf("lifetime overflow accepted: %v", err)
	}
	if got := a.Totals()["alice"]; got != (Usage{Uplink: max, Downlink: max}) {
		t.Fatalf("overflow mutated totals: %+v", got)
	}
	for _, user := range []string{"", string(make([]byte, maxUserTagBytes+1))} {
		if err := a.Accept(sample(user, 1, 1, 1, 1)); !errors.Is(err, ErrInvalidSample) {
			t.Fatalf("invalid user tag accepted: %q", user)
		}
	}
}

func TestAccumulatorCanceledContextKeepsWindow(t *testing.T) {
	a := New()
	if err := a.Accept(sample("alice", 1, 1, 1, 1)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Flush(ctx, func(map[string]Usage) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled flush reported: %v", err)
	}
	if a.PendingUsers() != 1 {
		t.Fatal("canceled flush dropped traffic")
	}
}

func TestAccumulatorTotalsSnapshotIsIndependent(t *testing.T) {
	a := New()
	if err := a.Accept(sample("alice", 1, 1, 1, 1)); err != nil {
		t.Fatal(err)
	}
	snapshot := a.Totals()
	snapshot["alice"] = Usage{Uplink: 999, Downlink: 999}
	delete(snapshot, "alice")
	if got := a.Totals()["alice"]; got != (Usage{Uplink: 1, Downlink: 1}) {
		t.Fatalf("caller mutated accumulator state: %+v", got)
	}
}

func TestAccumulatorConcurrentDrainsAndFlushes(t *testing.T) {
	a := New()
	ctx := context.Background()
	const users, drains = 8, 200
	var wg sync.WaitGroup
	for u := 0; u < users; u++ {
		wg.Add(1)
		go func(u int) {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", u)
			for seq := 1; seq <= drains; seq++ {
				if err := a.Accept(sample(user, 1, uint64(seq), uint64(seq)*10, uint64(seq)*20)); err != nil {
					t.Errorf("concurrent accept: %v", err)
					return
				}
			}
		}(u)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := a.Flush(ctx, func(map[string]Usage) error { return nil }); err != nil {
				t.Errorf("concurrent flush: %v", err)
				return
			}
		}
	}()
	wg.Wait()
	if err := a.Flush(ctx, func(map[string]Usage) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for u := 0; u < users; u++ {
		want := Usage{Uplink: drains * 10, Downlink: drains * 20}
		if got := a.Totals()[fmt.Sprintf("user-%d", u)]; got != want {
			t.Fatalf("concurrent accounting lost traffic for user-%d: %+v want %+v", u, got, want)
		}
	}
	if a.PendingUsers() != 0 {
		t.Fatal("final flush left traffic pending")
	}
}
