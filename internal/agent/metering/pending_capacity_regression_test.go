package metering

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

// A clean, previously tracked user still consumes a pending slot when it
// receives new traffic. A full window must not silently grow past its bound.
func TestAccumulatorFullWindowRejectsCleanTrackedUser(t *testing.T) {
	a := New()
	if err := a.Accept(sample("previously-flushed", 1, 1, 4, 8)); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(context.Background(), func(map[string]Usage) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxPendingUsers; i++ {
		if err := a.Accept(sample(fmt.Sprintf("new-user-%d", i), 1, 1, 1, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if got := a.PendingUsers(); got != MaxPendingUsers {
		t.Fatalf("bad pending window setup: got %d", got)
	}
	if err := a.Accept(sample("previously-flushed", 1, 2, 5, 9)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("previously flushed user overflowed pending window: %v", err)
	}
	if got := a.PendingUsers(); got != MaxPendingUsers {
		t.Fatalf("rejected sample changed pending limit: got %d", got)
	}
	if got := a.Totals()["previously-flushed"]; got != (Usage{Uplink: 4, Downlink: 8}) {
		t.Fatalf("rejected sample mutated previously flushed totals: %+v", got)
	}
	// Releasing capacity must make the exact refused observation retryable.
	if err := a.Flush(context.Background(), func(map[string]Usage) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(sample("previously-flushed", 1, 2, 5, 9)); err != nil {
		t.Fatalf("capacity release did not permit retry: %v", err)
	}
}

func TestDurablePendingWindowCapacityRemainsRecoverable(t *testing.T) {
	ctx := context.Background()
	var items []checkpointUser
	items = append(items, checkpointUser{
		User: "previously-flushed", Generation: 1, Seq: 1,
		Last:  Counters{Uplink: 4, Downlink: 8},
		Total: Usage{Uplink: 4, Downlink: 8}, Dirty: false,
	})
	for i := 0; i < MaxPendingUsers; i++ {
		items = append(items, checkpointUser{
			User: fmt.Sprintf("new-user-%d", i), Generation: 1, Seq: 1,
			Last:  Counters{Uplink: 1, Downlink: 1},
			Total: Usage{Uplink: 1, Downlink: 1}, Dirty: true,
		})
	}
	payload, err := json.Marshal(checkpoint{Version: checkpointVersion, Users: items})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > MaxCheckpointBytes {
		t.Fatalf("fixture is larger than permitted checkpoint: %d", len(payload))
	}
	store := &fakeCheckpointStore{payload: payload}
	a, err := OpenDurable(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AcceptDurable(ctx, sample("previously-flushed", 1, 2, 5, 9)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("durable pending slot overflow was allowed: %v", err)
	}
	if got := a.PendingUsers(); got != MaxPendingUsers {
		t.Fatalf("durable pending slot count changed after refusal: got %d", got)
	}
	reopened, err := OpenDurable(ctx, store)
	if err != nil {
		t.Fatalf("previous checkpoint became unrecoverable: %v", err)
	}
	if got := reopened.PendingUsers(); got != MaxPendingUsers {
		t.Fatalf("recovered pending count changed: %d", got)
	}
	if got := reopened.Totals()["previously-flushed"]; got != (Usage{Uplink: 4, Downlink: 8}) {
		t.Fatalf("failed retry corrupted durable total: %+v", got)
	}
}
