package metering

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
)

const (
	durableNode  = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	durableEpoch = "ea2429da-7540-4e40-ae70-38fd3f19794b"
)

func openMeteringJournal(t *testing.T, path string) *state.Store {
	t.Helper()
	store, err := state.Open(path, durableNode, durableEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestDurableAccumulatorRehydratesAndFlushesAbsoluteTotals(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.sqlite")
	journal := openMeteringJournal(t, path)
	acc, err := OpenDurable(ctx, journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := acc.Accept(sample("unpersisted", 4, 1, 1, 1)); !errors.Is(err, ErrDurableMode) {
		t.Fatalf("durable accumulator allowed an uncheckpointed drain: %v", err)
	}
	if err := acc.Flush(ctx, func(map[string]Usage) error { return nil }); !errors.Is(err, ErrDurableMode) {
		t.Fatalf("durable accumulator allowed a non-durable flush: %v", err)
	}
	if err := acc.AcceptDurable(ctx, sample("alice", 4, 3, 100, 200)); err != nil {
		t.Fatal(err)
	}
	if err := acc.AcceptDurable(ctx, sample("alice", 4, 4, 130, 260)); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal = openMeteringJournal(t, path)
	defer journal.Close()
	recovered, err := OpenDurable(ctx, journal)
	if err != nil {
		t.Fatal(err)
	}
	if got := recovered.Totals()["alice"]; got != (Usage{Uplink: 130, Downlink: 260}) || recovered.PendingUsers() != 1 {
		t.Fatalf("checkpoint did not rehydrate dirty absolute totals: totals=%+v pending=%d", got, recovered.PendingUsers())
	}
	if err := recovered.FlushDurable(ctx, func(batch map[string]Usage) error {
		if len(batch) != 1 || batch["alice"] != (Usage{Uplink: 130, Downlink: 260}) {
			t.Fatalf("flush did not send absolute totals: %+v", batch)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal = openMeteringJournal(t, path)
	defer journal.Close()
	clean, err := OpenDurable(ctx, journal)
	if err != nil {
		t.Fatal(err)
	}
	if clean.PendingUsers() != 0 || clean.Totals()["alice"] != (Usage{Uplink: 130, Downlink: 260}) {
		t.Fatalf("clean checkpoint lost totals or resurrected delivery: %+v pending=%d", clean.Totals(), clean.PendingUsers())
	}
}

func TestDurableAcceptRollsBackMemoryWhenCheckpointFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.sqlite")
	journal := openMeteringJournal(t, path)
	acc, err := OpenDurable(ctx, journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := acc.AcceptDurable(ctx, sample("alice", 2, 1, 10, 20)); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := acc.AcceptDurable(ctx, sample("alice", 2, 2, 30, 40)); err == nil {
		t.Fatal("accepted destructive drain despite failed durable checkpoint")
	}
	if got := acc.Totals()["alice"]; got != (Usage{Uplink: 10, Downlink: 20}) {
		t.Fatalf("failed checkpoint changed in-memory accounting: %+v", got)
	}
	journal = openMeteringJournal(t, path)
	defer journal.Close()
	recovered, err := OpenDurable(ctx, journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.AcceptDurable(ctx, sample("alice", 2, 2, 30, 40)); err != nil {
		t.Fatalf("rolled-back drain was not retryable after storage recovery: %v", err)
	}
	if got := recovered.Totals()["alice"]; got != (Usage{Uplink: 30, Downlink: 40}) {
		t.Fatalf("retry did not fold the newly persisted drain: %+v", got)
	}
}

func TestDurableFlushFailureRetainsOutboxAcrossRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.sqlite")
	journal := openMeteringJournal(t, path)
	acc, err := OpenDurable(ctx, journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := acc.AcceptDurable(ctx, sample("bob", 1, 1, 55, 89)); err != nil {
		t.Fatal(err)
	}
	commitErr := errors.New("temporary destination failure")
	if err := acc.FlushDurable(ctx, func(map[string]Usage) error { return commitErr }); !errors.Is(err, commitErr) {
		t.Fatalf("flush failure not surfaced: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal = openMeteringJournal(t, path)
	defer journal.Close()
	recovered, err := OpenDurable(ctx, journal)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.PendingUsers() != 1 {
		t.Fatal("failed destination delivery was not durable across restart")
	}
	if err := recovered.FlushDurable(ctx, func(batch map[string]Usage) error {
		if batch["bob"] != (Usage{Uplink: 55, Downlink: 89}) {
			t.Fatalf("retry lost pending totals: %+v", batch)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type fakeCheckpointStore struct{ payload []byte }

func (f *fakeCheckpointStore) LoadMeteringCheckpoint(context.Context) ([]byte, error) {
	return f.payload, nil
}

func (f *fakeCheckpointStore) SaveMeteringCheckpoint(_ context.Context, payload []byte) error {
	f.payload = append([]byte(nil), payload...)
	return nil
}

func TestDurableOpenRejectsMalformedOrUnsupportedCheckpoint(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"version":2,"users":[]}`),
		[]byte(`{"version":1,"users":[{"user":"alice","generation":1,"seq":1,"last":{"Uplink":5,"Downlink":5},"total":{"Uplink":1,"Downlink":1},"dirty":true}]}`),
		[]byte(`{"version":1,"users":[]} trailing`),
	} {
		if _, err := OpenDurable(context.Background(), &fakeCheckpointStore{payload: payload}); err == nil {
			t.Fatalf("accepted malformed/unsupported checkpoint %q", payload)
		}
	}
}
