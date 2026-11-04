package metering

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
)

// CheckpointStore is the protected node-local persistence boundary exposed by
// internal/agent/state.Store. A checkpoint is bounded, versioned JSON and must
// remain private; it contains counters and generation metadata, not secrets.
type CheckpointStore interface {
	LoadMeteringCheckpoint(context.Context) ([]byte, error)
	SaveMeteringCheckpoint(context.Context, []byte) error
}

const checkpointVersion = 1

// MaxCheckpointBytes matches the bound enforced by the protected node journal.
const MaxCheckpointBytes = state.MaxMeteringCheckpointBytes

type checkpoint struct {
	Version int              `json:"version"`
	Users   []checkpointUser `json:"users"`
}

type checkpointUser struct {
	User       string   `json:"user"`
	Generation uint64   `json:"generation"`
	Seq        uint64   `json:"seq"`
	Last       Counters `json:"last"`
	Total      Usage    `json:"total"`
	Dirty      bool     `json:"dirty"`
}

// OpenDurable rehydrates a generation-aware accumulator from the protected
// node journal. A missing checkpoint starts empty; malformed, oversized or
// over-capacity checkpoints fail closed rather than resetting accounting.
func OpenDurable(ctx context.Context, store CheckpointStore) (*Accumulator, error) {
	if store == nil {
		return nil, ErrInvalidSample
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	payload, err := store.LoadMeteringCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("load durable metering state: %w", err)
	}
	a := New()
	a.checkpointStore = store
	if len(payload) == 0 {
		return a, nil
	}
	if len(payload) > MaxCheckpointBytes {
		return nil, fmt.Errorf("%w: checkpoint exceeds size bound", ErrInvalidSample)
	}
	var saved checkpoint
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&saved); err != nil {
		return nil, fmt.Errorf("%w: malformed checkpoint: %v", ErrInvalidSample, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing checkpoint data", ErrInvalidSample)
	}
	if saved.Version != checkpointVersion || len(saved.Users) > MaxTrackedUsers {
		return nil, fmt.Errorf("%w: unsupported version or user count", ErrInvalidSample)
	}
	for _, item := range saved.Users {
		if item.User == "" || len(item.User) > maxUserTagBytes ||
			item.Total.Uplink < item.Last.Uplink || item.Total.Downlink < item.Last.Downlink {
			return nil, fmt.Errorf("%w: invalid checkpoint user or counter relationship", ErrInvalidSample)
		}
		if _, exists := a.users[item.User]; exists {
			return nil, fmt.Errorf("%w: duplicate checkpoint user", ErrInvalidSample)
		}
		state := &userState{
			generation: item.Generation,
			seq:        item.Seq,
			last:       item.Last,
			total:      item.Total,
			dirty:      item.Dirty,
		}
		a.users[item.User] = state
		if state.dirty {
			a.pendingUsers++
		}
	}
	if a.pendingUsers > MaxPendingUsers {
		return nil, fmt.Errorf("%w: pending user count exceeds bound", ErrInvalidSample)
	}
	return a, nil
}

// AcceptDurable persists a drain observation before reporting success to the
// caller. If persistence fails, it rolls the in-memory mutation back so the
// caller can retry the destructive runtime drain without acknowledging it.
func (a *Accumulator) AcceptDurable(ctx context.Context, sample Sample) error {
	if a == nil {
		return ErrInvalidSample
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.checkpointStore == nil {
		return ErrDurableMode
	}
	before, pendingBefore := cloneUsers(a.users)
	if err := a.acceptLocked(sample); err != nil {
		return err
	}
	payload, err := a.marshalLocked()
	if err == nil {
		err = a.checkpointStore.SaveMeteringCheckpoint(ctx, payload)
	}
	if err != nil {
		a.users, a.pendingUsers = before, pendingBefore
		return fmt.Errorf("persist drained metering sample: %w", err)
	}
	return nil
}

// FlushDurable delivers absolute totals, then checkpoints the clean state.
// If the checkpoint write fails after delivery, the pending totals are kept
// dirty in memory and on disk; retries are safe only with an idempotent
// absolute-total upsert at the destination. This is at-least-once foundation
// behavior, not a cross-database atomic transaction or a billing service.
func (a *Accumulator) FlushDurable(ctx context.Context, commit func(map[string]Usage) error) error {
	if a == nil || commit == nil {
		return ErrInvalidSample
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.checkpointStore == nil {
		return ErrDurableMode
	}
	if a.pendingUsers == 0 {
		return nil
	}
	batch := make(map[string]Usage, a.pendingUsers)
	for user, item := range a.users {
		if item.dirty {
			batch[user] = item.total
		}
	}
	if err := commit(batch); err != nil {
		return fmt.Errorf("commit metering outbox: %w", err)
	}
	for user := range batch {
		a.users[user].dirty = false
	}
	pendingBefore := a.pendingUsers
	a.pendingUsers = 0
	payload, err := a.marshalLocked()
	if err == nil {
		err = a.checkpointStore.SaveMeteringCheckpoint(ctx, payload)
	}
	if err != nil {
		for user := range batch {
			a.users[user].dirty = true
		}
		a.pendingUsers = pendingBefore
		return fmt.Errorf("checkpoint delivered metering totals: %w", err)
	}
	return nil
}

func cloneUsers(in map[string]*userState) (map[string]*userState, int) {
	out := make(map[string]*userState, len(in))
	pending := 0
	for user, item := range in {
		copy := *item
		out[user] = &copy
		if copy.dirty {
			pending++
		}
	}
	return out, pending
}

func (a *Accumulator) marshalLocked() ([]byte, error) {
	items := make([]checkpointUser, 0, len(a.users))
	for user, item := range a.users {
		items = append(items, checkpointUser{
			User: user, Generation: item.generation, Seq: item.seq,
			Last: item.last, Total: item.total, Dirty: item.dirty,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].User < items[j].User })
	payload, err := json.Marshal(checkpoint{Version: checkpointVersion, Users: items})
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > MaxCheckpointBytes {
		return nil, errors.New("metering checkpoint size exceeds bound")
	}
	return payload, nil
}
