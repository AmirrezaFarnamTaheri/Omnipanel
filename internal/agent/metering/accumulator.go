// Package metering implements a bounded, fail-closed traffic counter
// accumulator for the node agent. It supports protected local checkpoint and
// at-least-once absolute-total delivery, but is NOT a billing-grade meter:
// native runtime wiring and authoritative remote accounting remain blocked.
//
// Design inputs (studied, not copied) from the S-UI stats service at pinned
// revision 19302d1 (see docs/research/four-panel-integration-assessment.md):
//
//   - A destructive runtime counter drain must never lose traffic when the
//     storage commit fails. Uncommitted observations are retained and folded
//     into the next attempt instead of being dropped.
//   - Retention must stay bounded: repeated failed commits fold per user
//     rather than appending unboundedly many pending batches.
//
// OmniPanel adds the fail-closed generation contract the panels lack:
// counters are cumulative within one runtime process generation, samples
// carry a strictly increasing drain sequence, replays are idempotent,
// stale generations and within-generation counter regressions are refused
// instead of silently guessed, and pending-window capacity is explicit.
// Flush delivers absolute per-user totals, so an idempotent upsert store
// can deduplicate at-least-once delivery across retries.
package metering

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrInvalidSample rejects malformed or overflowing observations.
	ErrInvalidSample = errors.New("invalid metering sample")
	// ErrStaleGeneration rejects a sample from an older runtime process
	// generation than already accepted for the user.
	ErrStaleGeneration = errors.New("stale runtime generation sample")
	// ErrCounterRegression rejects counters that moved backwards inside one
	// generation. A runtime restart must bump the generation, not reset
	// counters under the old one.
	ErrCounterRegression = errors.New("runtime counter regression within generation")
	// ErrCapacity rejects a NEW user when the uncommitted window is full.
	// Existing users keep folding; traffic is never silently discarded.
	ErrCapacity = errors.New("metering pending window capacity exceeded")
	// ErrDurableMode prevents callers from bypassing checkpoint-before-ack
	// semantics when an accumulator was opened from durable storage.
	ErrDurableMode = errors.New("durable accumulator requires durable operations")
)

// MaxPendingUsers bounds distinct users with uncommitted traffic, while
// MaxTrackedUsers also bounds retained generation/replay state after flush.
// Overflow is an explicit operator-visible error, not a silent drop.
const (
	MaxPendingUsers = 4096
	MaxTrackedUsers = 8192
)

// maxUserTagBytes bounds a runtime user tag; the verifier, not this package,
// decides which tags are authorized members.
const maxUserTagBytes = 128

// Counters are cumulative within one runtime process generation. The first
// accepted sample of a generation therefore also recovers traffic observed
// before this accumulator started watching that generation.
type Counters struct {
	Uplink   uint64
	Downlink uint64
}

// Sample is one drained observation for one user. Generation identifies the
// runtime process (counters start at zero each generation); Seq is the
// strictly increasing drain sequence within that generation.
type Sample struct {
	User       string
	Generation uint64
	Seq        uint64
	Counters   Counters
}

// Usage is the absolute accumulated traffic for one user across generations.
type Usage struct {
	Uplink   uint64
	Downlink uint64
}

type userState struct {
	generation uint64
	seq        uint64
	last       Counters
	total      Usage
	dirty      bool
}

// Accumulator folds drained samples into per-user totals and hands absolute
// totals to a store. It is safe for concurrent use. The zero value is not
// usable; call New.
type Accumulator struct {
	mu              sync.Mutex
	users           map[string]*userState
	pendingUsers    int
	checkpointStore CheckpointStore
}

func New() *Accumulator {
	return &Accumulator{users: make(map[string]*userState)}
}

// Accept folds one sample. Duplicate or replayed drain sequences within the
// current generation are idempotent no-ops. Stale generations, counter
// regressions, malformed tags and capacity overflow return errors and never
// mutate state.
func (a *Accumulator) Accept(s Sample) error {
	if a == nil {
		return ErrInvalidSample
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.checkpointStore != nil {
		return ErrDurableMode
	}
	return a.acceptLocked(s)
}

func (a *Accumulator) acceptLocked(s Sample) error {
	if s.User == "" || len(s.User) > maxUserTagBytes {
		return ErrInvalidSample
	}
	state, seen := a.users[s.User]
	if !seen {
		if a.pendingUsers >= MaxPendingUsers || len(a.users) >= MaxTrackedUsers {
			return ErrCapacity
		}
		state = &userState{}
	}
	switch {
	case seen && s.Generation < state.generation:
		return ErrStaleGeneration
	case seen && s.Generation == state.generation:
		if s.Seq <= state.seq {
			// At-least-once drain delivery: replays change nothing.
			return nil
		}
		if s.Counters.Uplink < state.last.Uplink || s.Counters.Downlink < state.last.Downlink {
			return ErrCounterRegression
		}
		if err := addDelta(state, s.Counters.Uplink-state.last.Uplink, s.Counters.Downlink-state.last.Downlink); err != nil {
			return err
		}
	default:
		// First observation, or a newer generation whose counters restarted
		// from zero: the cumulative counters are the whole delta.
		if err := addDelta(state, s.Counters.Uplink, s.Counters.Downlink); err != nil {
			return err
		}
	}
	state.generation, state.seq, state.last = s.Generation, s.Seq, s.Counters
	if !seen {
		a.users[s.User] = state
	}
	if !state.dirty {
		state.dirty = true
		a.pendingUsers++
	}
	return nil
}

func addDelta(state *userState, up, down uint64) error {
	if up > ^uint64(0)-state.total.Uplink || down > ^uint64(0)-state.total.Downlink {
		return fmt.Errorf("%w: lifetime total would overflow", ErrInvalidSample)
	}
	state.total.Uplink += up
	state.total.Downlink += down
	return nil
}

// Flush hands the absolute totals of every user with uncommitted traffic to
// store and only then marks them committed. A failing store keeps the whole
// window pending; later Accepts fold into it and the next Flush retries with
// complete totals, so a bounded upsert store loses nothing and double counts
// nothing. The callback runs under the accumulator lock: it must be bounded
// and must not call back into the accumulator.
func (a *Accumulator) Flush(ctx context.Context, store func(totals map[string]Usage) error) error {
	if a == nil || store == nil {
		return ErrInvalidSample
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.checkpointStore != nil {
		return ErrDurableMode
	}
	if a.pendingUsers == 0 {
		return nil
	}
	batch := make(map[string]Usage, a.pendingUsers)
	for user, state := range a.users {
		if state.dirty {
			batch[user] = state.total
		}
	}
	if err := store(batch); err != nil {
		// Retain the folded window; nothing observed is dropped.
		return fmt.Errorf("commit metering window: %w", err)
	}
	for _, state := range a.users {
		state.dirty = false
	}
	a.pendingUsers = 0
	return nil
}

// Totals snapshots the accumulated usage for every known user, including
// traffic not yet committed by Flush. It is an observation aid, not the
// authoritative store.
func (a *Accumulator) Totals() map[string]Usage {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]Usage, len(a.users))
	for user, state := range a.users {
		out[user] = state.total
	}
	return out
}

// PendingUsers reports how many distinct users have uncommitted traffic.
func (a *Accumulator) PendingUsers() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pendingUsers
}
