// Package reconcile connects an authenticated, agent-initiated desired-state
// pull to the signature verifier and persistent journal. It never changes hosts.
package reconcile

import (
	"context"
	"errors"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

type Outcome string

const (
	PendingApplication Outcome = "pending_application"
	AlreadyApplied     Outcome = "already_applied"
)

type Report struct {
	Outcome            Outcome
	StructuralSequence uint64
	MembershipSequence uint64
	Digest             string
	NewlyRecorded      bool
}

// AuthenticatedPuller must already enforce authenticated node-scoped transport.
// A mock implementation verifies orchestration, not real enrollment or mTLS.
type AuthenticatedPuller interface {
	FetchNodeDesired(context.Context, string) ([]byte, error)
}

type Processor struct {
	store    *state.Store
	verifier manifest.Verifier
}

var ErrNotImplemented = errors.New("verification-only node reconciler not implemented")

func New(store *state.Store, verifier manifest.Verifier) (*Processor, error) {
	if store == nil || verifier.NodeID == "" || verifier.AuthorizedEpoch == "" {
		return nil, errors.New("missing protected journal or authorized verifier")
	}
	return &Processor{store: store, verifier: verifier}, nil
}

func (*Processor) PollOnce(context.Context, AuthenticatedPuller) (Report, error) {
	return Report{}, ErrNotImplemented
}

func (*Processor) Process(context.Context, []byte) (Report, error) {
	return Report{}, ErrNotImplemented
}
