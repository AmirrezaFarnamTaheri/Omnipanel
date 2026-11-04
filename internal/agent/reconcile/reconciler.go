// Package reconcile connects an authenticated, agent-initiated desired-state
// pull to the signature verifier and persistent journal. It never changes hosts.
package reconcile

import (
	"context"
	"errors"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/gateway"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

type Outcome string

const (
	PendingApplication Outcome = "pending_application"
	AlreadyApplied     Outcome = "already_applied"
	NoChange           Outcome = "no_change"
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
	FetchNodeDesired(context.Context, gateway.Request) ([]byte, error)
}

type Processor struct {
	store    *state.Store
	verifier manifest.Verifier
}

func New(store *state.Store, verifier manifest.Verifier) (*Processor, error) {
	if store == nil || verifier.NodeID == "" || verifier.AuthorizedEpoch == "" {
		return nil, errors.New("missing protected journal or authorized verifier")
	}
	return &Processor{store: store, verifier: verifier}, nil
}

// PollOnce is always initiated by the node. The supplied puller is an
// authenticated transport supplied by the caller; this package cannot claim
// enrollment or mTLS merely because the interface exists.
func (p *Processor) PollOnce(ctx context.Context, source AuthenticatedPuller) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if source == nil {
		return Report{}, errors.New("authenticated node puller is required")
	}
	// Poll with the durable *applied* cursors. A signed revision that is only
	// RECEIVED or VERIFIED in the journal must never masquerade as applied.
	cursor, err := p.store.Cursor(ctx)
	if err != nil {
		return Report{}, err
	}
	wire, err := source.FetchNodeDesired(ctx, gateway.Request{
		NodeID:             p.verifier.NodeID,
		ControlPlaneEpoch:  p.verifier.AuthorizedEpoch,
		StructuralSequence: cursor.StructuralSequence,
		MembershipSequence: cursor.MembershipSequence,
	})
	if errors.Is(err, gateway.ErrNoChange) {
		// A 204 is an authenticated no-change response, not applied or healthy.
		return Report{
			Outcome:            NoChange,
			StructuralSequence: cursor.StructuralSequence,
			MembershipSequence: cursor.MembershipSequence,
			Digest:             cursor.Digest,
		}, nil
	}
	if err != nil {
		return Report{}, err
	}
	return p.Process(ctx, wire)
}

// Process cryptographically verifies the signed envelope BEFORE journal writes.
// The journal's applied cursor stays unchanged until a separate native driver,
// health observer and commit-confirm mechanism can demonstrate actual success.
func (p *Processor) Process(ctx context.Context, envelope []byte) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	cursor, err := p.store.Cursor(ctx)
	if err != nil {
		return Report{}, err
	}
	verifier := p.verifier
	verifier.Current = cursor
	revision, err := verifier.Verify(envelope)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		StructuralSequence: revision.Manifest.StructuralSequence,
		MembershipSequence: revision.Manifest.MembershipSequence,
		Digest:             revision.Digest,
	}
	if revision.Decision == manifest.AlreadyApplied {
		report.Outcome = AlreadyApplied
		return report, nil
	}
	if revision.Decision != manifest.ApplyRevision {
		return Report{}, errors.New("unsupported signed revision decision")
	}
	added, err := p.store.RecordReceived(ctx, revision)
	if err != nil {
		return Report{}, err
	}
	if err := p.store.Transition(ctx, revision.Manifest.StructuralSequence, revision.Digest, state.Verified); err != nil {
		return Report{}, err
	}
	report.Outcome = PendingApplication
	report.NewlyRecorded = added
	return report, nil
}
