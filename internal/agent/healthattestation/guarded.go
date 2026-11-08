package healthattestation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/supervisoripc"
)

var ErrWitnessGuardUnavailable = errors.New("witness candidate host or durable recovery guard is not qualified")

// candidateGuardReader is implemented by the real protected node SQLite WAL.
// A test double only verifies orchestration; it is not trusted production state.
type candidateGuardReader interface {
	RequirePendingCandidate(context.Context, state.CandidateBinding) error
}

// candidateRootObserver is implemented by the UID-0-authenticated supervisor
// Unix client, not by an arbitrary client-selected HTTP endpoint.
type candidateRootObserver interface {
	ObserveApprovedCandidate(context.Context, string) (supervisoripc.CandidateObservation, error)
}

// GuardedVerifier binds cryptographic witness nonce issuance/consumption to
// a root-observed EXACT candidate and a matching live rollback lease. Neither
// a fabricated Accepted struct nor a raw DurableVerifier receipt may authorize
// an applied cursor; an independent reference client still must execute the
// actual external network suite and present reviewed transcript provenance.
type GuardedVerifier struct {
	verifier *DurableVerifier
	journal  candidateGuardReader
	root     candidateRootObserver
}

// NewGuardedVerifier is the production constructor. It deliberately requires
// concrete, separately trusted SQLite and rooted SO_PEERCRED client types.
// The package-private constructor exists only for deterministic unit tests.
func NewGuardedVerifier(verifier *DurableVerifier, journal *state.Store, root *supervisoripc.Client) (*GuardedVerifier, error) {
	if verifier == nil || journal == nil || root == nil {
		return nil, ErrWitnessGuardUnavailable
	}
	return newGuardedVerifier(verifier, journal, root)
}

func newGuardedVerifier(verifier *DurableVerifier, journal candidateGuardReader, root candidateRootObserver) (*GuardedVerifier, error) {
	if verifier == nil || verifier.db == nil || journal == nil || root == nil ||
		!verifier.cfg.Scope.valid() {
		return nil, ErrWitnessGuardUnavailable
	}
	return &GuardedVerifier{verifier: verifier, journal: journal, root: root}, nil
}

func (g *GuardedVerifier) requireLiveCandidate(ctx context.Context) error {
	if g == nil || g.verifier == nil || g.journal == nil || g.root == nil ||
		ctx == nil || ctx.Err() != nil {
		return ErrWitnessGuardUnavailable
	}
	scope := g.verifier.cfg.Scope
	observed, err := g.root.ObserveApprovedCandidate(ctx, scope.Generation)
	if err != nil || !observed.Healthy {
		return ErrWitnessGuardUnavailable
	}
	approval := observed.Approval
	now := time.Now()
	if approval.Reference != scope.Generation ||
		approval.NodeID != scope.NodeID || approval.Epoch != scope.Epoch ||
		approval.ManifestDigest != scope.ManifestDigest ||
		approval.StructuralSequence != scope.StructuralSequence ||
		approval.MembershipSequence != scope.MembershipSequence ||
		!witnessRefPattern.MatchString(approval.RollbackRef) ||
		approval.RollbackRef == approval.Reference ||
		approval.ExpiresUnix <= now.Unix() ||
		approval.ExpiresUnix > now.Add(2*time.Minute).Unix() {
		return ErrWitnessGuardUnavailable
	}
	binding := state.CandidateBinding{
		NodeID:             approval.NodeID,
		Epoch:              approval.Epoch,
		StructuralSequence: approval.StructuralSequence,
		MembershipSequence: approval.MembershipSequence,
		ManifestDigest:     approval.ManifestDigest,
		CandidateDigest:    strings.TrimPrefix(approval.Reference, "sha256:"),
		RollbackRef:        approval.RollbackRef,
	}
	if err := g.journal.RequirePendingCandidate(ctx, binding); err != nil {
		return ErrWitnessGuardUnavailable
	}
	return nil
}

// Issue requires an observed root-approved active candidate AND the exact
// VERIFIED WAL rollback lease before and after persisting an unpredictable
// nonce. A failure after issuance may leave an inert pending nonce; it never
// grants an applied state or ACK, and Verify will recheck eligibility.
func (g *GuardedVerifier) Issue(ctx context.Context) (Challenge, error) {
	if err := g.requireLiveCandidate(ctx); err != nil {
		return Challenge{}, err
	}
	challenge, err := g.verifier.Issue(ctx)
	if err != nil {
		return Challenge{}, err
	}
	if err := g.requireLiveCandidate(ctx); err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

// Verify checks the same root and WAL trust boundaries immediately before and
// after cryptographic verification/nonce consumption. If eligibility drops
// during verification, the nonce stays consumed and no Accepted result escapes.
// The two SQLite stores and independent root process are not an atomic commit:
// this is PRE-ACK evidence authentication, not a transactionally applied state.
func (g *GuardedVerifier) Verify(ctx context.Context, report []byte) (Accepted, error) {
	if err := g.requireLiveCandidate(ctx); err != nil {
		return Accepted{}, err
	}
	accepted, err := g.verifier.Verify(ctx, report)
	if err != nil {
		return Accepted{}, err
	}
	if err := g.requireLiveCandidate(ctx); err != nil {
		return Accepted{}, err
	}
	return accepted, nil
}
