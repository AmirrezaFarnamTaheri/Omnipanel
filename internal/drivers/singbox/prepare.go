package singbox

import (
	"context"
	"errors"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

var ErrPreparationRejected = errors.New("Sing-box candidate preparation denied by trusted policy or rollback guard")

// PreparedActivation is a LOCAL, UNPRIVILEGED receipt proving that an exact
// policy-compiled full configuration passed the pinned native syntax check
// and that an exclusive recovery guard was committed in the SQLite WAL.
// This is not a root approval, host application, independent health result or
// applied ACK. Its private staging path must never be sent to a web API.
type PreparedActivation struct {
	Staged StagedConfig
	Guard  state.ActivationGuard
}

// PrepareActivation bridges existing separately tested boundaries, in order:
//
//   1. Consume one already-verified, node-scoped manifest revision and a
//      locally approved, typed egress policy, not arbitrary JSON from a caller.
//   2. Compile a complete configuration with manifest-to-fragment digest checks.
//   3. Run the exact pinned native Sing-box binary against the exact bytes,
//      publishing only an owner-private, content-addressed staged candidate.
//   4. Durably reserve an exclusive rollback lease bound to those exact bytes,
//      the signed manifest identity and a previously qualified known-good ref.
//
// A failed reservation MAY leave a private, inert staged candidate behind.
// The root supervisor must never infer authorization from staging files or
// this receipt. Privileged apply requires a separately reviewed, root-owned
// approval and independent crash recovery; those functions are NOT implemented
// here. The caller must have obtained manifest.Verified from the authenticating
// manifest verifier; Go's exported struct alone is not a cryptographic proof.
func PrepareActivation(
	ctx context.Context,
	store *state.Store,
	stager *NativeStager,
	plans []drivers.ComponentPlan,
	policy ProtectedPolicy,
	build drivers.BuildIdentity,
	deadline time.Time,
) (PreparedActivation, error) {
	if ctx == nil || store == nil || stager == nil || len(plans) == 0 {
		return PreparedActivation{}, ErrPreparationRejected
	}
	if err := ctx.Err(); err != nil {
		return PreparedActivation{}, err
	}
	// The node's pinned installed runtime and the trusted compilation
	// identity must coincide. A caller cannot substitute a different binary
	// while keeping a manifest-bound configuration apparently valid.
	if stager.build != build || plans[0].Revision.Decision != manifest.ApplyRevision {
		return PreparedActivation{}, ErrPreparationRejected
	}
	now := time.Now()
	if deadline.IsZero() || deadline.Before(now.Add(time.Second)) || deadline.After(now.Add(2*time.Minute)) {
		return PreparedActivation{}, ErrPreparationRejected
	}
	artifact, err := CompileFull(ctx, plans, policy, build)
	if err != nil {
		return PreparedActivation{}, err
	}
	staged, err := stager.Stage(ctx, artifact)
	if err != nil {
		return PreparedActivation{}, err
	}
	if staged.ComponentID != artifact.ComponentID || staged.SHA256 != artifact.SHA256 ||
		staged.Path == "" {
		return PreparedActivation{}, ErrPreparationRejected
	}
	// Stage must precede reservation to bind the candidate hash; reservation
	// must precede ANY future root-side apply, which is deliberately absent.
	guard, err := store.ReserveActivation(ctx, plans[0].Revision, staged.SHA256, deadline)
	if err != nil {
		return PreparedActivation{}, ErrPreparationRejected
	}
	if guard.CandidateDigest != staged.SHA256 ||
		guard.ManifestDigest != plans[0].Revision.Digest {
		return PreparedActivation{}, ErrPreparationRejected
	}
	return PreparedActivation{Staged: staged, Guard: guard}, nil
}
