package state

import (
	"context"
	"time"
)

// CandidateBinding is the exact non-secret scope independently echoed by the
// root-owned candidate supervisor. The SQLite recovery guard alone is not a
// privileged authorization or independently observed network evidence.
type CandidateBinding struct {
	NodeID             string
	Epoch              string
	StructuralSequence uint64
	MembershipSequence uint64
	ManifestDigest     string
	CandidateDigest    string
	RollbackRef        string
}

// RequirePendingCandidate is a read-only, single-SQL-snapshot check of an
// unexpired exclusive WAL guard, the VERIFIED signed revision and the original
// known-good rollback baseline. No caller can mark APPLIED or issue an ACK.
// The separate root process must ALSO attest actual local candidate identity;
// an unprivileged journal is insufficient to authorize host configuration.
func (s *Store) RequirePendingCandidate(ctx context.Context, binding CandidateBinding) error {
	if s == nil || s.db == nil || ctx == nil || ctx.Err() != nil ||
		!uuidPattern.MatchString(binding.NodeID) || !uuidPattern.MatchString(binding.Epoch) ||
		binding.NodeID != s.nodeID || binding.Epoch != s.epoch ||
		binding.StructuralSequence == 0 || binding.StructuralSequence > maxActivationSeq ||
		binding.MembershipSequence > maxActivationSeq ||
		!digestPattern.MatchString(binding.ManifestDigest) ||
		!digestPattern.MatchString(binding.CandidateDigest) ||
		!knownGoodRefPattern.MatchString(binding.RollbackRef) ||
		binding.RollbackRef == "sha256:"+binding.CandidateDigest {
		return ErrActivationDenied
	}
	now := time.Now().UTC()
	const exactGuard = `SELECT 1 FROM activation_guard AS a
JOIN revisions AS r ON r.epoch=a.epoch
  AND r.structural=a.structural AND r.membership=a.membership
  AND r.digest=a.manifest_digest AND r.stage='VERIFIED'
JOIN node_scope AS n ON n.singleton=1
WHERE a.singleton=1 AND a.epoch=? AND a.structural=? AND a.membership=?
  AND a.manifest_digest=? AND a.candidate_digest=? AND a.rollback_ref=?
  AND n.node_id=? AND n.epoch=? AND n.last_good_ref=a.rollback_ref
  AND n.applied_structural<a.structural AND n.applied_membership<=a.membership
  AND a.deadline_ns>? AND a.deadline_ns<=?`
	var accepted int
	err := s.db.QueryRowContext(ctx, exactGuard,
		binding.Epoch, int64(binding.StructuralSequence), int64(binding.MembershipSequence),
		binding.ManifestDigest, binding.CandidateDigest, binding.RollbackRef,
		binding.NodeID, binding.Epoch, now.UnixNano(), now.Add(maxActivationWindow).UnixNano(),
	).Scan(&accepted)
	if err != nil || accepted != 1 {
		return ErrActivationDenied
	}
	return nil
}
