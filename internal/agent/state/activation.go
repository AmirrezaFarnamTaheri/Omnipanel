// Package state records a crash-recoverable rollback guard before any future
// supervisor-mediated runtime activation. This code cannot activate a host or
// assert that a pending desired revision is deployed or healthy.
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

const (
	maxActivationWindow = 2 * time.Minute
	minActivationWindow = time.Second
	maxActivationSeq    = 9007199254740991
)

var (
	ErrActivationDenied   = errors.New("activation guard denied: verified intent, approved baseline or exclusive lease missing")
	ErrRollbackUnverified = errors.New("known-good runtime restoration is not independently observed")
	knownGoodRefPattern   = regexp.MustCompile("^sha256:[a-f0-9]{64}$")
)

// ActivationGuard is an owner-private, durable safety lease. It records the
// exact signed manifest digest, a separately staged candidate digest and the
// previously observed LKG digest. Its deadline is advisory recovery metadata;
// an independent always-on watchdog must be installed before host activation.
type ActivationGuard struct {
	StructuralSequence uint64
	MembershipSequence uint64
	ManifestDigest     string
	CandidateDigest    string
	RollbackRef        string
	Deadline           time.Time
}

// RecoveryOperator must be supplied by an independently qualified trusted
// local supervisor. This package intentionally ships no privileged operator.
// Its response alone is NOT a production health attestation.
type RecoveryOperator interface {
	RestoreLastKnownGood(context.Context, string) error
	ObserveLastKnownGood(context.Context, string) (bool, error)
}

// ReserveActivation atomically writes the guard BEFORE any future host action.
// It accepts only a VERIFIED intent matching the protected node journal and
// requires a previously qualified LKG reference already persisted in node_scope.
// There is deliberately no API here to seed or forge a known-good reference.
func (s *Store) ReserveActivation(ctx context.Context, revision manifest.Verified, candidateDigest string, deadline time.Time) (ActivationGuard, error) {
	if s == nil || s.db == nil || ctx == nil {
		return ActivationGuard{}, ErrActivationDenied
	}
	if err := ctx.Err(); err != nil {
		return ActivationGuard{}, err
	}
	m := revision.Manifest
	if revision.Decision != manifest.ApplyRevision ||
		m.NodeID != s.nodeID || m.ControlPlaneEpoch != s.epoch ||
		m.SchemaVersion != "2.0" || m.BaseEgressPolicy != "deny-protected-v1" ||
		m.StructuralSequence == 0 || m.StructuralSequence > maxActivationSeq ||
		m.MembershipSequence > maxActivationSeq ||
		!digestPattern.MatchString(revision.Digest) ||
		!digestPattern.MatchString(candidateDigest) {
		return ActivationGuard{}, ErrActivationDenied
	}
	now := time.Now()
	if deadline.IsZero() || deadline.Before(now.Add(minActivationWindow)) || deadline.After(now.Add(maxActivationWindow)) {
		return ActivationGuard{}, ErrActivationDenied
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ActivationGuard{}, fmt.Errorf("%w: cannot begin protected lease", ErrActivationDenied)
	}
	defer tx.Rollback()
	var appliedStructural, appliedMembership int64
	var lastGood string
	if err := tx.QueryRowContext(ctx,
		"SELECT applied_structural,applied_membership,last_good_ref FROM node_scope WHERE singleton=1").
		Scan(&appliedStructural, &appliedMembership, &lastGood); err != nil {
		return ActivationGuard{}, ErrActivationDenied
	}
	if !knownGoodRefPattern.MatchString(lastGood) ||
		m.StructuralSequence <= uint64(appliedStructural) ||
		m.MembershipSequence < uint64(appliedMembership) {
		return ActivationGuard{}, ErrActivationDenied
	}
	var stage Stage
	err = tx.QueryRowContext(ctx,
		"SELECT stage FROM revisions WHERE epoch=? AND structural=? AND membership=? AND digest=?",
		s.epoch, int64(m.StructuralSequence), int64(m.MembershipSequence), revision.Digest).Scan(&stage)
	if err != nil || stage != Verified {
		return ActivationGuard{}, ErrActivationDenied
	}

	// INSERT has no ON CONFLICT clause: even the same proposal may not
	// extend or replace an unconfirmed activation after a crash or timeout.
	// SQLite's unique singleton key serializes competing processes.
	deadline = time.Unix(0, deadline.UnixNano()).UTC()
	_, err = tx.ExecContext(ctx,
		"INSERT INTO activation_guard(singleton,epoch,structural,membership,manifest_digest,candidate_digest,rollback_ref,deadline_ns) VALUES(1,?,?,?,?,?,?,?)",
		s.epoch, int64(m.StructuralSequence), int64(m.MembershipSequence), revision.Digest, candidateDigest, lastGood, deadline.UnixNano())
	if err != nil {
		return ActivationGuard{}, ErrActivationDenied
	}
	if err := tx.Commit(); err != nil {
		return ActivationGuard{}, fmt.Errorf("%w: durable activation lease commit failed", ErrActivationDenied)
	}
	return ActivationGuard{
		StructuralSequence: m.StructuralSequence,
		MembershipSequence: m.MembershipSequence,
		ManifestDigest:     revision.Digest,
		CandidateDigest:    candidateDigest,
		RollbackRef:        lastGood,
		Deadline:           deadline,
	}, nil
}

// UnconfirmedActivation reads the same lease after process restart. An
// expired lease still requires recovery; it cannot silently evaporate.
func (s *Store) UnconfirmedActivation(ctx context.Context) (*ActivationGuard, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrActivationDenied
	}
	var epoch string
	var structural, membership, deadlineNS int64
	var digest, candidate, rollback string
	err := s.db.QueryRowContext(ctx,
		"SELECT epoch,structural,membership,manifest_digest,candidate_digest,rollback_ref,deadline_ns FROM activation_guard WHERE singleton=1").
		Scan(&epoch, &structural, &membership, &digest, &candidate, &rollback, &deadlineNS)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable recovery guard", ErrActivationDenied)
	}
	if epoch != s.epoch || structural <= 0 || structural > maxActivationSeq ||
		membership < 0 || membership > maxActivationSeq ||
		!digestPattern.MatchString(digest) || !digestPattern.MatchString(candidate) ||
		!knownGoodRefPattern.MatchString(rollback) || deadlineNS <= 0 {
		return nil, ErrActivationDenied
	}
	return &ActivationGuard{
		StructuralSequence: uint64(structural),
		MembershipSequence: uint64(membership),
		ManifestDigest:     digest,
		CandidateDigest:    candidate,
		RollbackRef:        rollback,
		Deadline:           time.Unix(0, deadlineNS).UTC(),
	}, nil
}

// RecoverActivation can clear a stale guard ONLY after the separately trusted
// supervisor restores the exact LKG reference and observes it healthy. Failure
// preserves the guard for retry after restart. This method never advances the
// applied cursor or grants production deployment authorization.
func (s *Store) RecoverActivation(ctx context.Context, operator RecoveryOperator) error {
	if ctx == nil {
		return ErrActivationDenied
	}
	guard, err := s.UnconfirmedActivation(ctx)
	if err != nil || guard == nil {
		return err
	}
	if operator == nil {
		return ErrRollbackUnverified
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := operator.RestoreLastKnownGood(ctx, guard.RollbackRef); err != nil {
		// Never expose stdout/stderr or operator-supplied details that might
		// contain secrets from a runtime config.
		return ErrRollbackUnverified
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	healthy, err := operator.ObserveLastKnownGood(ctx, guard.RollbackRef)
	if err != nil || !healthy {
		return ErrRollbackUnverified
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: recovery guard transaction failed", ErrRollbackUnverified)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx,
		"DELETE FROM activation_guard WHERE singleton=1 AND epoch=? AND structural=? AND membership=? AND manifest_digest=? AND candidate_digest=? AND rollback_ref=? AND deadline_ns=?",
		s.epoch, int64(guard.StructuralSequence), int64(guard.MembershipSequence), guard.ManifestDigest,
		guard.CandidateDigest, guard.RollbackRef, guard.Deadline.UnixNano())
	if err != nil {
		return ErrRollbackUnverified
	}
	removed, err := result.RowsAffected()
	if err != nil || removed != 1 {
		return ErrRollbackUnverified
	}
	if err := tx.Commit(); err != nil {
		return ErrRollbackUnverified
	}
	return nil
}
