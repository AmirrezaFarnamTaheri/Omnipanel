// Package state records a crash-recoverable rollback guard before any future
// supervisor-mediated runtime activation. This seam never marks a revision
// applied or claims that a native runtime is healthy.
package state

import (
	"context"
	"errors"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

var ErrActivationUnavailable = errors.New("activation guard is not yet implemented")

type ActivationGuard struct {
	StructuralSequence uint64
	MembershipSequence uint64
	ManifestDigest     string
	CandidateDigest    string
	RollbackRef        string
	Deadline           time.Time
}

// RecoveryOperator must be a separately qualified, trustworthy local supervisor.
// There is no production implementation or privileged service in this branch.
type RecoveryOperator interface {
	RestoreLastKnownGood(context.Context, string) error
	ObserveLastKnownGood(context.Context, string) (bool, error)
}

func (s *Store) ReserveActivation(ctx context.Context, revision manifest.Verified, candidateDigest string, deadline time.Time) (ActivationGuard, error) {
	return ActivationGuard{}, ErrActivationUnavailable
}

func (s *Store) UnconfirmedActivation(ctx context.Context) (*ActivationGuard, error) {
	return nil, ErrActivationUnavailable
}

func (s *Store) RecoverActivation(ctx context.Context, operator RecoveryOperator) error {
	return ErrActivationUnavailable
}
