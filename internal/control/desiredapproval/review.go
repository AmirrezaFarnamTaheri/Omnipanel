package desiredapproval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ReviewRequest contains only an independently authenticated reviewer session
// and an immutable proposal identifier, never a claimed administrator role.
type ReviewRequest struct {
	SessionToken string
	ProposalID string
}

// Reviewable is the exact signed intent displayed to a second administrator.
// The reviewer must separately confirm EnvelopeSHA256 in Approve. This record
// carries neither private signing material nor credential plaintext.
type Reviewable struct {
	ProposalID string
	OrganizationID string
	NodeID string
	Epoch string
	StructuralSequence uint64
	MembershipSequence uint64
	EnvelopeSHA256 string
	Envelope []byte
	ExpiresAt time.Time
}

// Review performs the same live, step-up-backed reviewer authorization as
// Approve, but creates no approval and returns a private copy of the exact
// signed bytes. A future HTTP adapter must use an authenticated same-origin,
// no-store and CSRF-protected channel, never a public subscription endpoint.
func (s *Service) Review(ctx context.Context, input ReviewRequest) (Reviewable, error) {
	if err := ctx.Err(); err != nil {
		return Reviewable{}, err
	}
	if s == nil || s.db == nil {
		return Reviewable{}, ErrConfiguration
	}
	hash, ok := sessionDigest(input.SessionToken)
	if !ok || !idPattern.MatchString(input.ProposalID) {
		return Reviewable{}, ErrInvalidInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Reviewable{}, fmt.Errorf("begin independent signed proposal review: %w", err)
	}
	defer tx.Rollback()
	var org, node, epoch, proposerHash string
	var structural, membership int64
	var storedDigest, wire []byte
	var proposerAdmin, proposerSession, proposerCounter int64
	var expires time.Time
	err = tx.QueryRowContext(ctx, savedProposalSQL, input.ProposalID).
		Scan(&org, &node, &epoch, &structural, &membership, &storedDigest, &wire,
			&proposerAdmin, &proposerSession, &proposerHash, &proposerCounter, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Reviewable{}, ErrUnauthorized
	}
	if err != nil {
		return Reviewable{}, fmt.Errorf("read immutable signed intent for review: %w", err)
	}
	sha := sha256.Sum256(wire)
	if !idPattern.MatchString(node) || !idPattern.MatchString(org) ||
		epoch != s.verifier.AuthorizedEpoch || structural <= 0 ||
		membership < 0 || len(wire) == 0 || len(wire) > maxEnvelope ||
		!bytes.Equal(storedDigest, sha[:]) {
		return Reviewable{}, ErrUnauthorized
	}
	verified, err := s.verify(node, wire)
	if err != nil || verified.Manifest.ControlPlaneEpoch != epoch ||
		verified.Manifest.StructuralSequence != uint64(structural) ||
		verified.Manifest.MembershipSequence != uint64(membership) {
		return Reviewable{}, ErrUnauthorized
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return Reviewable{}, fmt.Errorf("read trusted review clock: %w", err)
	}
	if !expires.After(now) {
		return Reviewable{}, ErrUnauthorized
	}
	reviewer, err := sessionProof(ctx, tx, hash, org, now, false)
	if err != nil {
		return Reviewable{}, err
	}
	if reviewer.adminID == proposerAdmin {
		return Reviewable{}, ErrUnauthorized
	}
	var original int
	err = tx.QueryRowContext(ctx, revalidateProposerSQL, proposerSession,
		proposerHash, org, proposerAdmin, now, proposerCounter).Scan(&original)
	if errors.Is(err, sql.ErrNoRows) {
		return Reviewable{}, ErrUnauthorized
	}
	if err != nil {
		return Reviewable{}, fmt.Errorf("revalidate reviewed proposal's author: %w", err)
	}
	if err := checkBinding(ctx, tx, node, org, now); err != nil {
		return Reviewable{}, err
	}
	if err := ctx.Err(); err != nil {
		return Reviewable{}, err
	}
	if err := tx.Commit(); err != nil {
		return Reviewable{}, fmt.Errorf("finish signed proposal review: %w", err)
	}
	return Reviewable{
		ProposalID: input.ProposalID, OrganizationID: org, NodeID: node,
		Epoch: epoch, StructuralSequence: uint64(structural),
		MembershipSequence: uint64(membership),
		EnvelopeSHA256: hex.EncodeToString(sha[:]),
		Envelope: append([]byte(nil), wire...),
		ExpiresAt: expires,
	}, nil
}
