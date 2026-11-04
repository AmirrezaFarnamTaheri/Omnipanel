package desiredapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrSnapshotUnavailable means that a node has no current authorized signed
// snapshot, or that a stored snapshot failed the resource/metadata preflight.
var ErrSnapshotUnavailable = errors.New("authorized signed desired-state snapshot unavailable")

// SQLSource reads the preauthorized view defined in migration 0008. The view
// enforces binding/organization/node state in one PostgreSQL MVCC statement.
// The gateway database role should receive SELECT on the view only; it must
// never have direct access to revision/head or enrollment-issuance tables.
type SQLSource struct {
	db *sql.DB
}

func NewSQLSource(db *sql.DB) (*SQLSource, error) {
	if db == nil {
		return nil, ErrInvalidConfig
	}
	return &SQLSource{db: db}, nil
}

const authorizedSnapshotQuery = `SELECT control_plane_epoch, structural_sequence, membership_sequence, envelope
FROM agent_desired_current
WHERE node_id=$1`

// Latest is called only with the node identity authenticated from the TLS
// certificate, never with a node ID supplied in an HTTP request parameter.
// The envelope itself is untrusted until the Handler verifies its signature.
func (s *SQLSource) Latest(ctx context.Context, nodeID string) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if s == nil || s.db == nil || !identityPattern.MatchString(nodeID) {
		return Snapshot{}, ErrSnapshotUnavailable
	}
	var epoch string
	var structural, membership int64
	var envelope []byte
	err := s.db.QueryRowContext(ctx, authorizedSnapshotQuery, nodeID).Scan(&epoch, &structural, &membership, &envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrSnapshotUnavailable
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("read authorized signed desired-state snapshot: %w", err)
	}
	if !identityPattern.MatchString(epoch) || structural <= 0 || structural > int64(maxSequence) ||
		membership < 0 || membership > int64(maxSequence) || len(envelope) == 0 || len(envelope) > 1<<20 {
		return Snapshot{}, ErrSnapshotUnavailable
	}
	return Snapshot{
		Epoch:              epoch,
		StructuralSequence: uint64(structural),
		MembershipSequence: uint64(membership),
		Envelope:           append([]byte(nil), envelope...),
	}, nil
}
