package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SQLStore is a LOW-LEVEL transaction ledger retained for isolated tests.
// It does NOT revalidate organization/node approval at token redemption and
// must never be wired directly into a deployed enrollment listener. Instead,
// construct ApprovedSQLStore for certificate issuance and admission.
// Schema migration remains separate from construction.
// Queries use $n parameters compatible with PostgreSQL and SQLite lab tests.
type SQLStore struct{ db *sql.DB }

func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	if db == nil {
		return nil, errors.New("node enrollment SQL database required")
	}
	return &SQLStore{db: db}, nil
}

func (s *SQLStore) Lookup(ctx context.Context, digest [32]byte, at time.Time) (string, error) {
	var node string
	err := s.db.QueryRowContext(ctx, `SELECT node_id FROM agent_enrollment_grants
        WHERE token_digest=$1 AND consumed_at IS NULL AND expires_at > $2`, digest[:], at.Unix()).Scan(&node)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidToken
	}
	if err != nil {
		return "", err
	}
	if !nodePattern.MatchString(node) {
		return "", ErrInvalidToken
	}
	return node, nil
}

// Commit performs a compare-and-consume within the *same transaction* as
// certificate registration. Concurrent redemptions can return at most one
// authorized certificate. Failed writes roll back the consumed flag.
func (s *SQLStore) Commit(ctx context.Context, digest [32]byte, node, serial string, key [32]byte, notBefore, notAfter, at time.Time) error {
	if !nodePattern.MatchString(node) || serial == "" || !notAfter.After(at) || !notAfter.After(notBefore) {
		return ErrInvalidToken
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var redeemedNode string
	err = tx.QueryRowContext(ctx, `UPDATE agent_enrollment_grants SET consumed_at=$1
        WHERE token_digest=$2 AND node_id=$3 AND consumed_at IS NULL AND expires_at > $4
        RETURNING node_id`, at.Unix(), digest[:], node, at.Unix()).Scan(&redeemedNode)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidToken
	}
	if err != nil {
		return err
	}
	if redeemedNode != node {
		return ErrInvalidToken
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_node_certificates
        (serial,node_id,spki_digest,not_before,not_after,issued_at)
        VALUES($1,$2,$3,$4,$5,$6)`, serial, node, key[:], notBefore.Unix(), notAfter.Unix(), at.Unix())
	if err != nil {
		return fmt.Errorf("record newly issued node certificate: %w", err)
	}
	return tx.Commit()
}

// Active is the online node-identity/revocation lookup. Certificate chains
// must be validated separately by TLS; only a bound, unrevoked serial+key
// for the expected node is accepted.
func (s *SQLStore) Active(ctx context.Context, node, serial string, key [32]byte, at time.Time) (bool, error) {
	if !nodePattern.MatchString(node) || serial == "" {
		return false, ErrUnauthorized
	}
	var found int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM agent_node_certificates
        WHERE node_id=$1 AND serial=$2 AND spki_digest=$3 AND revoked_at IS NULL
        AND not_before <= $4 AND not_after > $4`, node, serial, key[:], at.Unix()).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return found == 1, nil
}

// Revoke permanently disables a registered certificate. It is not an
// unauthenticated HTTP operation; the invoking control plane must authorize
// the node-scoped action and create an audit record.
func (s *SQLStore) Revoke(ctx context.Context, node, serial string, at time.Time) error {
	if !nodePattern.MatchString(node) || serial == "" {
		return ErrUnauthorized
	}
	result, err := s.db.ExecContext(ctx, `UPDATE agent_node_certificates SET revoked_at=$1
        WHERE node_id=$2 AND serial=$3 AND revoked_at IS NULL`, at.Unix(), node, serial)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 1 {
		return nil
	}
	// A duplicate revoke is idempotent, but a mismatched node/serial is not.
	var found int
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM agent_node_certificates
        WHERE node_id=$1 AND serial=$2 AND revoked_at IS NOT NULL`, node, serial).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	}
	return err
}
