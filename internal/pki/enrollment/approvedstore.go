package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ApprovedSQLStore is the ONLY PostgreSQL TokenStore intended for a future
// deployed enrollment issuer. Unlike the low-level SQLStore test ledger, it
// requires an audited, organization-scoped admin grant on every lookup and
// rechecks that authorization under database locks at certificate commit.
//
// This adapter does not create grants or alter node approval state. It needs
// migrations 0003 and 0005 plus the legacy admin/session/node schema.
type ApprovedSQLStore struct {
	db *sql.DB
}

func NewApprovedSQLStore(db *sql.DB) (*ApprovedSQLStore, error) {
	if db == nil {
		return nil, errors.New("approved node enrollment requires PostgreSQL")
	}
	return &ApprovedSQLStore{db: db}, nil
}

// approvedGrantQuery does not trust the bearer-derived node UUID alone.
// A previously issued token remains unusable when the organization, UUID
// bridge, legacy node, issuing admin, approver or scoped permission is revoked.
// The immutable issuance audit must exist and match the grant.
const approvedGrantQuery = `SELECT i.node_id::text
FROM agent_enrollment_grants g
JOIN agent_grant_issues i ON i.token_digest=g.token_digest
JOIN agent_grant_audit aud ON aud.issue_id=i.issue_id
  AND aud.token_digest=g.token_digest
  AND aud.actor_admin_id=i.actor_admin_id
  AND aud.node_id=i.node_id
  AND aud.organization_id=i.organization_id
  AND aud.correlation_id=i.correlation_id
JOIN agent_grant_node_bindings b ON b.node_id=i.node_id
  AND b.organization_id=i.organization_id
JOIN agent_grant_organizations org ON org.organization_id=b.organization_id
JOIN nodes n ON n.id=b.legacy_node_id
JOIN admins issuer ON issuer.id=i.actor_admin_id
JOIN agent_grant_admin_scopes issuer_scope ON issuer_scope.admin_id=issuer.id
  AND issuer_scope.organization_id=i.organization_id
JOIN admins approver ON approver.id=b.approved_by
JOIN agent_grant_admin_scopes approver_scope ON approver_scope.admin_id=approver.id
  AND approver_scope.organization_id=i.organization_id
JOIN admin_sessions sess ON sess.id=i.session_id AND sess.admin_id=issuer.id
WHERE g.token_digest=$1
  AND g.node_id=i.node_id::text
  AND g.consumed_at IS NULL
  AND g.created_at <= floor(extract(epoch FROM clock_timestamp()))::bigint
  AND g.expires_at > floor(extract(epoch FROM clock_timestamp()))::bigint
  AND i.created_at <= clock_timestamp() AND i.expires_at > clock_timestamp()
  AND b.state='approved' AND b.approved_at <= clock_timestamp()
  AND org.state='active' AND n.status='pending_enrollment'
  AND issuer.role='owner' AND issuer.totp_enabled AND issuer_scope.can_issue
  AND approver.role='owner' AND approver_scope.can_approve
  AND b.approved_by <> i.actor_admin_id
  AND sess.expires_at > clock_timestamp()`

func (s *ApprovedSQLStore) Lookup(ctx context.Context, digest [32]byte, at time.Time) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s == nil || s.db == nil {
		return "", ErrInvalidToken
	}
	var node string
	err := s.db.QueryRowContext(ctx, approvedGrantQuery, digest[:]).Scan(&node)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidToken
	}
	if err != nil {
		return "", fmt.Errorf("authorized enrollment lookup: %w", err)
	}
	if !nodePattern.MatchString(node) {
		return "", ErrInvalidToken
	}
	return node, nil
}

// Commit does NOT rely on an earlier Lookup or the client's clock. It locks
// the current grant, node binding, legacy node, organization, and both admin
// authority rows before consuming the grant and registering the certificate.
// A concurrent revocation therefore either wins before the credential is
// issued or immediately disables the resulting certificate via Active.
func (s *ApprovedSQLStore) Commit(ctx context.Context, digest [32]byte, node, serial string,
	keyDigest [32]byte, notBefore, notAfter, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.db == nil || !nodePattern.MatchString(node) || serial == "" ||
		!notAfter.After(notBefore) || !notAfter.After(at) {
		return ErrInvalidToken
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin authorized enrollment redemption: %w", err)
	}
	defer tx.Rollback()

	// Lock authorization before writing either the redeemed marker or the
	// certificate. PostgreSQL row locks serialize this with node revocation.
	const lockClause = ` AND g.node_id=$2
FOR UPDATE OF g,b,n
FOR SHARE OF org,issuer,issuer_scope,approver,approver_scope,sess`
	var authorizedNode string
	err = tx.QueryRowContext(ctx, approvedGrantQuery+lockClause, digest[:], node).Scan(&authorizedNode)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidToken
	}
	if err != nil {
		return fmt.Errorf("lock approved node enrollment: %w", err)
	}
	if authorizedNode != node {
		return ErrInvalidToken
	}

	// The DB clock remains authoritative even when certificate signing or
	// the previous authorization query spans the token expiration boundary.
	var current time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&current); err != nil {
		return fmt.Errorf("read redemption clock: %w", err)
	}
	if !notAfter.After(current) {
		return ErrInvalidToken
	}

	var redeemed string
	err = tx.QueryRowContext(ctx, `UPDATE agent_enrollment_grants
SET consumed_at=floor(extract(epoch FROM clock_timestamp()))::bigint
WHERE token_digest=$1 AND node_id=$2 AND consumed_at IS NULL
  AND expires_at > floor(extract(epoch FROM clock_timestamp()))::bigint
RETURNING node_id`, digest[:], node).Scan(&redeemed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidToken
	}
	if err != nil {
		return fmt.Errorf("redeem approved node token: %w", err)
	}
	if redeemed != node {
		return ErrInvalidToken
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO agent_node_certificates
(serial,node_id,spki_digest,not_before,not_after,issued_at)
VALUES($1,$2,$3,$4,$5,floor(extract(epoch FROM clock_timestamp()))::bigint)`,
		serial, node, keyDigest[:], notBefore.Unix(), notAfter.Unix())
	if err != nil {
		return fmt.Errorf("register approved node credential: %w", err)
	}
	// Recheck expiry immediately before commit; failure rolls back both writes.
	var stillCurrent bool
	err = tx.QueryRowContext(ctx, `SELECT
  g.expires_at > floor(extract(epoch FROM clock_timestamp()))::bigint
  AND $2 > clock_timestamp()
FROM agent_enrollment_grants g
WHERE g.token_digest=$1`, digest[:], notAfter).Scan(&stillCurrent)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !stillCurrent) {
		return ErrInvalidToken
	}
	if err != nil {
		return fmt.Errorf("recheck committed credential lifetime: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit approved node certificate: %w", err)
	}
	return nil
}

// Active is the online credential admission check used *after* Go TLS verifies
// the client's certificate chain. Existing admitted nodes can transition to
// active or draining, but a quarantined node, suspended organization, revoked
// binding, missing cert record, expired cert or revoked serial is denied.
func (s *ApprovedSQLStore) Active(ctx context.Context, node, serial string,
	keyDigest [32]byte, at time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s == nil || s.db == nil || !nodePattern.MatchString(node) || serial == "" {
		return false, ErrUnauthorized
	}
	var active bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1
FROM agent_node_certificates c
JOIN agent_grant_node_bindings b ON b.node_id::text=c.node_id
JOIN agent_grant_organizations org ON org.organization_id=b.organization_id
JOIN nodes n ON n.id=b.legacy_node_id
WHERE c.node_id=$1 AND c.serial=$2 AND c.spki_digest=$3
  AND c.revoked_at IS NULL
  AND c.not_before <= $4 AND c.not_after > $4
  AND c.not_before <= floor(extract(epoch FROM clock_timestamp()))::bigint
  AND c.not_after > floor(extract(epoch FROM clock_timestamp()))::bigint
  AND b.state='approved' AND org.state='active'
  AND n.status IN ('pending_enrollment','active','draining')
)`, node, serial, keyDigest[:], at.UTC().Unix()).Scan(&active)
	if err != nil {
		return false, fmt.Errorf("verify node certificate approval: %w", err)
	}
	return active, nil
}

// Revoke records the serial revocation through the same basic ledger. This
// cannot grant access because all admission still passes through Active.
func (s *ApprovedSQLStore) Revoke(ctx context.Context, node, serial string, at time.Time) error {
	if s == nil || s.db == nil {
		return ErrUnauthorized
	}
	return (&SQLStore{db: s.db}).Revoke(ctx, node, serial, at)
}
