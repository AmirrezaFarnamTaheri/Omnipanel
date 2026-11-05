// Package grants implements a non-HTTP, PostgreSQL-backed operator approval
// boundary for single-use node certificate enrollment. It does not create
// administrator sessions or node approvals, deliver secrets, or run a CA.
package grants

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	ErrInvalidConfig = errors.New("invalid admin grant issuer configuration")
	ErrInvalidInput  = errors.New("invalid admin grant request")
	ErrUnauthorized  = errors.New("administrator not authorized")
	ErrNotApproved   = errors.New("node not approved for enrollment")
	ErrConflict      = errors.New("pending grant already exists")
	idPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Request is INTERNAL API input from a separately authenticated control
// plane. Never accept its fields from unauthenticated or CSRF-vulnerable HTTP.
// AdminSessionToken is a bearer secret; never log or persist its plaintext.
type Request struct {
	AdminSessionToken string
	OrganizationID    string
	NodeID            string
	CorrelationID     string
	Lifetime          time.Duration
}

type Issued struct {
	Token          string
	NodeID         string
	OrganizationID string
	ExpiresAt      time.Time
	AuditID        int64
}

type Service struct{ db *sql.DB }

func New(db *sql.DB) (*Service, error) {
	if db == nil {
		return nil, ErrInvalidConfig
	}
	return &Service{db: db}, nil
}

func validate(r Request) error {
	if !idPattern.MatchString(r.OrganizationID) || !idPattern.MatchString(r.NodeID) ||
		!idPattern.MatchString(r.CorrelationID) || r.Lifetime < time.Minute || r.Lifetime > 15*time.Minute ||
		len(r.AdminSessionToken) != base64.RawURLEncoding.EncodedLen(32) {
		return ErrInvalidInput
	}
	data, err := base64.RawURLEncoding.DecodeString(r.AdminSessionToken)
	if err != nil || len(data) != 32 || base64.RawURLEncoding.EncodeToString(data) != r.AdminSessionToken {
		return ErrInvalidInput
	}
	return nil
}

// Issue grants a node-scoped bearer only after proving all of these facts
// inside a single SQL transaction: a live owner session, a recent independent
// step-up, organization-scoped grant authority, an independently approved
// UUID-to-legacy-node binding, active org, and pending legacy node.
// Token digest, issuance metadata and audit are committed atomically.
// The issuance metadata binds the exact session credential, so administrator
// logout invalidates the bearer until redemption without touching history.
func (s *Service) Issue(ctx context.Context, r Request) (Issued, error) {
	if err := ctx.Err(); err != nil {
		return Issued{}, err
	}
	if s == nil || s.db == nil {
		return Issued{}, ErrInvalidConfig
	}
	if err := validate(r); err != nil {
		return Issued{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Issued{}, fmt.Errorf("begin enrollment grant transaction: %w", err)
	}
	defer tx.Rollback()

	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		return Issued{}, fmt.Errorf("read authorized grant clock: %w", err)
	}
	sessionHash := sha256.Sum256([]byte(r.AdminSessionToken))
	var adminID, sessionID int64
	// Lock source-of-truth rows against concurrent session expiry/revocation,
	// org-role removal and removal of step-up authorizations.
	err = tx.QueryRowContext(ctx, `SELECT a.id, s.id
FROM admin_sessions s
JOIN admins a ON a.id=s.admin_id
JOIN agent_grant_admin_scopes m ON m.admin_id=a.id AND m.organization_id=$2::uuid
JOIN agent_grant_stepups su ON su.session_id=s.id
WHERE s.token_hash=$1 AND a.role='owner' AND a.totp_enabled AND m.can_issue
  AND s.created_at <= $3 AND s.last_seen_at <= $3
  AND s.expires_at > $3 AND s.created_at > $3 - interval '12 hours'
  AND s.last_seen_at > $3 - interval '2 hours'
  AND su.method='totp' AND su.verified_source='trusted' AND su.verified_counter IS NOT NULL
  AND su.verified_at <= $3
  AND su.verified_at > $3 - interval '5 minutes'
  AND su.expires_at > $3
FOR SHARE OF a,s,m,su`, hex.EncodeToString(sessionHash[:]), r.OrganizationID, dbNow).Scan(&adminID, &sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return Issued{}, ErrUnauthorized
	}
	if err != nil {
		return Issued{}, fmt.Errorf("validate administrator scope: %w", err)
	}

	var node string
	// The identity bridge must be explicitly approved by a different admin.
	// Lock both the bridge and legacy node to prevent status changes racing
	// the issuance transaction.
	err = tx.QueryRowContext(ctx, `SELECT b.node_id::text
FROM agent_grant_node_bindings b
JOIN agent_grant_organizations o ON o.organization_id=b.organization_id
JOIN agent_grant_admin_scopes ap_scope ON ap_scope.admin_id=b.approved_by AND ap_scope.organization_id=b.organization_id
JOIN admins approver ON approver.id=b.approved_by
JOIN nodes n ON n.id=b.legacy_node_id
WHERE b.node_id=$1::uuid AND b.organization_id=$2::uuid
  AND b.state='approved' AND o.state='active'
  AND ap_scope.can_approve AND approver.role='owner'
  AND n.status='pending_enrollment' AND b.approved_by<>$3
  AND b.approved_at <= $4
FOR UPDATE OF b,n
FOR SHARE OF o,ap_scope,approver`, r.NodeID, r.OrganizationID, adminID, dbNow).Scan(&node)
	if errors.Is(err, sql.ErrNoRows) {
		return Issued{}, ErrNotApproved
	}
	if err != nil {
		return Issued{}, fmt.Errorf("validate node identity binding: %w", err)
	}
	var existing int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM agent_enrollment_grants
WHERE node_id=$1 AND consumed_at IS NULL AND expires_at > $2
LIMIT 1`, node, dbNow.Unix()).Scan(&existing)
	if err == nil {
		return Issued{}, ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Issued{}, fmt.Errorf("inspect current enrollment grants: %w", err)
	}
	// Repeated requests cannot reveal previous token plaintext. Any existing
	// correlation is an error, even if that grant has already been consumed.
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM agent_grant_issues
WHERE actor_admin_id=$1 AND correlation_id=$2::uuid LIMIT 1`, adminID, r.CorrelationID).Scan(&existing)
	if err == nil {
		return Issued{}, ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Issued{}, fmt.Errorf("inspect grant correlation: %w", err)
	}

	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return Issued{}, fmt.Errorf("secure grant secret generation: %w", err)
	}
	digest := sha256.Sum256(secret[:])
	bearer := base64.RawURLEncoding.EncodeToString(secret[:])
	expires := dbNow.Add(r.Lifetime).UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_enrollment_grants
(token_digest,node_id,created_at,expires_at) VALUES ($1,$2,$3,$4)`, digest[:], node, dbNow.Unix(), expires.Unix())
	if err != nil {
		return Issued{}, fmt.Errorf("persist authorized grant: %w", err)
	}

	var issueID int64
	// The session credential hash is an immutable issuance fact (migration
	// 0006). It lets logout delete the session row while every outstanding
	// bearer from that session fails closed, and it prevents a recycled
	// session id from re-authorizing an old grant after a fresh login.
	err = tx.QueryRowContext(ctx, `INSERT INTO agent_grant_issues
(token_digest,actor_admin_id,session_id,session_token_hash,organization_id,node_id,correlation_id,created_at,expires_at)
VALUES ($1,$2,$3,$4,$5::uuid,$6::uuid,$7::uuid,$8,$9) RETURNING issue_id`,
		digest[:], adminID, sessionID, hex.EncodeToString(sessionHash[:]), r.OrganizationID, node, r.CorrelationID, dbNow, expires).Scan(&issueID)
	if err != nil {
		return Issued{}, fmt.Errorf("persist issuance metadata: %w", err)
	}

	var auditID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO agent_grant_audit
(issue_id,actor_admin_id,organization_id,node_id,token_digest,action,correlation_id,created_at)
VALUES ($1,$2,$3::uuid,$4::uuid,$5,'grant-issued',$6::uuid,$7) RETURNING audit_id`,
		issueID, adminID, r.OrganizationID, node, digest[:], r.CorrelationID, dbNow).Scan(&auditID)
	if err != nil {
		return Issued{}, fmt.Errorf("persist grant audit record: %w", err)
	}
	// The initial checks may be overtaken by a long database stall. Do not
	// return a bearer with an already expired TTL or a stale session step-up.
	var stillAuthorized bool
	err = tx.QueryRowContext(ctx, `SELECT
  s.expires_at > clock_timestamp()
  AND s.created_at <= clock_timestamp() AND s.last_seen_at <= clock_timestamp()
  AND s.last_seen_at > clock_timestamp() - interval '2 hours'
  AND s.created_at > clock_timestamp() - interval '12 hours'
  AND su.verified_at <= clock_timestamp()
  AND su.verified_source='trusted' AND su.verified_counter IS NOT NULL
  AND su.verified_at > clock_timestamp() - interval '5 minutes'
  AND su.expires_at > clock_timestamp()
  AND $2 > clock_timestamp()
FROM admin_sessions s
JOIN agent_grant_stepups su ON su.session_id=s.id
WHERE s.id=$1`, sessionID, expires).Scan(&stillAuthorized)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !stillAuthorized) {
		return Issued{}, ErrUnauthorized
	}
	if err != nil {
		return Issued{}, fmt.Errorf("recheck enrollment grant authority: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Issued{}, err
	}
	if err := tx.Commit(); err != nil {
		return Issued{}, fmt.Errorf("commit authorized enrollment grant: %w", err)
	}
	return Issued{Token: bearer, NodeID: node, OrganizationID: r.OrganizationID, ExpiresAt: expires, AuditID: auditID}, nil
}
