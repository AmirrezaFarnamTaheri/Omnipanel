// Package desiredapproval provides a non-HTTP, two-stage administrator
// authorization boundary for already-signed node configuration publications.
// It neither signs manifests nor creates administrator sessions or TOTP
// attestations. Callers must separately enforce CSRF/origin and safe UX.
package desiredapproval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

var (
	ErrConfiguration = errors.New("invalid publication approval configuration")
	ErrInvalidInput  = errors.New("invalid publication approval input")
	ErrUnauthorized  = errors.New("publication administrator authorization denied")
	ErrConflict      = errors.New("publication has already been reviewed")
	idPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}// Package desiredapproval provides a non-HTTP, two-stage administrator
// authorization boundary for already-signed node configuration publications.
// It neither signs manifests nor creates administrator sessions or TOTP
// attestations. Callers must separately enforce CSRF/origin and safe UX.
package desiredapproval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

var (
	ErrConfiguration = errors.New("invalid publication approval configuration")
)
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}// Package desiredapproval provides a non-HTTP, two-stage administrator
// authorization boundary for already-signed node configuration publications.
// It neither signs manifests nor creates administrator sessions or TOTP
// attestations. Callers must separately enforce CSRF/origin and safe UX.
package desiredapproval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

var (
	ErrConfiguration = errors.New("invalid publication approval configuration")
)
)

const (
	maxEnvelope         = 1 << 20
	minProposalLifetime = time.Minute
	maxProposalLifetime = 10 * time.Minute
	approvedLifetime    = 5 * time.Minute
)

type Service struct {
	db       *sql.DB
	verifier manifest.Verifier
}

// NewService pins signer public keys, approved builds, and control-plane epoch
// independently from any incoming signed manifest or database state.
func NewService(db *sql.DB, verifier manifest.Verifier) (*Service, error) {
	if db == nil || !idPattern.MatchString(verifier.AuthorizedEpoch) ||
		len(verifier.TrustedSigners) == 0 || len(verifier.AllowedCapabilities) == 0 ||
		len(verifier.QualifiedBuilds) == 0 || verifier.MaxClockSkew < 0 {
		return nil, ErrConfiguration
	}
	trusted := verifier
	trusted.TrustedSigners = make(map[string]ed25519.PublicKey, len(verifier.TrustedSigners))
	for id, key := range verifier.TrustedSigners {
		if len(key) != ed25519.PublicKeySize {
			return nil, ErrConfiguration
		}
		trusted.TrustedSigners[id] = append(ed25519.PublicKey(nil), key...)
	}
	trusted.AllowedCapabilities = make(map[string]bool, len(verifier.AllowedCapabilities))
	for name, allowed := range verifier.AllowedCapabilities {
		trusted.AllowedCapabilities[name] = allowed
	}
	trusted.QualifiedBuilds = make(map[string]manifest.Build, len(verifier.QualifiedBuilds))
	for name, build := range verifier.QualifiedBuilds {
		build.Capabilities = append([]string(nil), build.Capabilities...)
		trusted.QualifiedBuilds[name] = build
	}
	trusted.NodeID = ""
	trusted.Current = manifest.Cursor{}
	return &Service{db: db, verifier: trusted}, nil
}

type ProposalRequest struct {
	SessionToken   string
	ProposalID     string
	OrganizationID string
	NodeID         string
	Envelope       []byte
	Lifetime       time.Duration
}

type ProposalReceipt struct {
	ProposalID     string
	NodeID         string
	EnvelopeSHA256 string
	ExpiresAt      time.Time
}

type ApprovalRequest struct {
	SessionToken string
	ProposalID   string
	// Must be the 64-byte lowercase hex digest displayed by a separate
	// authenticated review of the immutable signed proposal's exact bytes.
	ExpectedSHA256 string
}

type ApprovalReceipt struct {
	ProposalID     string
	ApprovalID     string
	NodeID         string
	EnvelopeSHA256 string
	ExpiresAt      time.Time
}

func sessionDigest(token string) (string, bool) {
	if len(token) != base64.RawURLEncoding.EncodedLen(32) {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return "", false
	}
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:]), true
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	x := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", x[:8], x[8:12], x[12:16], x[16:20], x[20:]), nil
}

type session struct {
	adminID   int64
	sessionID int64
	counter   int64
}

// sessionProof obtains administrator identity solely from a LIVE session
// credential in PostgreSQL, not a claimed admin ID. Step-up must have been
// independently verified with the durable TOTP replay counter and remain
// fresh. Locks serialize logout, role/scope revoke and step-up mutation.
const sessionProofSQL = `SELECT a.id, s.id, su.verified_counter
FROM admin_sessions s
JOIN admins a ON a.id=s.admin_id
JOIN agent_desired_publish_permissions perm
 ON perm.admin_id=a.id AND perm.organization_id=$2::uuid
JOIN agent_grant_stepups su ON su.session_id=s.id
WHERE s.token_hash=$1
 AND a.role='owner' AND a.totp_enabled
 AND (CASE WHEN $4::boolean THEN perm.can_propose ELSE perm.can_approve END)
 AND s.created_at <= $3 AND s.last_seen_at <= $3
 AND s.created_at > $3 - interval '12 hours'
 AND s.last_seen_at > $3 - interval '2 hours'
 AND s.expires_at > $3
 AND su.method='totp' AND su.verified_source='trusted'
 AND su.verified_counter IS NOT NULL AND su.verified_counter >= 0
 AND su.verified_at <= $3 AND su.verified_at > $3 - interval '5 minutes'
 AND su.expires_at > $3
FOR SHARE OF s,a,perm,su`

func sessionProof(ctx context.Context, tx *sql.Tx, hash, org string, now time.Time, proposer bool) (session, error) {
	var actor session
	err := tx.QueryRowContext(ctx, sessionProofSQL, hash, org, now, proposer).
		Scan(&actor.adminID, &actor.sessionID, &actor.counter)
	if errors.Is(err, sql.ErrNoRows) {
		return session{}, ErrUnauthorized
	}
	if err != nil {
		return session{}, fmt.Errorf("validate independent administrator step-up: %w", err)
	}
	return actor, nil
}

const approvedBindingSQL = `SELECT b.node_id::text
FROM agent_grant_node_bindings b
JOIN agent_grant_organizations org ON org.organization_id=b.organization_id
JOIN nodes n ON n.id=b.legacy_node_id
WHERE b.node_id=$1::uuid AND b.organization_id=$2::uuid
 AND b.state='approved' AND org.state='active'
 AND b.approved_at <= $3
 AND n.status IN ('pending_enrollment','active','draining')
FOR SHARE OF b,org,n`

func checkBinding(ctx context.Context, tx *sql.Tx, node, org string, now time.Time) error {
	var admitted string
	err := tx.QueryRowContext(ctx, approvedBindingSQL, node, org, now).Scan(&admitted)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && admitted != node) {
		return ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("validate desired publication node authorization: %w", err)
	}
	return nil
}

func (s *Service) verify(node string, wire []byte) (manifest.Verified, error) {
	v := s.verifier
	v.NodeID = node
	v.Current = manifest.Cursor{}
	out, err := v.Verify(wire)
	if err != nil || out.Decision != manifest.ApplyRevision {
		return manifest.Verified{}, ErrUnauthorized
	}
	return out, nil
}

// Even while auth rows are locked, clock-based session/TOTP authorization
// can expire. A database-clocked recheck immediately before commit prevents
// an authorization admitted before an unexpected storage stall from escaping.
const stillFreshSessionSQL = `SELECT EXISTS(
 SELECT 1 FROM admin_sessions s
 JOIN admins a ON a.id=s.admin_id
 JOIN agent_desired_publish_permissions perm
  ON perm.admin_id=a.id AND perm.organization_id=$2::uuid
 JOIN agent_grant_stepups su ON su.session_id=s.id
 WHERE s.token_hash=$1 AND a.id=$3 AND s.id=$4
  AND a.role='owner' AND a.totp_enabled
  AND (CASE WHEN $6::boolean THEN perm.can_propose ELSE perm.can_approve END)
  AND s.created_at <= clock_timestamp()
  AND s.last_seen_at <= clock_timestamp()
  AND s.created_at > clock_timestamp() - interval '12 hours'
  AND s.last_seen_at > clock_timestamp() - interval '2 hours'
  AND s.expires_at > clock_timestamp()
  AND su.method='totp' AND su.verified_source='trusted'
  AND su.verified_counter=$5
  AND su.verified_at <= clock_timestamp()
  AND su.verified_at > clock_timestamp() - interval '5 minutes'
  AND su.expires_at > clock_timestamp()
) AND $7 > clock_timestamp()`

func stillFreshSession(ctx context.Context, tx *sql.Tx, hash, org string,
	actor session, proposer bool, deadline time.Time) error {
	var valid bool
	err := tx.QueryRowContext(ctx, stillFreshSessionSQL,
		hash, org, actor.adminID, actor.sessionID, actor.counter, proposer, deadline).Scan(&valid)
	if err != nil {
		return fmt.Errorf("revalidate expiring administrator authority: %w", err)
	}
	if !valid {
		return ErrUnauthorized
	}
	return nil
}

// Propose records the exact signed bytes and the first administrator's
// session-bound trusted TOTP proof. The proposal itself grants no right to
// publish; another live administrator must review and approve it.
func (s *Service) Propose(ctx context.Context, input ProposalRequest) (ProposalReceipt, error) {
	if err := ctx.Err(); err != nil {
		return ProposalReceipt{}, err
	}
	if s == nil || s.db == nil {
		return ProposalReceipt{}, ErrConfiguration
	}
	hash, ok := sessionDigest(input.SessionToken)
	if !ok || !idPattern.MatchString(input.ProposalID) ||
		!idPattern.MatchString(input.OrganizationID) ||
		!idPattern.MatchString(input.NodeID) ||
		input.Lifetime < minProposalLifetime || input.Lifetime > maxProposalLifetime ||
		len(input.Envelope) == 0 || len(input.Envelope) > maxEnvelope {
		return ProposalReceipt{}, ErrInvalidInput
	}
	verified, err := s.verify(input.NodeID, input.Envelope)
	if err != nil {
		return ProposalReceipt{}, err
	}
	m := verified.Manifest
	digest := sha256.Sum256(input.Envelope)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProposalReceipt{}, fmt.Errorf("begin signed proposal: %w", err)
	}
	defer tx.Rollback()
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return ProposalReceipt{}, fmt.Errorf("read proposal clock: %w", err)
	}
	actor, err := sessionProof(ctx, tx, hash, input.OrganizationID, now, true)
	if err != nil {
		return ProposalReceipt{}, err
	}
	if err := checkBinding(ctx, tx, input.NodeID, input.OrganizationID, now); err != nil {
		return ProposalReceipt{}, err
	}
	expires := now.Add(input.Lifetime).UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_desired_publish_proposals
(proposal_id,organization_id,node_id,control_plane_epoch,structural_sequence,
 membership_sequence,envelope_sha256,envelope,proposer_admin_id,
 proposer_session_id,proposer_session_hash,proposer_stepup_counter,created_at,expires_at)
VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		input.ProposalID, input.OrganizationID, input.NodeID, m.ControlPlaneEpoch,
		int64(m.StructuralSequence), int64(m.MembershipSequence), digest[:],
		input.Envelope, actor.adminID, actor.sessionID, hash, actor.counter, now, expires)
	if err != nil {
		return ProposalReceipt{}, fmt.Errorf("commit immutable proposal intent: %w", err)
	}
	// A long database stall cannot commit an already-expired authorization.
	var current time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&current); err != nil {
		return ProposalReceipt{}, fmt.Errorf("recheck proposal deadline: %w", err)
	}
	if !expires.After(current) {
		return ProposalReceipt{}, ErrUnauthorized
	}
	if err := stillFreshSession(ctx, tx, hash, input.OrganizationID, actor, true, expires); err != nil {
		return ProposalReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return ProposalReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProposalReceipt{}, fmt.Errorf("commit signed proposal: %w", err)
	}
	return ProposalReceipt{ProposalID: input.ProposalID, NodeID: input.NodeID,
		EnvelopeSHA256: hex.EncodeToString(digest[:]), ExpiresAt: expires}, nil
}

const savedProposalSQL = `SELECT organization_id::text,node_id::text,control_plane_epoch::text,
structural_sequence,membership_sequence,envelope_sha256,envelope,
proposer_admin_id,proposer_session_id,proposer_session_hash,
proposer_stepup_counter,expires_at
FROM agent_desired_publish_proposals
WHERE proposal_id=$1::uuid AND created_at <= clock_timestamp()
 AND expires_at > clock_timestamp()
FOR UPDATE`

// Proposer's live session proof must still match the EXACT original session
// token hash, administrator, counter, owner permission and recent verified
// TOTP. Deleting the old session or recycling its ID cannot revive it.
const revalidateProposerSQL = `SELECT 1
FROM admin_sessions ps
JOIN admins a ON a.id=ps.admin_id
JOIN agent_desired_publish_permissions perm
 ON perm.admin_id=a.id AND perm.organization_id=$3::uuid
JOIN agent_grant_stepups su ON su.session_id=ps.id
WHERE ps.id=$1 AND ps.token_hash=$2 AND ps.admin_id=$4
 AND a.role='owner' AND a.totp_enabled AND perm.can_propose
 AND ps.created_at <= $5 AND ps.last_seen_at <= $5
 AND ps.created_at > $5 - interval '12 hours'
 AND ps.last_seen_at > $5 - interval '2 hours'
 AND ps.expires_at > $5
 AND su.method='totp' AND su.verified_source='trusted'
 AND su.verified_counter=$6 AND su.verified_counter >= 0
 AND su.verified_at <= $5 AND su.verified_at > $5 - interval '5 minutes'
 AND su.expires_at > $5
FOR SHARE OF ps,a,perm,su`

// Approve requires a DIFFERENT authenticated owner with a separate trusted
// recent step-up. The reviewer must confirm the exact signed envelope SHA256.
// Neither client request nor database proposal can select a new trusted epoch.
func (s *Service) Approve(ctx context.Context, input ApprovalRequest) (ApprovalReceipt, error) {
	if err := ctx.Err(); err != nil {
		return ApprovalReceipt{}, err
	}
	if s == nil || s.db == nil {
		return ApprovalReceipt{}, ErrConfiguration
	}
	sessionHash, ok := sessionDigest(input.SessionToken)
	if !ok || !idPattern.MatchString(input.ProposalID) ||
		!digestPattern.MatchString(input.ExpectedSHA256) {
		return ApprovalReceipt{}, ErrInvalidInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalReceipt{}, fmt.Errorf("begin independent publication approval: %w", err)
	}
	defer tx.Rollback()
	var org, node, epoch, proposerHash string
	var structural, membership int64
	var storedDigest, wire []byte
	var proposerAdmin, proposerSession, proposerCounter int64
	var proposalExpiry time.Time
	err = tx.QueryRowContext(ctx, savedProposalSQL, input.ProposalID).
		Scan(&org, &node, &epoch, &structural, &membership, &storedDigest, &wire,
			&proposerAdmin, &proposerSession, &proposerHash, &proposerCounter, &proposalExpiry)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalReceipt{}, ErrUnauthorized
	}
	if err != nil {
		return ApprovalReceipt{}, fmt.Errorf("read immutable signed proposal: %w", err)
	}
	hash := sha256.Sum256(wire)
	if !idPattern.MatchString(org) || !idPattern.MatchString(node) ||
		epoch != s.verifier.AuthorizedEpoch || structural <= 0 ||
		membership < 0 || len(wire) == 0 || len(wire) > maxEnvelope ||
		!bytes.Equal(storedDigest, hash[:]) ||
		input.ExpectedSHA256 != hex.EncodeToString(hash[:]) {
		return ApprovalReceipt{}, ErrUnauthorized
	}
	verified, err := s.verify(node, wire)
	if err != nil {
		return ApprovalReceipt{}, err
	}
	if verified.Manifest.ControlPlaneEpoch != epoch ||
		verified.Manifest.StructuralSequence != uint64(structural) ||
		verified.Manifest.MembershipSequence != uint64(membership) {
		return ApprovalReceipt{}, ErrUnauthorized
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return ApprovalReceipt{}, fmt.Errorf("read approval clock: %w", err)
	}
	if !proposalExpiry.After(now) {
		return ApprovalReceipt{}, ErrUnauthorized
	}
	reviewer, err := sessionProof(ctx, tx, sessionHash, org, now, false)
	if err != nil {
		return ApprovalReceipt{}, err
	}
	if reviewer.adminID == proposerAdmin {
		return ApprovalReceipt{}, ErrUnauthorized
	}
	var originalSession int
	err = tx.QueryRowContext(ctx, revalidateProposerSQL, proposerSession,
		proposerHash, org, proposerAdmin, now, proposerCounter).Scan(&originalSession)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalReceipt{}, ErrUnauthorized
	}
	if err != nil {
		return ApprovalReceipt{}, fmt.Errorf("revalidate first administrator: %w", err)
	}
	if err := checkBinding(ctx, tx, node, org, now); err != nil {
		return ApprovalReceipt{}, err
	}
	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM agent_desired_publish_decisions
WHERE proposal_id=$1::uuid`, input.ProposalID).Scan(&exists)
	if err == nil {
		return ApprovalReceipt{}, ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ApprovalReceipt{}, fmt.Errorf("inspect existing publication decision: %w", err)
	}
	approvalID, err := newUUID()
	if err != nil {
		return ApprovalReceipt{}, fmt.Errorf("generate unpredictable approval ID: %w", err)
	}
	expires := proposalExpiry
	if next := now.Add(approvedLifetime); next.Before(expires) {
		expires = next
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_desired_publish_approvals
(approval_id,organization_id,node_id,control_plane_epoch,structural_sequence,
membership_sequence,envelope_sha256,issuer_admin_id,approver_admin_id,created_at,expires_at)
VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11)`,
		approvalID, org, node, epoch, structural, membership, hash[:],
		proposerAdmin, reviewer.adminID, now, expires)
	if err != nil {
		return ApprovalReceipt{}, fmt.Errorf("record independently approved publication: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_desired_publish_decisions
(proposal_id,approval_id,approver_admin_id,approver_session_id,
approver_session_hash,approver_stepup_counter,reviewed_sha256,approved_at)
VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)`,
		input.ProposalID, approvalID, reviewer.adminID, reviewer.sessionID,
		sessionHash, reviewer.counter, hash[:], now)
	if err != nil {
		return ApprovalReceipt{}, fmt.Errorf("record immutable two-person decision: %w", err)
	}
	var stillCurrent time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&stillCurrent); err != nil {
		return ApprovalReceipt{}, fmt.Errorf("recheck approval deadline: %w", err)
	}
	if !expires.After(stillCurrent) {
		return ApprovalReceipt{}, ErrUnauthorized
	}
	if err := stillFreshSession(ctx, tx, proposerHash, org, session{
		adminID: proposerAdmin, sessionID: proposerSession, counter: proposerCounter,
	}, true, expires); err != nil {
		return ApprovalReceipt{}, err
	}
	if err := stillFreshSession(ctx, tx, sessionHash, org, reviewer, false, expires); err != nil {
		return ApprovalReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return ApprovalReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return ApprovalReceipt{}, fmt.Errorf("commit independent publication decision: %w", err)
	}
	return ApprovalReceipt{ProposalID: input.ProposalID, ApprovalID: approvalID,
		NodeID: node, EnvelopeSHA256: hex.EncodeToString(hash[:]), ExpiresAt: expires}, nil
}
