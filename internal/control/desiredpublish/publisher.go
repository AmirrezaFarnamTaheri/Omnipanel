// Package desiredpublish consumes independently preapproved signed manifest
// publications. It holds no signing key and exposes no public administrator
// endpoint. It must run with a DB identity separate from the read-only gateway.
package desiredpublish

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

var (
	ErrConfiguration = errors.New("invalid signed publication configuration")
	ErrUnauthorizedPublication = errors.New("signed publication is not independently approved")
	ErrSequenceConflict = errors.New("signed publication is not next in trusted epoch")
)

const maxSignedEnvelopeBytes = 1 << 20

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Receipt proves a committed audit/outbox transaction, not a running node
// configuration or a delivered outbox notification.
type Receipt struct {
	AuditID int64
	NodeID string
	Epoch string
	StructuralSequence uint64
	MembershipSequence uint64
}

// Publisher verifies signatures with independently provisioned trust and
// consumes existing two-person approvals. This does NOT issue approvals,
// recover epochs, or create signing keys.
type Publisher struct {
	db *sql.DB
	verifier manifest.Verifier
}

// New freezes trust configuration so caller-side map/key mutation cannot
// broaden the set of accepted signing keys or runtime qualifications later.
func New(db *sql.DB, verifier manifest.Verifier) (*Publisher, error) {
	if db == nil || !uuidPattern.MatchString(verifier.AuthorizedEpoch) ||
		len(verifier.TrustedSigners) == 0 || len(verifier.AllowedCapabilities) == 0 ||
		len(verifier.QualifiedBuilds) == 0 || verifier.MaxClockSkew < 0 {
		return nil, ErrConfiguration
	}
	copied := verifier
	copied.TrustedSigners = make(map[string]ed25519.PublicKey, len(verifier.TrustedSigners))
	for id, key := range verifier.TrustedSigners {
		if len(key) != ed25519.PublicKeySize {
			return nil, ErrConfiguration
		}
		copied.TrustedSigners[id] = append(ed25519.PublicKey(nil), key...)
	}
	copied.AllowedCapabilities = make(map[string]bool, len(verifier.AllowedCapabilities))
	for name, allowed := range verifier.AllowedCapabilities {
		copied.AllowedCapabilities[name] = allowed
	}
	copied.QualifiedBuilds = make(map[string]manifest.Build, len(verifier.QualifiedBuilds))
	for name, build := range verifier.QualifiedBuilds {
		build.Capabilities = append([]string(nil), build.Capabilities...)
		copied.QualifiedBuilds[name] = build
	}
	copied.NodeID = ""
	copied.Current = manifest.Cursor{}
	return &Publisher{db: db, verifier: copied}, nil
}

// The approval is matched against the EXACT signed bytes, protected epoch,
// node, structural sequence and membership cursor. Locks serialize publishers
// for the same binding and guard against concurrent node/org revocation.
// This query never accepts user-supplied roles or node/organization selectors.
const approvedPublication = `SELECT a.issuer_admin_id, a.approver_admin_id
FROM agent_desired_publish_approvals a
JOIN agent_grant_node_bindings b ON b.node_id=a.node_id
 AND b.organization_id=a.organization_id
JOIN agent_grant_organizations org ON org.organization_id=b.organization_id
JOIN nodes n ON n.id=b.legacy_node_id
JOIN admins issuer ON issuer.id=a.issuer_admin_id
JOIN admins approver ON approver.id=a.approver_admin_id
JOIN agent_desired_publish_permissions proposer_perm
 ON proposer_perm.admin_id=issuer.id AND proposer_perm.organization_id=a.organization_id
JOIN agent_desired_publish_permissions approver_perm
 ON approver_perm.admin_id=approver.id AND approver_perm.organization_id=a.organization_id
WHERE a.approval_id=$1::uuid AND a.node_id=$2::uuid
 AND a.control_plane_epoch=$3::uuid AND a.structural_sequence=$4
 AND a.membership_sequence=$5 AND a.envelope_sha256=$6
 AND a.consumed_at IS NULL
 AND a.created_at <= clock_timestamp() AND a.expires_at > clock_timestamp()
 AND b.state='approved' AND b.approved_by=a.approver_admin_id
 AND b.approved_at <= clock_timestamp() AND org.state='active'
 AND n.status IN ('pending_enrollment','active','draining')
 AND issuer.role='owner' AND issuer.totp_enabled AND proposer_perm.can_propose
 AND approver.role='owner' AND approver.totp_enabled AND approver_perm.can_approve
 AND a.issuer_admin_id <> a.approver_admin_id
FOR UPDATE OF a,b
FOR SHARE OF org,n,issuer,approver,proposer_perm,approver_perm`

// PublishSigned is a fail-closed, no-key-custody, transactional publisher.
// The pending approval must have been inserted by a separately protected,
// audited approval writer. Failed inserts/updates or audit/outbox writes roll
// back both the new head and the approval consumption. No HTTP route uses it.
func (p *Publisher) PublishSigned(ctx context.Context, approvalID, nodeID string, wire []byte) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if p == nil || p.db == nil || !uuidPattern.MatchString(approvalID) ||
		!uuidPattern.MatchString(nodeID) || len(wire) == 0 || len(wire) > maxSignedEnvelopeBytes {
		return Receipt{}, ErrUnauthorizedPublication
	}
	v := p.verifier
	v.NodeID = nodeID
	v.Current = manifest.Cursor{}
	verified, err := v.Verify(wire)
	if err != nil || verified.Decision != manifest.ApplyRevision {
		return Receipt{}, ErrUnauthorizedPublication
	}
	m := verified.Manifest
	digest := sha256.Sum256(wire)

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, fmt.Errorf("begin signed publication: %w", err)
	}
	defer tx.Rollback()

	var issuerID, approverID int64
	err = tx.QueryRowContext(ctx, approvedPublication, approvalID, nodeID,
		m.ControlPlaneEpoch, int64(m.StructuralSequence), int64(m.MembershipSequence), digest[:]).
		Scan(&issuerID, &approverID)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, ErrUnauthorizedPublication
	}
	if err != nil {
		return Receipt{}, fmt.Errorf("lock signed publication approval: %w", err)
	}

	// Binding lock above serializes all publisher transactions for a node.
	// A fresh READ COMMITTED statement observes the previous committed head.
	var previousEpoch string
	var previousStructural, previousMembership int64
	err = tx.QueryRowContext(ctx, `SELECT h.control_plane_epoch::text,h.structural_sequence,r.membership_sequence
FROM agent_desired_heads h
JOIN agent_desired_revisions r ON r.node_id=h.node_id
 AND r.control_plane_epoch=h.control_plane_epoch
 AND r.structural_sequence=h.structural_sequence
WHERE h.node_id=$1::uuid FOR UPDATE OF h`, nodeID).
		Scan(&previousEpoch, &previousStructural, &previousMembership)
	hasHead := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, fmt.Errorf("read preceding signed head: %w", err)
	}
	if hasHead {
		if previousEpoch != m.ControlPlaneEpoch ||
			uint64(previousStructural)+1 != m.StructuralSequence ||
			m.MembershipSequence < uint64(previousMembership) {
			return Receipt{}, ErrSequenceConflict
		}
	} else if m.StructuralSequence != 1 {
		return Receipt{}, ErrSequenceConflict
	}

	consumed, err := tx.ExecContext(ctx, `UPDATE agent_desired_publish_approvals
SET consumed_at=clock_timestamp() WHERE approval_id=$1::uuid
AND consumed_at IS NULL AND expires_at > clock_timestamp()`, approvalID)
	if err != nil {
		return Receipt{}, fmt.Errorf("consume signed publication approval: %w", err)
	}
	n, err := consumed.RowsAffected()
	if err != nil || n != 1 {
		return Receipt{}, ErrUnauthorizedPublication
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_desired_revisions
(node_id,control_plane_epoch,structural_sequence,membership_sequence,envelope)
VALUES($1::uuid,$2::uuid,$3,$4,$5)`,
		nodeID, m.ControlPlaneEpoch, int64(m.StructuralSequence), int64(m.MembershipSequence), wire)
	if err != nil {
		return Receipt{}, fmt.Errorf("insert immutable signed revision: %w", err)
	}
	if hasHead {
		_, err = tx.ExecContext(ctx, `UPDATE agent_desired_heads
SET structural_sequence=$2,updated_at=clock_timestamp()
WHERE node_id=$1::uuid AND structural_sequence=$3 AND control_plane_epoch=$4::uuid`,
			nodeID, int64(m.StructuralSequence), previousStructural, m.ControlPlaneEpoch)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO agent_desired_heads
(node_id,control_plane_epoch,structural_sequence) VALUES($1::uuid,$2::uuid,$3)`,
			nodeID, m.ControlPlaneEpoch, int64(m.StructuralSequence))
	}
	if err != nil {
		return Receipt{}, fmt.Errorf("advance signed desired head: %w", err)
	}
	var auditID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO agent_desired_publish_audit
(approval_id,node_id,control_plane_epoch,structural_sequence,membership_sequence,
envelope_sha256,issuer_admin_id,approver_admin_id)
VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8) RETURNING audit_id`,
		approvalID, nodeID, m.ControlPlaneEpoch, int64(m.StructuralSequence),
		int64(m.MembershipSequence), digest[:], issuerID, approverID).Scan(&auditID)
	if err != nil {
		return Receipt{}, fmt.Errorf("append signed publication audit: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_desired_publish_outbox
(audit_id,node_id,structural_sequence) VALUES($1,$2::uuid,$3)`,
		auditID, nodeID, int64(m.StructuralSequence))
	if err != nil {
		return Receipt{}, fmt.Errorf("enqueue signed publication intent: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, fmt.Errorf("commit signed publication: %w", err)
	}
	return Receipt{
		AuditID: auditID, NodeID: nodeID, Epoch: m.ControlPlaneEpoch,
		StructuralSequence: m.StructuralSequence,
		MembershipSequence: m.MembershipSequence,
	}, nil
}
