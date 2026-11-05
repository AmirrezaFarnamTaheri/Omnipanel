//go:build postgres_integration

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
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
	_ "github.com/lib/pq"
)

func signedApprovalFixture(t *testing.T, now time.Time) ([]byte, manifest.Verifier) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	artifact := strings.Repeat("a", 64)
	m := manifest.Manifest{
		SchemaVersion: "2.0", ControlPlaneEpoch: testEpoch, NodeID: testNode,
		StructuralSequence: 1, MembershipSequence: 1,
		IssuedAt: now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(10*time.Minute).Format(time.RFC3339),
		RequiredCapabilities: []string{"singbox-reality-vision"},
		Components: []manifest.Component{{
			ID: "reality", Driver: "singbox", RuntimeVersion: "1.14.4+omni.2",
			ArtifactDigest: artifact, ConfigurationDigest: strings.Repeat("b", 64),
			ConfigurationRef: "reality-config", DependsOn: []string{},
			Listeners: []manifest.Listener{{Address: "0.0.0.0", Port: 443, Transport: "tcp"}},
			Disruption: "listener_restart",
		}}, BaseEgressPolicy: "deny-protected-v1",
	}
	raw, err := json.Marshal(m)
	if err != nil { t.Fatal(err) }
	var obj any
	if err := json.Unmarshal(raw, &obj); err != nil { t.Fatal(err) }
	canonical, err := json.Marshal(obj)
	if err != nil { t.Fatal(err) }
	digest := sha256.Sum256(canonical)
	signature := ed25519.Sign(key, append([]byte("omnipanel:desired-state:ed25519-jcs-v1\n"), canonical...))
	wire, err := json.Marshal(manifest.Envelope{
		SignatureVersion: "ed25519-jcs-v1", SignerID: "trusted-test",
		ContentDigest: hex.EncodeToString(digest[:]),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
		Manifest: m,
	})
	if err != nil { t.Fatal(err) }
	verifier := testVerifier()
	verifier.TrustedSigners = map[string]ed25519.PublicKey{"trusted-test": key.Public().(ed25519.PublicKey)}
	verifier.Now = func() time.Time { return now }
	return wire, verifier
}

func TestPostgresDualOperatorSignedApproval(t *testing.T) {
	dsn := os.Getenv("OMNIPANEL_TEST_POSTGRES_DSN")
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Path != "/omnipanel_enrollment_test" {
		t.Fatal("requires disposable local PostgreSQL database only")
	}
	ctx := context.Background()
	admin, err := sql.Open("postgres", dsn)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = admin.Close() })
	if err := admin.PingContext(ctx); err != nil { t.Fatal(err) }
	var salt [8]byte
	if _, err := rand.Read(salt[:]); err != nil { t.Fatal(err) }
	schema := "approval_chain_" + hex.EncodeToString(salt[:])
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil { t.Fatal(err) }
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
	})
	query := u.Query()
	query.Set("options", "-csearch_path="+schema)
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(8)
	var actual string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&actual); err != nil || actual != schema {
		t.Fatalf("unexpected schema: %q %v", actual, err)
	}
	for _, name := range []string{
		"0001_initial.sql", "0002_m2.sql", "0003_agent_enrollment.sql",
		"0004_agent_enrollment_rate_limits.sql", "0005_agent_admin_grants.sql",
		"0006_agent_grant_logout_revocation.sql", "0007_agent_grant_verified_stepup.sql",
		"0008_agent_signed_desired.sql", "0009_agent_signed_publication.sql",
		"0010_agent_desired_dual_approval.sql",
	} {
		migration, err := os.ReadFile(filepath.Join("..", "..", "..", "db", "migrations", name))
		if err != nil { t.Fatal(err) }
		if _, err := db.ExecContext(ctx, string(migration)); err != nil {
			t.Fatalf("migration %s failed: %v", name, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	proposerToken := testToken()
	reviewerToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb7}, 32))
	proposerHash := sha256.Sum256([]byte(proposerToken))
	reviewerHash := sha256.Sum256([]byte(reviewerToken))
	fixtures := []struct { query string; args []any }{
		{`INSERT INTO admins(id,email,password_hash,role,totp_enabled,created_at)
VALUES (11,'desired-proposer@test.invalid','none','owner',true,$1),
       (12,'desired-reviewer@test.invalid','none','owner',true,$1)`, []any{now.Add(-time.Hour)}},
		{`INSERT INTO admin_sessions(id,admin_id,token_hash,created_at,last_seen_at,expires_at)
VALUES (21,11,$1,$3,$3,$4),(22,12,$2,$3,$3,$4)`,
			[]any{hex.EncodeToString(proposerHash[:]), hex.EncodeToString(reviewerHash[:]), now, now.Add(time.Hour)}},
		{`INSERT INTO agent_grant_stepups(session_id,method,verified_at,expires_at,verified_counter,verified_source)
VALUES (21,'totp',$1,$2,41,'trusted'),(22,'totp',$1,$2,42,'trusted')`,
			[]any{now, now.Add(5*time.Minute)}},
		{`INSERT INTO nodes(id,name,public_address,provider,status)
VALUES (31,'desired-approval-node','192.0.2.31','fixture','active')`, nil},
		{"INSERT INTO agent_grant_organizations(organization_id,state) VALUES($1,'active')", []any{testOrg}},
		{`INSERT INTO agent_desired_publish_permissions(admin_id,organization_id,can_propose,can_approve)
-- Proposer deliberately also has reviewer scope: identity separation,
-- not just a missing permission bit, must reject self-review/self-approval.
VALUES (11,$1,true,true),(12,$1,false,true)`, []any{testOrg}},
		{`INSERT INTO agent_grant_node_bindings(node_id,legacy_node_id,organization_id,state,approved_by,approved_at)
VALUES($1,31,$2,'approved',12,$3)`, []any{testNode, testOrg, now.Add(-time.Minute)}},
	}
	for _, f := range fixtures {
		if _, err := db.ExecContext(ctx, f.query, f.args...); err != nil {
			t.Fatalf("invalid isolated approval fixture: %v", err)
		}
	}
	wire, verifier := signedApprovalFixture(t, now)
	svc, err := NewService(db, verifier)
	if err != nil { t.Fatal(err) }
	hash := sha256.Sum256(wire)
	expected := hex.EncodeToString(hash[:])
	proposal := ProposalRequest{
		SessionToken: proposerToken, ProposalID: testProposal,
		OrganizationID: testOrg, NodeID: testNode,
		Envelope: wire, Lifetime: 5*time.Minute,
	}
	receipt, err := svc.Propose(ctx, proposal)
	if err != nil || receipt.ProposalID != testProposal || receipt.EnvelopeSHA256 != expected {
		t.Fatalf("separately authenticated proposer failed: %+v %v", receipt, err)
	}
	// Reviewer obtains independently authenticated, signed bytes before
	// confirming the exact digest, not a proposer-supplied approval flag.
	preview, err := svc.Review(ctx, ReviewRequest{SessionToken: reviewerToken, ProposalID: testProposal})
	if err != nil || !bytes.Equal(preview.Envelope, wire) ||
		preview.EnvelopeSHA256 != expected || preview.NodeID != testNode {
		t.Fatalf("trusted reviewer could not inspect immutable signed intent: %+v %v", preview, err)
	}
	if _, err := svc.Review(ctx, ReviewRequest{SessionToken: proposerToken, ProposalID: testProposal}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("proposer read proposal as a second independent reviewer: %v", err)
	}
	approveReq := ApprovalRequest{SessionToken: reviewerToken, ProposalID: testProposal, ExpectedSHA256: expected}
	self := approveReq
	self.SessionToken = proposerToken
	if _, err := svc.Approve(ctx, self); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("proposer could self-approve: %v", err)
	}
	wrong := approveReq
	wrong.ExpectedSHA256 = strings.Repeat("a", 64)
	if _, err := svc.Approve(ctx, wrong); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong signed digest approved: %v", err)
	}
	revoke := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil { t.Fatal(err) }
	}
	revoke("UPDATE agent_desired_publish_permissions SET can_approve=false WHERE admin_id=12")
	if _, err := svc.Approve(ctx, approveReq); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked approver authority used: %v", err)
	}
	revoke("UPDATE agent_desired_publish_permissions SET can_approve=true WHERE admin_id=12")
	revoke("UPDATE agent_grant_organizations SET state='suspended' WHERE organization_id=$1", testOrg)
	if _, err := svc.Approve(ctx, approveReq); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("suspended organization approved: %v", err)
	}
	revoke("UPDATE agent_grant_organizations SET state='active' WHERE organization_id=$1", testOrg)
	revoke("UPDATE agent_grant_stepups SET verified_source='legacy' WHERE session_id=22")
	if _, err := svc.Approve(ctx, approveReq); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("untrusted legacy MFA marker approved: %v", err)
	}
	revoke("UPDATE agent_grant_stepups SET verified_source='trusted' WHERE session_id=22")

	// Failed second-stage audit insertion must leave no bearer, no decision,
	// and no partially authorized request for the publisher.
	revoke(`CREATE FUNCTION reject_desired_decision_test() RETURNS trigger LANGUAGE plpgsql
AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END; $$`)
	revoke(`CREATE TRIGGER reject_desired_decision_test
BEFORE INSERT ON agent_desired_publish_decisions
FOR EACH ROW EXECUTE FUNCTION reject_desired_decision_test()`)
	if result, err := svc.Approve(ctx, approveReq); err == nil || result.ApprovalID != "" {
		t.Fatalf("unaudited approval escaped: %+v %v", result, err)
	}
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_desired_publish_approvals").Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed decision left approval: %d %v", n, err)
	}
	revoke("DROP TRIGGER reject_desired_decision_test ON agent_desired_publish_decisions")
	revoke("DROP FUNCTION reject_desired_decision_test()")
	approved, err := svc.Approve(ctx, approveReq)
	if err != nil || approved.ApprovalID == "" || approved.EnvelopeSHA256 != expected {
		t.Fatalf("independent approval failed: %+v %v", approved, err)
	}
	if _, err := svc.Approve(ctx, approveReq); !errors.Is(err, ErrConflict) {
		t.Fatalf("same proposal approved twice: %v", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_desired_publish_decisions").Scan(&n); err != nil || n != 1 {
		t.Fatalf("missing durable two-person decision: %d %v", n, err)
	}
	for _, statement := range []string{
		"UPDATE agent_desired_publish_proposals SET proposer_admin_id=12",
		"DELETE FROM agent_desired_publish_proposals",
		"UPDATE agent_desired_publish_decisions SET approver_admin_id=11",
		"DELETE FROM agent_desired_publish_decisions",
	} {
		if _, err := db.ExecContext(ctx, statement); err == nil {
			t.Fatalf("immutable approval history altered: %s", statement)
		}
	}

	// Logout deletes the source session without deleting immutable history.
	// A recycled serial ID has a different credential hash and cannot reuse
	// that old proposal's TOTP attestation.
	second := proposal
	second.ProposalID = "e090a8e3-12fd-48d5-8dc4-0ab999a3da11"
	if _, err := svc.Propose(ctx, second); err != nil { t.Fatal(err) }
	revoke("DELETE FROM admin_sessions WHERE id=21")
	if _, err := svc.Approve(ctx, ApprovalRequest{
		SessionToken: reviewerToken, ProposalID: second.ProposalID, ExpectedSHA256: expected,
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("logged-out proposer's intent was approved: %v", err)
	}
}
