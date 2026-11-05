//go:build postgres_integration

package desiredpublish

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/gateway/desiredapi"
	_ "github.com/lib/pq"
)

const fixtureOrganization = "4b0895aa-1701-4c6d-8b31-91d642c23e1c"

func TestPostgresApprovedSignedPublication(t *testing.T) {
	dsn := os.Getenv("OMNIPANEL_TEST_POSTGRES_DSN")
	endpoint, err := url.Parse(dsn)
	if err != nil || endpoint.Scheme != "postgres" ||
		endpoint.Hostname() != "127.0.0.1" || endpoint.Path != "/omnipanel_enrollment_test" {
		t.Fatal("requires disposable local omnipanel_enrollment_test PostgreSQL")
	}
	ctx := context.Background()
	root, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err := root.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	var salt [10]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatal(err)
	}
	schema := "publish_chain_" + hex.EncodeToString(salt[:])
	if _, err := root.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := root.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
	})
	q := endpoint.Query()
	q.Set("options", "-csearch_path="+schema)
	endpoint.RawQuery = q.Encode()
	db, err := sql.Open("postgres", endpoint.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(16)
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if schema != "publish_chain_"+hex.EncodeToString(salt[:]) {
		t.Fatal("test not isolated to a random schema")
	}
	for _, name := range []string{
		"0001_initial.sql", "0002_m2.sql", "0003_agent_enrollment.sql",
		"0004_agent_enrollment_rate_limits.sql", "0005_agent_admin_grants.sql",
		"0006_agent_grant_logout_revocation.sql", "0007_agent_grant_verified_stepup.sql",
		"0008_agent_signed_desired.sql", "0009_agent_signed_publication.sql",
		"0010_agent_desired_dual_approval.sql",
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "db", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, string(data)); err != nil {
			t.Fatalf("full PostgreSQL migration %s failed: %v", name, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	// The original session token hashes, not only administrator IDs, must
	// survive in immutable decision provenance. No plaintext token is stored.
	proposerToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa3}, 32))
	reviewerToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb7}, 32))
	proposerHash := sha256.Sum256([]byte(proposerToken))
	reviewerHash := sha256.Sum256([]byte(reviewerToken))
	for _, seed := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO admins(id,email,password_hash,role,totp_enabled,created_at) VALUES
(11,'pub-issuer@test.invalid','none','owner',true,$1),
(12,'pub-approver@test.invalid','none','owner',true,$1)`, []any{now.Add(-time.Hour)}},
		{`INSERT INTO admin_sessions(id,admin_id,token_hash,created_at,last_seen_at,expires_at)
VALUES (21,11,$1,$3,$3,$4),(22,12,$2,$3,$3,$4)`,
			[]any{hex.EncodeToString(proposerHash[:]), hex.EncodeToString(reviewerHash[:]), now, now.Add(time.Hour)}},
		{`INSERT INTO agent_grant_stepups(session_id,method,verified_at,expires_at,verified_counter,verified_source)
VALUES (21,'totp',$1,$2,41,'trusted'),(22,'totp',$1,$2,42,'trusted')`,
			[]any{now, now.Add(5*time.Minute)}},
		{`INSERT INTO nodes(id,name,public_address,provider,status)
VALUES (31,'publisher-node','192.0.2.31','fixture','pending_enrollment')`, nil},
		{"INSERT INTO agent_grant_organizations(organization_id,state) VALUES($1,'active')", []any{fixtureOrganization}},
		{`INSERT INTO agent_grant_admin_scopes(admin_id,organization_id,can_issue,can_approve)
VALUES (11,$1,false,false),(12,$1,false,false)`, []any{fixtureOrganization}},
		{`INSERT INTO agent_desired_publish_permissions(admin_id,organization_id,can_propose,can_approve)
VALUES (11,$1,true,false),(12,$1,false,true)`, []any{fixtureOrganization}},
		{`INSERT INTO agent_grant_node_bindings
(node_id,legacy_node_id,organization_id,state,approved_by,approved_at)
VALUES($1,31,$2,'approved',12,$3)`, []any{fixtureNode, fixtureOrganization, now.Add(-time.Minute)}},
	} {
		if _, err := db.ExecContext(ctx, seed.query, seed.args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(table string) int {
		t.Helper()
		var v int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	approval := func(id string, seq, membership uint64, wire []byte, expiry time.Time) {
		t.Helper()
		digest := sha256.Sum256(wire)
		_, err := db.ExecContext(ctx, `INSERT INTO agent_desired_publish_approvals
(approval_id,organization_id,node_id,control_plane_epoch,structural_sequence,membership_sequence,
envelope_sha256,issuer_admin_id,approver_admin_id,created_at,expires_at)
VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,11,12,$8,$9)`,
			id, fixtureOrganization, fixtureNode, fixtureEpoch,
			int64(seq), int64(membership), digest[:], now.Add(-time.Minute), expiry)
		if err != nil {
			t.Fatal(err)
		}
		// These are test-only provenanced rows: the approval writer is
		// tested independently in desiredapproval's PostgreSQL suite.
		// A publisher must refuse any bare approval without both proofs.
		_, err = db.ExecContext(ctx, `INSERT INTO agent_desired_publish_proposals
(proposal_id,organization_id,node_id,control_plane_epoch,structural_sequence,
membership_sequence,envelope_sha256,envelope,proposer_admin_id,proposer_session_id,
proposer_session_hash,proposer_stepup_counter,created_at,expires_at)
VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,11,21,$9,41,$10,$11)`,
			id, fixtureOrganization, fixtureNode, fixtureEpoch,
			int64(seq), int64(membership), digest[:], wire,
			hex.EncodeToString(proposerHash[:]), now.Add(-time.Minute), expiry)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.ExecContext(ctx, `INSERT INTO agent_desired_publish_decisions
(proposal_id,approval_id,approver_admin_id,approver_session_id,
approver_session_hash,approver_stepup_counter,reviewed_sha256,approved_at)
VALUES($1::uuid,$1::uuid,12,22,$2,42,$3,$4)`,
			id, hex.EncodeToString(reviewerHash[:]), digest[:], now.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
	}
	wire1, verifier := fixtureSignedPublication(t, 1, 1)
	publisher, err := New(db, verifier)
	if err != nil {
		t.Fatal(err)
	}
	const first = "f090a8e3-12fd-48d5-8dc4-0ab999a3da11"
	approval(first, 1, 1, wire1, now.Add(10*time.Minute))
	receipt, err := publisher.PublishSigned(ctx, first, fixtureNode, wire1)
	if err != nil || receipt.AuditID <= 0 || receipt.StructuralSequence != 1 || receipt.Epoch != fixtureEpoch {
		t.Fatalf("first signed publication failed: %+v %v", receipt, err)
	}
	if count("agent_desired_revisions") != 1 || count("agent_desired_heads") != 1 ||
		count("agent_desired_publish_audit") != 1 || count("agent_desired_publish_outbox") != 1 {
		t.Fatal("committed publication is missing revision/head/audit/outbox")
	}
	source, err := desiredapi.NewSQLSource(db)
	if err != nil {
		t.Fatal(err)
	}
	current, err := source.Latest(ctx, fixtureNode)
	if err != nil || !bytes.Equal(current.Envelope, wire1) || current.StructuralSequence != 1 {
		t.Fatalf("committed signed revision unavailable to the node: %+v %v", current, err)
	}
	if _, err := publisher.PublishSigned(ctx, first, fixtureNode, wire1); !errors.Is(err, ErrUnauthorizedPublication) {
		t.Fatalf("reused approval published twice: %v", err)
	}

	wire2, _ := fixtureSignedPublication(t, 2, 2)
	const second = "f090a8e3-12fd-48d5-8dc4-0ab999a3da12"
	const concurrent = "f090a8e3-12fd-48d5-8dc4-0ab999a3da13"
	approval(second, 2, 2, wire2, now.Add(10*time.Minute))
	approval(concurrent, 2, 2, wire2, now.Add(10*time.Minute))
	tampered := bytes.Replace(wire2, []byte("reality"), []byte("altered"), 1)
	if _, err := publisher.PublishSigned(ctx, second, fixtureNode, tampered); !errors.Is(err, ErrUnauthorizedPublication) {
		t.Fatalf("tampered signed manifest accepted: %v", err)
	}
	var success, conflicts, failed atomic.Int32
	var wg sync.WaitGroup
	for _, id := range []string{second, concurrent} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, err := publisher.PublishSigned(ctx, id, fixtureNode, wire2)
			switch {
			case err == nil:
				success.Add(1)
			case errors.Is(err, ErrSequenceConflict):
				conflicts.Add(1)
			default:
				failed.Add(1)
			}
		}(id)
	}
	wg.Wait()
	if success.Load() != 1 || conflicts.Load() != 1 || failed.Load() != 0 {
		t.Fatalf("concurrent publication was not serialized: success=%d conflicts=%d other=%d",
			success.Load(), conflicts.Load(), failed.Load())
	}
	if count("agent_desired_revisions") != 2 || count("agent_desired_publish_outbox") != 2 {
		t.Fatal("concurrency produced duplicate committed intents")
	}

	wire3, _ := fixtureSignedPublication(t, 3, 2)
	const third = "f090a8e3-12fd-48d5-8dc4-0ab999a3da14"
	approval(third, 3, 2, wire3, now.Add(10*time.Minute))
	if _, err := db.ExecContext(ctx, "UPDATE agent_grant_organizations SET state='suspended' WHERE organization_id=$1", fixtureOrganization); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishSigned(ctx, third, fixtureNode, wire3); !errors.Is(err, ErrUnauthorizedPublication) {
		t.Fatalf("suspended organization still published: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE agent_grant_organizations SET state='active' WHERE organization_id=$1", fixtureOrganization); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE agent_desired_publish_permissions SET can_propose=false WHERE admin_id=11"); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishSigned(ctx, third, fixtureNode, wire3); !errors.Is(err, ErrUnauthorizedPublication) {
		t.Fatalf("revoked signer authority still published: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE agent_desired_publish_permissions SET can_propose=true WHERE admin_id=11"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE agent_grant_node_bindings SET state='revoked' WHERE node_id=$1", fixtureNode); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishSigned(ctx, third, fixtureNode, wire3); !errors.Is(err, ErrUnauthorizedPublication) {
		t.Fatalf("revoked node binding still published: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE agent_grant_node_bindings SET state='approved' WHERE node_id=$1", fixtureNode); err != nil {
		t.Fatal(err)
	}

	// Inject a failure after both approval consumption and head mutation.
	// The transaction must roll everything back, allowing a safe retry.
	_, err = db.ExecContext(ctx, `CREATE FUNCTION refuse_publication_audit_test()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit test failure'; END; $$`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `CREATE TRIGGER refuse_publication_audit_test
BEFORE INSERT ON agent_desired_publish_audit FOR EACH ROW
EXECUTE FUNCTION refuse_publication_audit_test()`)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := publisher.PublishSigned(ctx, third, fixtureNode, wire3); err == nil || receipt.AuditID != 0 {
		t.Fatal("unaudited signed revision escaped the transaction")
	}
	if count("agent_desired_revisions") != 2 || count("agent_desired_heads") != 1 ||
		count("agent_desired_publish_outbox") != 2 {
		t.Fatal("failed audit left a partial head or outbox")
	}
	var consumed sql.NullTime
	if err := db.QueryRowContext(ctx, "SELECT consumed_at FROM agent_desired_publish_approvals WHERE approval_id=$1", third).Scan(&consumed); err != nil || consumed.Valid {
		t.Fatalf("failed publication consumed its authorization: %v %v", consumed, err)
	}
	if _, err := db.ExecContext(ctx, "DROP TRIGGER refuse_publication_audit_test ON agent_desired_publish_audit"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DROP FUNCTION refuse_publication_audit_test()"); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishSigned(ctx, third, fixtureNode, wire3); err != nil {
		t.Fatalf("approval could not be safely retried after audit rollback: %v", err)
	}
	if count("agent_desired_publish_audit") != 3 || count("agent_desired_publish_outbox") != 3 {
		t.Fatal("successful retry lacked audit/outbox pair")
	}

	// A bare preapproval row is NOT evidence of a separately authenticated
	// second operator. It must never permit publication without its immutable
	// proposal/decision chain, even for a correctly signed next revision.
	wire4, _ := fixtureSignedPublication(t, 4, 2)
	digest4 := sha256.Sum256(wire4)
	const bare = "f090a8e3-12fd-48d5-8dc4-0ab999a3da15"
	_, err = db.ExecContext(ctx, `INSERT INTO agent_desired_publish_approvals
(approval_id,organization_id,node_id,control_plane_epoch,structural_sequence,membership_sequence,
envelope_sha256,issuer_admin_id,approver_admin_id,created_at,expires_at)
VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,4,2,$5,11,12,$6,$7)`,
		bare, fixtureOrganization, fixtureNode, fixtureEpoch, digest4[:], now.Add(-time.Minute), now.Add(10*time.Minute))
	if err != nil { t.Fatal(err) }
	if _, err := publisher.PublishSigned(ctx, bare, fixtureNode, wire4); !errors.Is(err, ErrUnauthorizedPublication) {
		t.Fatalf("approval row without immutable two-person provenance was accepted: %v", err)
	}
	const fourth = "f090a8e3-12fd-48d5-8dc4-0ab999a3da16"
	approval(fourth, 4, 2, wire4, now.Add(10*time.Minute))
	if _, err := db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE id=22"); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishSigned(ctx, fourth, fixtureNode, wire4); !errors.Is(err, ErrUnauthorizedPublication) {
		t.Fatalf("logged-out approver's old decision remained redeemable: %v", err)
	}

	for _, query := range []string{
		"DELETE FROM agent_desired_publish_audit",
		"UPDATE agent_desired_publish_audit SET membership_sequence=0",
		"DELETE FROM agent_desired_publish_outbox",
		"UPDATE agent_desired_publish_outbox SET structural_sequence=1",
		fmt.Sprintf("UPDATE agent_desired_publish_approvals SET envelope_sha256=decode('%064x','hex') WHERE approval_id='%s'", 2, third),
	} {
		if _, err := db.ExecContext(ctx, query); err == nil {
			t.Fatalf("immutable approval/audit/outbox history changed: %s", query)
		}
	}
}
