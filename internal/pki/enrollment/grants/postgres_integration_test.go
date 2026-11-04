//go:build postgres_integration

package grants

import (
	"bytes"
	"context"
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

	_ "github.com/lib/pq"
)

const (
	otherNode = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc"
	thirdNode = "1dd5747c-5adc-471f-a933-0c9f72f3ca9c"
)

func TestPostgresAdminApprovedNodeGrants(t *testing.T) {
	dsn := os.Getenv("OMNIPANEL_TEST_POSTGRES_DSN")
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme != "postgres" || parsed.Hostname() != "127.0.0.1" ||
		parsed.Path != "/omnipanel_enrollment_test" {
		t.Fatal("requires isolated local omnipanel_enrollment_test PostgreSQL database")
	}
	ctx := context.Background()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(16)
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	// Migration 0001 is a distinct legacy contract, not modified or certified
	// by this test. Exercise the exact auth/node columns this service reads.
	const authFixture = `
CREATE TABLE admins(id serial PRIMARY KEY,email text NOT NULL UNIQUE,password_hash text NOT NULL,role text NOT NULL,totp_enabled boolean NOT NULL,created_at timestamptz NOT NULL);
CREATE TABLE admin_sessions(id serial PRIMARY KEY,admin_id integer NOT NULL REFERENCES admins(id),token_hash text NOT NULL UNIQUE,created_at timestamptz NOT NULL,last_seen_at timestamptz NOT NULL,expires_at timestamptz NOT NULL);
CREATE TABLE nodes(id serial PRIMARY KEY,status text NOT NULL);`
	if _, err := db.ExecContext(ctx, authFixture); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "db", "migrations", "0005_agent_admin_grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("real PostgreSQL admin grant migration failed: %v", err)
	}
	issuer, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	session := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xA3}, 32))
	sessionHash := sha256.Sum256([]byte(session))
	seed := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO admins(id,email,password_hash,role,totp_enabled,created_at) VALUES
(11,'issuer@test.invalid','none','owner',true,$1),
(12,'approver@test.invalid','none','owner',true,$1),
(13,'operator@test.invalid','none','operator',true,$1)`, []any{now.Add(-time.Hour)}},
		{`INSERT INTO admin_sessions(id,admin_id,token_hash,created_at,last_seen_at,expires_at)
VALUES (21,11,$1,$2,$3,$4)`, []any{hex.EncodeToString(sessionHash[:]), now.Add(-10 * time.Minute), now, now.Add(time.Hour)}},
		{`INSERT INTO nodes(id,status) VALUES (31,'pending_enrollment'),(32,'pending_enrollment'),(33,'pending_enrollment')`, nil},
		{`INSERT INTO agent_grant_organizations(organization_id,state) VALUES($1,'active')`, []any{organizationID}},
		{`INSERT INTO agent_grant_admin_scopes(admin_id,organization_id,can_issue,can_approve) VALUES
(11,$1,true,false),(12,$1,false,true),(13,$1,true,false)`, []any{organizationID}},
		{`INSERT INTO agent_grant_stepups(session_id,method,verified_at,expires_at)
VALUES (21,'totp',$1,$2)`, []any{now, now.Add(5 * time.Minute)}},
		{`INSERT INTO agent_grant_node_bindings(node_id,legacy_node_id,organization_id,state,approved_by,approved_at)
VALUES ($1,31,$4,'approved',12,$5),($2,32,$4,'approved',12,$5),($3,33,$4,'approved',12,$5)`, []any{nodeID, otherNode, thirdNode, organizationID, now}},
	}
	for _, item := range seed {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatalf("invalid trusted test fixture: %v", err)
		}
	}
	request := func(node, correlation string) Request {
		return Request{AdminSessionToken: session, OrganizationID: organizationID, NodeID: node, CorrelationID: correlation, Lifetime: 5 * time.Minute}
	}
	count := func(table string) int {
		t.Helper()
		var n int
		// All table identifiers are source constants, never request values.
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	assertDenied := func(r Request, kind error) {
		t.Helper()
		before := count("agent_grant_audit")
		out, err := issuer.Issue(ctx, r)
		if !errors.Is(err, kind) || out.Token != "" || out.AuditID != 0 {
			t.Fatalf("invalid authorization returned a bearer: returned=%t err=%v wanted=%v", out.Token != "", err, kind)
		}
		if count("agent_grant_audit") != before {
			t.Fatal("denied operation changed durable audit")
		}
	}

	t.Run("session-bound two-person approval and atomic audit", func(t *testing.T) {
		out, err := issuer.Issue(ctx, request(nodeID, correlationID))
		if err != nil {
			t.Fatal(err)
		}
		if out.NodeID != nodeID || out.OrganizationID != organizationID || out.AuditID <= 0 || len(out.Token) != 43 || !out.ExpiresAt.After(now) {
			t.Fatal("valid approved grant or audit metadata missing")
		}
		raw, err := base64.RawURLEncoding.DecodeString(out.Token)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		var dbDigest, auditDigest []byte
		var adminID, auditAdmin int
		if err := db.QueryRowContext(ctx, `SELECT g.token_digest,i.actor_admin_id
FROM agent_enrollment_grants g JOIN agent_grant_issues i ON i.token_digest=g.token_digest
WHERE g.node_id=$1`, nodeID).Scan(&dbDigest, &adminID); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT token_digest,actor_admin_id FROM agent_grant_audit WHERE audit_id=$1`, out.AuditID).Scan(&auditDigest, &auditAdmin); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dbDigest, digest[:]) || !bytes.Equal(auditDigest, dbDigest) || adminID != 11 || auditAdmin != 11 {
			t.Fatal("grant, issuer metadata and audit did not commit consistently")
		}
		if count("agent_grant_issues") != 1 || count("agent_grant_audit") != 1 {
			t.Fatal("missing or duplicate issue/audit")
		}
		assertDenied(request(nodeID, "e090a8e3-12fd-48d5-8dc4-0ab999a3da03"), ErrConflict)
		if _, err := db.ExecContext(ctx, `UPDATE agent_enrollment_grants SET consumed_at=extract(epoch FROM clock_timestamp())::bigint WHERE token_digest=$1`, dbDigest); err != nil {
			t.Fatal(err)
		}
		assertDenied(request(nodeID, correlationID), ErrConflict)
	})

	t.Run("owner, org, step-up and approval policy fail closed", func(t *testing.T) {
		r := request(otherNode, "b090a8e3-12fd-48d5-8dc4-0ab999a3da03")
		r.AdminSessionToken = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x2B}, 32))
		assertDenied(r, ErrUnauthorized)
		r = request(otherNode, "b090a8e3-12fd-48d5-8dc4-0ab999a3da03")
		mutate := func(query string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, query, args...); err != nil {
				t.Fatal(err)
			}
		}
		mutate("UPDATE admins SET role='operator' WHERE id=11")
		assertDenied(r, ErrUnauthorized)
		mutate("UPDATE admins SET role='owner' WHERE id=11")
		mutate("UPDATE agent_grant_admin_scopes SET can_issue=false WHERE admin_id=11")
		assertDenied(r, ErrUnauthorized)
		mutate("UPDATE agent_grant_admin_scopes SET can_issue=true WHERE admin_id=11")
		mutate("UPDATE agent_grant_stepups SET verified_at=$1,expires_at=$2 WHERE session_id=21", now.Add(-8*time.Minute), now.Add(4*time.Minute))
		assertDenied(r, ErrUnauthorized)
		mutate("UPDATE agent_grant_stepups SET verified_at=$1,expires_at=$2 WHERE session_id=21", now, now.Add(5*time.Minute))
		mutate("UPDATE admin_sessions SET last_seen_at=$1 WHERE id=21", now.Add(-3*time.Hour))
		assertDenied(r, ErrUnauthorized)
		mutate("UPDATE admin_sessions SET last_seen_at=$1 WHERE id=21", now)
		mutate("UPDATE agent_grant_organizations SET state='suspended' WHERE organization_id=$1", organizationID)
		assertDenied(r, ErrNotApproved)
		mutate("UPDATE agent_grant_organizations SET state='active' WHERE organization_id=$1", organizationID)
		mutate("UPDATE agent_grant_node_bindings SET approved_by=11 WHERE node_id=$1", otherNode)
		assertDenied(r, ErrNotApproved)
		mutate("UPDATE agent_grant_node_bindings SET approved_by=12 WHERE node_id=$1", otherNode)
		mutate("UPDATE agent_grant_admin_scopes SET can_approve=false WHERE admin_id=12")
		assertDenied(r, ErrNotApproved)
		mutate("UPDATE agent_grant_admin_scopes SET can_approve=true WHERE admin_id=12")
		mutate("UPDATE nodes SET status='quarantined' WHERE id=32")
		assertDenied(r, ErrNotApproved)
		mutate("UPDATE nodes SET status='pending_enrollment' WHERE id=32")
		mutate("UPDATE agent_grant_node_bindings SET state='revoked' WHERE node_id=$1", otherNode)
		assertDenied(r, ErrNotApproved)
		mutate("UPDATE agent_grant_node_bindings SET state='approved' WHERE node_id=$1", otherNode)
		badOrg := r
		badOrg.OrganizationID = "4b0895aa-1701-4c6d-8b31-91d642c23e1c"
		assertDenied(badOrg, ErrUnauthorized)
	})

	t.Run("failed audit insert rolls back token and issue", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `CREATE FUNCTION fail_grant_audit_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END; $$`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER fail_grant_audit_test BEFORE INSERT ON agent_grant_audit FOR EACH ROW EXECUTE FUNCTION fail_grant_audit_test()`); err != nil {
			t.Fatal(err)
		}
		beforeTokens, beforeAudit := count("agent_enrollment_grants"), count("agent_grant_audit")
		out, err := issuer.Issue(ctx, request(otherNode, "d090a8e3-12fd-48d5-8dc4-0ab999a3da03"))
		if err == nil || out.Token != "" {
			t.Fatal("unaudited token escaped")
		}
		if count("agent_enrollment_grants") != beforeTokens || count("agent_grant_audit") != beforeAudit {
			t.Fatal("transaction left unaudited token")
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER fail_grant_audit_test ON agent_grant_audit`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DROP FUNCTION fail_grant_audit_test()`); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("simultaneous grant requests serialize on approved binding", func(t *testing.T) {
		var success, conflicts, failures atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				corr := fmt.Sprintf("f090a8e3-12fd-48d5-8dc4-%012x", i+1)
				out, err := issuer.Issue(ctx, request(thirdNode, corr))
				if err == nil && out.Token != "" && out.AuditID > 0 {
					success.Add(1)
				} else if errors.Is(err, ErrConflict) {
					conflicts.Add(1)
				} else {
					failures.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if success.Load() != 1 || conflicts.Load() != 11 || failures.Load() != 0 {
			t.Fatalf("grant serialization failed: success=%d conflict=%d error=%d", success.Load(), conflicts.Load(), failures.Load())
		}
		if count("agent_grant_issues") != 2 || count("agent_grant_audit") != 2 {
			t.Fatal("missing/extra atomic audits")
		}
		if _, err := db.ExecContext(ctx, `UPDATE agent_grant_audit SET action='other'`); err == nil {
			t.Fatal("audit UPDATE allowed")
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM agent_grant_audit`); err == nil {
			t.Fatal("audit DELETE allowed")
		}
	})

	t.Run("database outage never returns uncommitted bearer", func(t *testing.T) {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		out, err := issuer.Issue(ctx, request(otherNode, "a090a8e3-12fd-48d5-8dc4-0ab999a3da03"))
		if err == nil || out.Token != "" {
			t.Fatal("database outage issued unaudited token")
		}
	})
}
