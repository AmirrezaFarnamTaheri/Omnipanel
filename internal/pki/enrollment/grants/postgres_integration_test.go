//go:build postgres_integration

package grants

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
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

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/pki/enrollment"

	_ "github.com/lib/pq"
)

const (
	otherNode = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc"
	thirdNode = "1dd5747c-5adc-471f-a933-0c9f72f3ca9c"
)

// The integration fixture models a separately protected secret opener.
// It never takes the secret or administrator identity from request inputs.
type fixtureTOTPOpener struct{}

func (fixtureTOTPOpener) OpenTOTP(_ context.Context, id int64, envelope string) ([]byte, error) {
	if id != 11 || envelope != "fixture:encrypted:totp" {
		return nil, errors.New("test key custody refused unbound identity")
	}
	return []byte(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))), nil
}

func TestPostgresAdminApprovedNodeGrants(t *testing.T) {
	dsn := os.Getenv("OMNIPANEL_TEST_POSTGRES_DSN")
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme != "postgres" || parsed.Hostname() != "127.0.0.1" ||
		parsed.Path != "/omnipanel_enrollment_test" {
		t.Fatal("requires isolated local omnipanel_enrollment_test PostgreSQL database")
	}
	ctx := context.Background()
	adminDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adminDB.Close() })
	adminDB.SetMaxOpenConns(4)
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	// Every grant integration run gets an isolated schema and applies the real
	// published migration chain. This catches production-shape drift that a
	// hand-built auth fixture would hide, without colliding with other CI tests.
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "grant_chain_" + hex.EncodeToString(suffix[:])
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop isolated migration schema: %v", err)
		}
	})
	query := parsed.Query()
	query.Set("options", "-csearch_path="+schema)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(16)
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	var currentSchema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&currentSchema); err != nil || currentSchema != schema {
		t.Fatalf("grant test is not isolated to its migration schema: current=%q err=%v", currentSchema, err)
	}
	for _, name := range []string{
		"0001_initial.sql", "0002_m2.sql", "0003_agent_enrollment.sql",
		"0004_agent_enrollment_rate_limits.sql", "0005_agent_admin_grants.sql",
		"0006_agent_grant_logout_revocation.sql", "0007_agent_grant_verified_stepup.sql",
	} {
		migration, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "db", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, string(migration)); err != nil {
			t.Fatalf("full-chain PostgreSQL migration %s failed: %v", name, err)
		}
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
		{`INSERT INTO nodes(id,name,public_address,provider,status) VALUES
(31,'node-31','192.0.2.31','fixture','pending_enrollment'),
(32,'node-32','192.0.2.32','fixture','pending_enrollment'),
(33,'node-33','192.0.2.33','fixture','pending_enrollment')`, nil},
		{`INSERT INTO agent_grant_organizations(organization_id,state) VALUES($1,'active')`, []any{organizationID}},
		{`INSERT INTO agent_grant_admin_scopes(admin_id,organization_id,can_issue,can_approve) VALUES
(11,$1,true,false),(12,$1,false,true),(13,$1,true,false)`, []any{organizationID}},
		{`INSERT INTO agent_grant_stepups(session_id,method,verified_at,expires_at,verified_counter,verified_source)
VALUES (21,'totp',$1,$2,0,'trusted')`, []any{now, now.Add(5 * time.Minute)}},
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

	t.Run("schema rejects trusted factor with missing replay counter", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		_, err = tx.ExecContext(ctx, "UPDATE agent_grant_stepups SET verified_source='trusted', verified_counter=NULL WHERE session_id=21")
		if err == nil {
			t.Fatal("PostgreSQL accepted trusted factor with a missing anti-replay counter")
		}
	})

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

	t.Run("revoked scope or node cannot redeem previously issued bearer", func(t *testing.T) {
		grant, err := issuer.Issue(ctx, request(nodeID, "e990a8e3-12fd-48d5-8dc4-0ab999a3da03"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(grant.Token)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		store, err := enrollment.NewApprovedSQLStore(db)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := store.Lookup(ctx, digest, time.Now().UTC()); err != nil || got != nodeID {
			t.Fatalf("valid authorized grant not recognized: %q, %v", got, err)
		}
		change := func(query string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, query, args...); err != nil {
				t.Fatal(err)
			}
		}
		denied := func(where string) {
			t.Helper()
			if got, err := store.Lookup(ctx, digest, time.Now().UTC()); !errors.Is(err, enrollment.ErrInvalidToken) || got != "" {
				t.Fatalf("%s bypassed at lookup: node=%q err=%v", where, got, err)
			}
		}
		key := sha256.Sum256([]byte("test-only public-key fingerprint"))
		notBefore := time.Now().UTC().Add(-time.Minute)
		notAfter := time.Now().UTC().Add(time.Hour)

		// Invalidate approval after the preliminary lookup, before commit.
		change("UPDATE agent_grant_node_bindings SET state='revoked' WHERE node_id=$1", nodeID)
		if err := store.Commit(ctx, digest, nodeID, "90001", key, notBefore, notAfter, time.Now().UTC()); !errors.Is(err, enrollment.ErrInvalidToken) {
			t.Fatalf("revocation race permitted certificate commit: %v", err)
		}
		denied("revoked node binding")
		var consumed sql.NullInt64
		if err := db.QueryRowContext(ctx, "SELECT consumed_at FROM agent_enrollment_grants WHERE token_digest=$1", digest[:]).Scan(&consumed); err != nil || consumed.Valid {
			t.Fatalf("refused redemption consumed token: consumed=%v err=%v", consumed, err)
		}
		change("UPDATE agent_grant_node_bindings SET state='approved' WHERE node_id=$1", nodeID)

		change("UPDATE agent_grant_organizations SET state='suspended' WHERE organization_id=$1", organizationID)
		denied("suspended organization")
		change("UPDATE agent_grant_organizations SET state='active' WHERE organization_id=$1", organizationID)

		change("UPDATE nodes SET status='quarantined' WHERE id=31")
		denied("quarantined node")
		change("UPDATE nodes SET status='pending_enrollment' WHERE id=31")

		change("UPDATE agent_grant_admin_scopes SET can_issue=false WHERE admin_id=11")
		denied("revoked issuing permission")
		change("UPDATE agent_grant_admin_scopes SET can_issue=true WHERE admin_id=11")

		change("UPDATE agent_grant_admin_scopes SET can_approve=false WHERE admin_id=12")
		denied("revoked second approval")
		change("UPDATE agent_grant_admin_scopes SET can_approve=true WHERE admin_id=12")

		change("UPDATE admins SET role='operator' WHERE id=12")
		denied("demoted approver")
		change("UPDATE admins SET role='owner' WHERE id=12")

		change("UPDATE admin_sessions SET expires_at=clock_timestamp() - interval '1 minute' WHERE id=21")
		denied("expired issuance session")
		change("UPDATE admin_sessions SET expires_at=clock_timestamp() + interval '1 hour' WHERE id=21")

		// A session can become idle-expired after grant issuance while its
		// absolute expiry and the enrollment bearer are still live. Both the
		// preliminary lookup and the locked commit authorization must reject it.
		change("UPDATE admin_sessions SET last_seen_at=clock_timestamp() - interval '2 hours 1 second' WHERE id=21")
		denied("idle-expired issuance session")
		if err := store.Commit(ctx, digest, nodeID, "90001", key, notBefore, notAfter, time.Now().UTC()); !errors.Is(err, enrollment.ErrInvalidToken) {
			t.Fatalf("idle-expired issuance session redeemed grant: %v", err)
		}
		var idleConsumed sql.NullInt64
		if err := db.QueryRowContext(ctx, "SELECT consumed_at FROM agent_enrollment_grants WHERE token_digest=$1", digest[:]).Scan(&idleConsumed); err != nil || idleConsumed.Valid {
			t.Fatalf("idle-expired session redemption consumed grant: consumed=%v err=%v", idleConsumed, err)
		}
		change("UPDATE admin_sessions SET last_seen_at=clock_timestamp() WHERE id=21")

		if err := store.Commit(ctx, digest, nodeID, "90001", key, notBefore, notAfter, time.Now().UTC()); err != nil {
			t.Fatalf("authorized commit refused: %v", err)
		}
		approved, err := store.Active(ctx, nodeID, "90001", key, time.Now().UTC())
		if err != nil || !approved {
			t.Fatalf("registered approved certificate rejected: %v", err)
		}
		change("UPDATE nodes SET status='active' WHERE id=31")
		approved, err = store.Active(ctx, nodeID, "90001", key, time.Now().UTC())
		if err != nil || !approved {
			t.Fatal("approved active node cannot use its previously issued certificate")
		}
		change("UPDATE nodes SET status='quarantined' WHERE id=31")
		approved, err = store.Active(ctx, nodeID, "90001", key, time.Now().UTC())
		if err != nil || approved {
			t.Fatal("quarantined node certificate remained active")
		}
		change("UPDATE nodes SET status='pending_enrollment' WHERE id=31")
		change("UPDATE agent_grant_node_bindings SET state='revoked' WHERE node_id=$1", nodeID)
		approved, err = store.Active(ctx, nodeID, "90001", key, time.Now().UTC())
		if err != nil || approved {
			t.Fatal("revoked binding certificate remained active")
		}
		change("UPDATE agent_grant_node_bindings SET state='approved' WHERE node_id=$1", nodeID)
		change("UPDATE agent_grant_organizations SET state='suspended' WHERE organization_id=$1", organizationID)
		approved, err = store.Active(ctx, nodeID, "90001", key, time.Now().UTC())
		if err != nil || approved {
			t.Fatal("certificate stayed authorized in suspended organization")
		}
		change("UPDATE agent_grant_organizations SET state='active' WHERE organization_id=$1", organizationID)
	})

	t.Run("verified TOTP writer, stale records, replay and attempt budget", func(t *testing.T) {
		change := func(query string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, query, args...); err != nil {
				t.Fatal(err)
			}
		}
		// A legacy/unverified row is not permission to mint a grant even
		// when someone populated its verified_at column recently.
		change("UPDATE agent_grant_stepups SET verified_source='legacy',verified_counter=NULL WHERE session_id=21")
		if output, err := issuer.Issue(ctx, request(otherNode, "d290a8e3-12fd-48d5-8dc4-0ab999a3da03")); !errors.Is(err, ErrUnauthorized) || output.Token != "" {
			t.Fatalf("unverified legacy step-up was admitted: token=%t err=%v", output.Token != "", err)
		}
		change("UPDATE admins SET totp_secret_enc='fixture:encrypted:totp' WHERE id=11")
		verifier, err := NewStepUpService(db, fixtureTOTPOpener{})
		if err != nil {
			t.Fatal(err)
		}
		var postgresNow time.Time
		if err := db.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&postgresNow); err != nil {
			t.Fatal(err)
		}
		secret := []byte("12345678901234567890")
		code := totpCode(secret, postgresNow.Unix()/30)
		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		if err := verifier.Verify(ctx, session, wrong); !errors.Is(err, ErrStepUpCode) {
			t.Fatalf("incorrect factor accepted or storage failure: %v", err)
		}
		if err := verifier.Verify(ctx, session, code); err != nil {
			t.Fatalf("valid time-bound factor rejected: %v", err)
		}
		var verifiedSource string
		var verifiedCounter sql.NullInt64
		if err := db.QueryRowContext(ctx, "SELECT verified_source,verified_counter FROM agent_grant_stepups WHERE session_id=21").Scan(&verifiedSource, &verifiedCounter); err != nil || verifiedSource != "trusted" || !verifiedCounter.Valid {
			t.Fatalf("verified factor not persisted as trusted: source=%q counter=%v err=%v", verifiedSource, verifiedCounter, err)
		}
		// A trusted row permits subsequent authorization checks (the third
		// node intentionally already has one outstanding grant).
		if output, err := issuer.Issue(ctx, request(thirdNode, "d390a8e3-12fd-48d5-8dc4-0ab999a3da03")); !errors.Is(err, ErrConflict) || output.Token != "" {
			t.Fatalf("trusted factor could not reach node-grant check: %v", err)
		}
		if err := verifier.Verify(ctx, session, code); !errors.Is(err, ErrStepUpCode) {
			t.Fatalf("same TOTP counter was reused: %v", err)
		}
		// A second session for the same owner cannot replay a code that
		// was already consumed by the first session.
		otherSession := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xB3}, 32))
		otherDigest := sha256.Sum256([]byte(otherSession))
		change("INSERT INTO admin_sessions(id,admin_id,token_hash,created_at,last_seen_at,expires_at) VALUES(22,11,$1,$2,$2,$3)", hex.EncodeToString(otherDigest[:]), postgresNow.Add(-time.Minute), postgresNow.Add(time.Hour))
		if err := verifier.Verify(ctx, otherSession, code); !errors.Is(err, ErrStepUpCode) {
			t.Fatalf("replay via other session accepted: %v", err)
		}
		change("DELETE FROM admin_sessions WHERE id=22")

		change("UPDATE admins SET role='operator' WHERE id=11")
		if err := verifier.Verify(ctx, session, code); !errors.Is(err, ErrStepUpSession) {
			t.Fatalf("operator role admitted to owner step-up: %v", err)
		}
		change("UPDATE admins SET role='owner' WHERE id=11")
		// Force the current database-clock budget to the limit, avoiding
		// dependence on the external runner's wall-clock window.
		change("INSERT INTO agent_grant_stepup_attempts(admin_id,window_start,hits) VALUES(11,floor(extract(epoch FROM clock_timestamp()) / 300)::bigint,5) ON CONFLICT(admin_id,window_start) DO UPDATE SET hits=5")
		if err := verifier.Verify(ctx, session, wrong); !errors.Is(err, ErrStepUpLimited) {
			t.Fatalf("attempt quota exceeded but verifier did not fail closed: %v", err)
		}
		change("DELETE FROM agent_grant_stepup_attempts WHERE admin_id=11")
	})

	t.Run("logout revokes outstanding tokens and preserves immutable history", func(t *testing.T) {
		grant, err := issuer.Issue(ctx, request(otherNode, "c190a8e3-12fd-48d5-8dc4-0ab999a3da03"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(grant.Token)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		store, err := enrollment.NewApprovedSQLStore(db)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := store.Lookup(ctx, digest, time.Now().UTC()); err != nil || got != otherNode {
			t.Fatalf("pre-logout grant not recognized: %q, %v", got, err)
		}
		key := sha256.Sum256([]byte("test-only public-key fingerprint"))
		if ok, err := store.Active(ctx, nodeID, "90001", key, time.Now().UTC()); err != nil || !ok {
			t.Fatalf("previously enrolled certificate not admitted before logout: %v", err)
		}
		beforeIssues, beforeAudit := count("agent_grant_issues"), count("agent_grant_audit")

		// Regression: migration 0005's RESTRICT foreign key made this logout
		// fail with a foreign-key violation while grant history existed.
		if _, err := db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id=21`); err != nil {
			t.Fatalf("administrator logout still blocked by grant history: %v", err)
		}
		var stepups int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM agent_grant_stepups WHERE session_id=21`).Scan(&stepups); err != nil || stepups != 0 {
			t.Fatalf("logout left step-up authorization behind: n=%d err=%v", stepups, err)
		}
		if got, err := store.Lookup(ctx, digest, time.Now().UTC()); !errors.Is(err, enrollment.ErrInvalidToken) || got != "" {
			t.Fatalf("outstanding token survived logout at lookup: node=%q err=%v", got, err)
		}
		notBefore := time.Now().UTC().Add(-time.Minute)
		notAfter := time.Now().UTC().Add(time.Hour)
		if err := store.Commit(ctx, digest, otherNode, "90002", key, notBefore, notAfter, time.Now().UTC()); !errors.Is(err, enrollment.ErrInvalidToken) {
			t.Fatalf("outstanding token survived logout at commit: %v", err)
		}
		var consumed sql.NullInt64
		if err := db.QueryRowContext(ctx, "SELECT consumed_at FROM agent_enrollment_grants WHERE token_digest=$1", digest[:]).Scan(&consumed); err != nil || consumed.Valid {
			t.Fatalf("refused redemption consumed token: consumed=%v err=%v", consumed, err)
		}

		// Immutable history keeps the original session facts after logout.
		var histSession int
		var histHash string
		if err := db.QueryRowContext(ctx, `SELECT session_id,session_token_hash FROM agent_grant_issues WHERE token_digest=$1`, digest[:]).Scan(&histSession, &histHash); err != nil {
			t.Fatal(err)
		}
		if histSession != 21 || histHash != hex.EncodeToString(sessionHash[:]) {
			t.Fatal("issuance history lost the original session binding")
		}
		if count("agent_grant_issues") != beforeIssues || count("agent_grant_audit") != beforeAudit {
			t.Fatal("logout rewrote issuance or audit history")
		}
		for _, q := range []string{
			`UPDATE agent_grant_issues SET session_id=999`,
			`DELETE FROM agent_grant_issues`,
			`UPDATE agent_grant_audit SET action='other'`,
			`DELETE FROM agent_grant_audit`,
		} {
			if _, err := db.ExecContext(ctx, q); err == nil {
				t.Fatalf("immutable history accepted mutation: %s", q)
			}
		}

		// Admin logout does not revoke an already-issued node certificate;
		// node admission depends on binding/organization/node status only.
		if ok, err := store.Active(ctx, nodeID, "90001", key, time.Now().UTC()); err != nil || !ok {
			t.Fatalf("admin logout revoked an enrolled node certificate: %v", err)
		}

		// A fresh login reusing the deleted serial id must not resurrect the
		// old bearer: the recorded credential hash no longer matches.
		relogin := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xB7}, 32))
		reloginHash := sha256.Sum256([]byte(relogin))
		loginAt := time.Now().UTC()
		if _, err := db.ExecContext(ctx, `INSERT INTO admin_sessions(id,admin_id,token_hash,created_at,last_seen_at,expires_at)
VALUES (21,11,$1,$2,$2,$3)`, hex.EncodeToString(reloginHash[:]), loginAt.Add(-time.Minute), loginAt.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO agent_grant_stepups(session_id,method,verified_at,expires_at,verified_counter,verified_source)
VALUES (21,'totp',$1,$2,0,'trusted')`, loginAt.Add(-time.Minute), loginAt.Add(5*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if got, err := store.Lookup(ctx, digest, time.Now().UTC()); !errors.Is(err, enrollment.ErrInvalidToken) || got != "" {
			t.Fatalf("recycled session id resurrected token at lookup: node=%q err=%v", got, err)
		}
		if err := store.Commit(ctx, digest, otherNode, "90002", key, notBefore, notAfter, time.Now().UTC()); !errors.Is(err, enrollment.ErrInvalidToken) {
			t.Fatalf("recycled session id resurrected token at commit: %v", err)
		}

		// The new session can issue fresh grants normally. nodeID has no
		// pending grant left: its earlier bearers were all redeemed above.
		r := request(nodeID, "c290a8e3-12fd-48d5-8dc4-0ab999a3da03")
		r.AdminSessionToken = relogin
		fresh, err := issuer.Issue(ctx, r)
		if err != nil {
			t.Fatalf("post-logout relogin cannot issue grants: %v", err)
		}
		freshRaw, err := base64.RawURLEncoding.DecodeString(fresh.Token)
		if err != nil {
			t.Fatal(err)
		}
		freshDigest := sha256.Sum256(freshRaw)
		if got, err := store.Lookup(ctx, freshDigest, time.Now().UTC()); err != nil || got != nodeID {
			t.Fatalf("fresh relogin grant not recognized: %q, %v", got, err)
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
