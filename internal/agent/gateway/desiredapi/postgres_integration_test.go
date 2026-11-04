//go:build postgres_integration

package desiredapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq" // Only the disposable integration test imports the PostgreSQL driver.
)

const otherDesiredNode = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc"
const desiredOrg = "4b0895aa-1701-4c6d-8b31-91d642c23e1c"

func TestPostgresSignedDesiredCurrentView(t *testing.T) {
	dsn := os.Getenv("OMNIPANEL_TEST_POSTGRES_DSN")
	endpoint, err := url.Parse(dsn)
	if err != nil || endpoint.Scheme != "postgres" || endpoint.Hostname() != "127.0.0.1" || endpoint.Path != "/omnipanel_enrollment_test" {
		t.Fatal("test requires the disposable local omnipanel_enrollment_test database")
	}
	ctx := context.Background()
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	// Use a randomized schema and the complete published migrations, never a
	// hand-built approximation. No modification to the existing test schemas.
	var salt [8]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatal(err)
	}
	schema := "desired_chain_" + hex.EncodeToString(salt[:])
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop disposable schema: %v", err)
		}
	})
	query := endpoint.Query()
	query.Set("options", "-csearch_path="+schema)
	endpoint.RawQuery = query.Encode()
	db, err := sql.Open("postgres", endpoint.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(8)
	var actualSchema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&actualSchema); err != nil || actualSchema != schema {
		t.Fatalf("unexpected migration schema %q: %v", actualSchema, err)
	}
	migrations := []string{
		"0001_initial.sql", "0002_m2.sql", "0003_agent_enrollment.sql",
		"0004_agent_enrollment_rate_limits.sql", "0005_agent_admin_grants.sql",
		"0006_agent_grant_logout_revocation.sql", "0007_agent_grant_verified_stepup.sql",
		"0008_agent_signed_desired.sql",
	}
	for _, name := range migrations {
		body, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "db", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("PostgreSQL migration %s: %v", name, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	wire, verifier := fixtureSignedDesired(t, now)
	seed := []struct {
		query string
		args  []any
	}{
		{"INSERT INTO admins(id,email,password_hash,role) VALUES(11,'desired-approver@test.invalid','fixture','owner')", nil},
		{"INSERT INTO nodes(id,name,public_address,provider,status) VALUES(31,'desired-a','192.0.2.31','fixture','pending_enrollment'),(32,'desired-b','192.0.2.32','fixture','active')", nil},
		{"INSERT INTO agent_grant_organizations(organization_id,state) VALUES($1,'active')", []any{desiredOrg}},
		{"INSERT INTO agent_grant_node_bindings(node_id,legacy_node_id,organization_id,state,approved_by,approved_at) VALUES($1,31,$3,'approved',11,$4),($2,32,$3,'approved',11,$4)", []any{desiredNode, otherDesiredNode, desiredOrg, now}},
		{"INSERT INTO agent_desired_revisions(node_id,control_plane_epoch,structural_sequence,membership_sequence,envelope) VALUES($1,$3,2,3,$4),($2,$3,2,3,$5)", []any{desiredNode, otherDesiredNode, desiredEpoch, wire, []byte("untrusted second node payload")}},
		{"INSERT INTO agent_desired_heads(node_id,control_plane_epoch,structural_sequence) VALUES($1,$3,2),($2,$3,2)", []any{desiredNode, otherDesiredNode, desiredEpoch}},
	}
	for _, step := range seed {
		if _, err := db.ExecContext(ctx, step.query, step.args...); err != nil {
			t.Fatal(err)
		}
	}
	source, err := NewSQLSource(db)
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Latest(ctx, desiredNode)
	if err != nil || first.Epoch != desiredEpoch || first.StructuralSequence != 2 || first.MembershipSequence != 3 || !bytes.Equal(first.Envelope, wire) {
		t.Fatalf("immutable signed snapshot did not read: %+v %v", first, err)
	}
	second, err := source.Latest(ctx, otherDesiredNode)
	if err != nil || !bytes.Equal(second.Envelope, []byte("untrusted second node payload")) {
		t.Fatalf("cross-node row or binding leak: %+v %v", second, err)
	}
	if _, err := source.Latest(ctx, "96c478bb-47c3-4dc6-a363-a2fbde813810"); !errors.Is(err, ErrSnapshotUnavailable) {
		t.Fatalf("unknown node was served: %v", err)
	}
	handler, err := NewHandler(&fixtureLedger{active: true}, source, desiredDomain, verifier, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	peer := fixtureVerifiedPeer(t, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, desiredRequest(requestQuery("0", "0"), &peer))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), wire) {
		t.Fatalf("authenticated PostgreSQL snapshot was not served: %d", w.Code)
	}

	change := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	denied := func(reason string) {
		t.Helper()
		if _, err := source.Latest(ctx, desiredNode); !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatalf("%s bypassed by read view: %v", reason, err)
		}
	}
	change("UPDATE agent_grant_node_bindings SET state='revoked' WHERE node_id=$1", desiredNode)
	denied("revoked binding")
	change("UPDATE agent_grant_node_bindings SET state='approved' WHERE node_id=$1", desiredNode)
	change("UPDATE agent_grant_organizations SET state='suspended' WHERE organization_id=$1", desiredOrg)
	denied("suspended organization")
	change("UPDATE agent_grant_organizations SET state='active' WHERE organization_id=$1", desiredOrg)
	change("UPDATE nodes SET status='quarantined' WHERE id=31")
	denied("quarantined legacy node")
	change("UPDATE nodes SET status='active' WHERE id=31")
	if _, err := source.Latest(ctx, desiredNode); err != nil {
		t.Fatalf("reactivated node missing: %v", err)
	}

	if _, err := db.ExecContext(ctx, "UPDATE agent_desired_revisions SET membership_sequence=4 WHERE node_id=$1", desiredNode); err == nil {
		t.Fatal("immutable signed revision accepted UPDATE")
	}
	// Delete an unreferenced revision so a missing immutability trigger
	// cannot be masked by the head's foreign-key constraint.
	change("INSERT INTO agent_desired_revisions(node_id,control_plane_epoch,structural_sequence,membership_sequence,envelope) VALUES($1,$2,4,3,$3)", otherDesiredNode, desiredEpoch, []byte("unheaded revision"))
	if _, err := db.ExecContext(ctx, "DELETE FROM agent_desired_revisions WHERE node_id=$1 AND structural_sequence=4", otherDesiredNode); err == nil {
		t.Fatal("unheaded signed revision accepted DELETE")
	}

	// A distinct actual revision can move the head forward. But its stored
	// metadata must match the envelope; the gateway must not trust the pointer.
	change("INSERT INTO agent_desired_revisions(node_id,control_plane_epoch,structural_sequence,membership_sequence,envelope) VALUES($1,$2,3,3,$3)", desiredNode, desiredEpoch, wire)
	change("UPDATE agent_desired_heads SET structural_sequence=3 WHERE node_id=$1", desiredNode)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, desiredRequest(requestQuery("0", "0"), &peer))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("inconsistent signed revision was served: %d", w.Code)
	}
	if _, err := db.ExecContext(ctx, "UPDATE agent_desired_heads SET structural_sequence=2 WHERE node_id=$1", desiredNode); err == nil {
		t.Fatal("head sequence rolled back")
	}
	// Supply a matching foreign-key target for the alternate epoch: only
	// the recovery-approval guard should make this UPDATE fail.
	alternateEpoch := "32486a70-22d9-4ec4-97bd-21881762f6d0"
	change("INSERT INTO agent_desired_revisions(node_id,control_plane_epoch,structural_sequence,membership_sequence,envelope) VALUES($1,$2,3,3,$3)", desiredNode, alternateEpoch, wire)
	if _, err := db.ExecContext(ctx, "UPDATE agent_desired_heads SET control_plane_epoch=$2 WHERE node_id=$1", desiredNode, alternateEpoch); err == nil {
		t.Fatal("epoch changed without recovery approval")
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM agent_desired_heads WHERE node_id=$1", desiredNode); err == nil {
		t.Fatal("head was deleted without recovery approval")
	}

	// Independent database identity: the gateway can SELECT the authorized
	// view but cannot SELECT or mutate its underlying revision/head tables.
	role := "desired_reader_" + hex.EncodeToString(salt[:])
	if _, err := admin.ExecContext(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "REVOKE SELECT ON "+schema+".agent_desired_current FROM "+role)
		_, _ = admin.ExecContext(context.Background(), "REVOKE USAGE ON SCHEMA "+schema+" FROM "+role)
		if _, err := admin.ExecContext(context.Background(), "DROP ROLE "+role); err != nil {
			t.Errorf("drop disposable reader role: %v", err)
		}
	})
	change("GRANT USAGE ON SCHEMA " + schema + " TO " + role)
	change("GRANT SELECT ON " + schema + ".agent_desired_current TO " + role)
	assertRole := func(query string, shouldPass bool) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE "+role); err != nil {
			t.Fatal(err)
		}
		rows, err := tx.QueryContext(ctx, query)
		if shouldPass && err != nil {
			t.Fatalf("reader view was denied: %v", err)
		}
		if !shouldPass && err == nil {
			rows.Close()
			t.Fatalf("reader accessed forbidden table: %s", query)
		}
		if rows != nil {
			rows.Close()
		}
	}
	assertRole("SELECT node_id FROM "+schema+".agent_desired_current", true)
	assertRole("SELECT node_id FROM "+schema+".agent_desired_revisions", false)
	assertRole("SELECT node_id FROM "+schema+".agent_desired_heads", false)
}
