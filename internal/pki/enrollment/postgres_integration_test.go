//go:build postgres_integration

package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq" // Test-only PostgreSQL driver; never used in privileged agent.
)

// Run only against an ephemeral local database with a known, dedicated name.
// Do not point this destructive DDL test at a development or production DB.
func TestPostgresEnrollmentLedger(t *testing.T) {
	dsn := os.Getenv("OMNIPANEL_TEST_POSTGRES_DSN")
	endpoint, err := url.Parse(dsn)
	if err != nil || endpoint.Scheme != "postgres" || endpoint.Hostname() != "127.0.0.1" || endpoint.Path != "/omnipanel_enrollment_test" {
		t.Fatal("integration tests require local disposable omnipanel_enrollment_test PostgreSQL database")
	}
	ctx := context.Background()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(8)
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "db", "migrations", "0003_agent_enrollment.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("real PostgreSQL migration rejected: %v", err)
	}
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ca, signer, at := issuerFixture(t)
	issuer, err := NewAuthority(ca, signer, testTrustDomain, store, func() time.Time { return at }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("persist, replay refusal, key scope and revocation", func(t *testing.T) {
		token, err := store.CreateGrant(ctx, testNodeA, at, at.Add(5*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		var digest []byte
		if err := db.QueryRowContext(ctx, "SELECT token_digest FROM agent_enrollment_grants WHERE node_id=$1", testNodeA).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		if len(digest) != 32 || bytes.Equal(digest, []byte(token)) {
			t.Fatal("plaintext token persisted or bad digest")
		}
		hash := sha256.Sum256([]byte(token))
		if !bytes.Equal(hash[:], digest) {
			parsed, err := parseToken(token)
			if err != nil || !bytes.Equal(parsed[:], digest) {
				t.Fatal("unexpected bearer digest")
			}
		}
		csr, _ := csrFixture(t, testNodeB)
		issued, err := issuer.Enroll(ctx, token, csr)
		if err != nil || issued.NodeID != testNodeA {
			t.Fatalf("authorized issuance failed: %+v %v", issued, err)
		}
		if _, err := issuer.Enroll(ctx, token, csr); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("replayed grant issued another certificate: %v", err)
		}
		block, _ := pem.Decode(issued.CertificatePEM)
		if block == nil {
			t.Fatal("certificate PEM missing")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		active, err := store.Active(ctx, testNodeA, issued.Serial, sha256.Sum256(spki), at)
		if err != nil || !active {
			t.Fatalf("issued certificate is absent from PostgreSQL ledger: %v", err)
		}
		active, err = store.Active(ctx, testNodeB, issued.Serial, sha256.Sum256(spki), at)
		if err != nil || active {
			t.Fatal("other node admitted registered certificate")
		}
		if err := store.Revoke(ctx, testNodeA, issued.Serial, at); err != nil {
			t.Fatal(err)
		}
		active, err = store.Active(ctx, testNodeA, issued.Serial, sha256.Sum256(spki), at)
		if err != nil || active {
			t.Fatal("revoked certificate is still active")
		}
	})
	t.Run("failed insert rolls back grant and concurrent redemption is single use", func(t *testing.T) {
		token, err := store.CreateGrant(ctx, testNodeA, at, at.Add(5*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		csr, _ := csrFixture(t, testNodeA)
		if _, err := db.ExecContext(ctx, `CREATE FUNCTION fail_agent_cert() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'forced insert error'; END; $$ LANGUAGE plpgsql`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER fail_agent_cert_insert BEFORE INSERT ON agent_node_certificates FOR EACH ROW EXECUTE FUNCTION fail_agent_cert()`); err != nil {
			t.Fatal(err)
		}
		if issued, err := issuer.Enroll(ctx, token, csr); err == nil || len(issued.CertificatePEM) != 0 {
			t.Fatal("unrecorded certificate escaped signing issuer")
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER fail_agent_cert_insert ON agent_node_certificates`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DROP FUNCTION fail_agent_cert()`); err != nil {
			t.Fatal(err)
		}
		hash, err := parseToken(token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Lookup(ctx, hash, at); err != nil {
			t.Fatalf("rolled back grant was wrongly consumed: %v", err)
		}
		var successes atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := issuer.Enroll(ctx, token, csr); err == nil {
					successes.Add(1)
				}
			}()
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatalf("concurrent PostgreSQL redemption minted %d certs", successes.Load())
		}
		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_node_certificates WHERE node_id=$1 AND revoked_at IS NULL", testNodeA).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("concurrent grant caused %d active certificates", count)
		}
	})
	t.Run("schema rejects malformed binary digest", func(t *testing.T) {
		_, err := db.ExecContext(ctx, `INSERT INTO agent_enrollment_grants(token_digest,node_id,expires_at,created_at) VALUES($1,$2,$3,$4)`, []byte{0x01}, testNodeA, at.Add(time.Minute).Unix(), at.Unix())
		if err == nil {
			t.Fatal("PostgreSQL digest constraint was not enforced")
		}
	})
}
