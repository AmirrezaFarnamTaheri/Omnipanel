package enrollment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3" // Isolated SQLite transaction test, not PostgreSQL qualification.
)

func sqliteFixture(t *testing.T) (*sql.DB, *SQLStore, string) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "enrollment.db") + "?_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(2)
	for _, schema := range []string{
		`CREATE TABLE agent_enrollment_grants (token_digest BLOB PRIMARY KEY CHECK(length(token_digest)=32),node_id TEXT NOT NULL,expires_at BIGINT NOT NULL,created_at BIGINT NOT NULL,consumed_at BIGINT)`,
		`CREATE TABLE agent_node_certificates (serial TEXT PRIMARY KEY,node_id TEXT NOT NULL,spki_digest BLOB NOT NULL CHECK(length(spki_digest)=32),not_before BIGINT NOT NULL,not_after BIGINT NOT NULL,issued_at BIGINT NOT NULL,revoked_at BIGINT)`,
	} {
		if _, err := db.Exec(schema); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return db, store, dsn
}

func TestSQLTokenPersistenceRevocationAndWrongNode(t *testing.T) {
	ctx := context.Background()
	db, store, dsn := sqliteFixture(t)
	ca, key, now := issuerFixture(t)
	bearer, err := store.CreateGrant(ctx, testNodeA, now, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFixture(t, testNodeB)
	issuer, err := NewAuthority(ca, key, testTrustDomain, store, func() time.Time { return now }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Enroll(ctx, bearer, csr)
	if err != nil || issued.NodeID != testNodeA {
		t.Fatalf("unqualified issuance: %+v %v", issued, err)
	}
	var tokenDigest []byte
	var consumed int64
	if err := db.QueryRow(`SELECT token_digest,consumed_at FROM agent_enrollment_grants`).Scan(&tokenDigest, &consumed); err != nil {
		t.Fatal(err)
	}
	if len(tokenDigest) != 32 || consumed != now.Unix() {
		t.Fatal("token plaintext or consumed state not durable")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	fresh, err := NewSQLStore(reopened)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := parseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Lookup(ctx, hash, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("used token resurrected after reopen: %v", err)
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	peer := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: chains}
	if _, err := AuthenticatePeer(ctx, peer, fresh, testTrustDomain, now); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Revoke(ctx, testNodeB, issued.Serial, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("other node revoked certificate")
	}
	if err := fresh.Revoke(ctx, testNodeA, issued.Serial, now); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Revoke(ctx, testNodeA, issued.Serial, now); err != nil {
		t.Fatal("repeat revoke must be idempotent:", err)
	}
	if _, err := AuthenticatePeer(ctx, peer, fresh, testTrustDomain, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked peer remained authorized")
	}
}

func TestSQLAtomicConsumeRollbackAndConcurrency(t *testing.T) {
	ctx := context.Background()
	db, store, _ := sqliteFixture(t)
	ca, key, now := issuerFixture(t)
	bearer, err := store.CreateGrant(ctx, testNodeA, now, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewAuthority(ca, key, testTrustDomain, store, func() time.Time { return now }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFixture(t, testNodeA)
	// A failed certificate ledger insert must rollback the token consumption.
	if _, err := db.Exec(`CREATE TRIGGER reject_issuance BEFORE INSERT ON agent_node_certificates BEGIN SELECT RAISE(ABORT, 'forced ledger failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if issued, err := issuer.Enroll(ctx, bearer, csr); err == nil || len(issued.CertificatePEM) != 0 {
		t.Fatal("unrecorded certificate escaped")
	}
	if _, err := db.Exec(`DROP TRIGGER reject_issuance`); err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := issuer.Enroll(ctx, bearer, csr); err == nil {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("one-time token produced %d certificates", success.Load())
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM agent_node_certificates`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("certificate records: %d error: %v", count, err)
	}
}

func TestSQLRejectsUnscopedOrLongLivedGrants(t *testing.T) {
	_, store, _ := sqliteFixture(t)
	at := time.Now()
	for _, tc := range []struct {
		node string
		ttl  time.Duration
	}{
		{testNodeB, 16 * time.Minute}, {"invalid", time.Minute}, {testNodeA, -time.Minute},
	} {
		if token, err := store.CreateGrant(context.Background(), tc.node, at, at.Add(tc.ttl)); err == nil || token != "" {
			t.Fatal("unapproved or unbounded grant issued")
		}
	}
}
