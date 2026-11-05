//go:build postgres_integration

package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/pki/enrollment"
	_ "github.com/lib/pq" // Test-only driver, not linked into the node runtime.
)

// This integration test is restricted to the disposable CI PostgreSQL service.
func TestPostgresSharedEnrollmentRateLimiter(t *testing.T) {
	dsn := os.Getenv("OMNIPANEL_TEST_POSTGRES_DSN")
	endpoint, err := url.Parse(dsn)
	if err != nil || endpoint.Scheme != "postgres" || endpoint.Hostname() != "127.0.0.1" || endpoint.Path != "/omnipanel_enrollment_test" {
		t.Fatal("rate limit integration tests require the dedicated local PostgreSQL test database")
	}
	ctx := context.Background()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(20)
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	ddl, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "db", "migrations", "0004_agent_enrollment_rate_limits.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(ddl)); err != nil {
		t.Fatalf("real PostgreSQL rate-limit migration failed: %v", err)
	}
	secret := bytes.Repeat([]byte{0x4a}, 32)
	makeLimiter := func(peerLimit, globalLimit int) *PostgresLimiter {
		t.Helper()
		limiter, err := NewPostgresLimiter(db, secret, peerLimit, globalLimit)
		if err != nil {
			t.Fatal(err)
		}
		return limiter
	}
	reset := func() {
		t.Helper()
		if _, err := db.ExecContext(ctx, "DELETE FROM agent_enrollment_rate_windows"); err != nil {
			t.Fatal(err)
		}
	}

	// Keep the short burst from straddling a 60-second database window.
	stabilize := func() {
		t.Helper()
		var second float64
		if err := db.QueryRowContext(ctx, "SELECT extract(second from clock_timestamp())::float8").Scan(&second); err != nil {
			t.Fatal(err)
		}
		if second >= 55 {
			time.Sleep(time.Duration(61-second) * time.Second)
		}
	}

	t.Run("per-peer and fleet-wide limits persist across instances", func(t *testing.T) {
		reset()
		stabilize()
		limiter := makeLimiter(2, 4)
		otherInstance := makeLimiter(2, 4)
		for _, tc := range []struct {
			ip      string
			allowed bool
		}{
			{"203.0.113.21", true},
			{"::ffff:203.0.113.21", true},
			{"203.0.113.21", false}, // Must not consume global budget.
			{"203.0.113.22", true},
			{"203.0.113.22", true},
			{"203.0.113.23", false}, // Fleet cap reached.
		} {
			actual, err := limiter.Allow(ctx, tc.ip)
			if err != nil || actual != tc.allowed {
				t.Fatalf("bad shared allowance for %q: got %t, want %t, err %v", tc.ip, actual, tc.allowed, err)
			}
			limiter, otherInstance = otherInstance, limiter
		}
		var globalCount, totalRows int
		if err := db.QueryRowContext(ctx, "SELECT hits FROM agent_enrollment_rate_windows WHERE scope='global'").Scan(&globalCount); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM agent_enrollment_rate_windows").Scan(&totalRows); err != nil {
			t.Fatal(err)
		}
		if globalCount != 4 || totalRows != 3 {
			t.Fatalf("wrong durable atomic budgets: global=%d rows=%d", globalCount, totalRows)
		}
		var leaked int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM agent_enrollment_rate_windows WHERE encode(key_digest, 'hex') LIKE '%203011321%'").Scan(&leaked); err != nil || leaked != 0 {
			t.Fatal("raw IP material persisted")
		}
	})

	t.Run("parallel gateways cannot exceed global cap", func(t *testing.T) {
		reset()
		stabilize()
		a := makeLimiter(3, 13)
		b := makeLimiter(3, 13)
		var admitted atomic.Int32
		var failed atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				limiter := a
				if i%2 != 0 {
					limiter = b
				}
				allowed, err := limiter.Allow(ctx, fmt.Sprintf("198.51.100.%d", i+1))
				if err != nil {
					failed.Add(1)
					return
				}
				if allowed {
					admitted.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if failed.Load() != 0 || admitted.Load() != 13 {
			t.Fatalf("concurrent budget violated: admitted=%d storage_errors=%d", admitted.Load(), failed.Load())
		}
		var hits int
		if err := db.QueryRowContext(ctx, "SELECT hits FROM agent_enrollment_rate_windows WHERE scope='global'").Scan(&hits); err != nil || hits != 13 {
			t.Fatalf("global row disagrees with successful calls: hits=%d, err=%v", hits, err)
		}
	})

	t.Run("handler enforces PostgreSQL limit without trusting forwarded IP", func(t *testing.T) {
		reset()
		stabilize()
		issuer := &stubIssuer{issued: fixtureIssued()}
		handler, err := New(issuer, makeLimiter(2, 10))
		if err != nil {
			t.Fatal(err)
		}
		for n := 1; n <= 3; n++ {
			r := tlsRequest(http.MethodPost, Path, strings.Repeat("A", 43), validJSON(t), "192.0.2.80:1200")
			r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", n))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			want := http.StatusCreated
			if n == 3 {
				want = http.StatusTooManyRequests
			}
			if w.Code != want {
				t.Fatalf("forwarded header evaded limiter at request %d: status %d wanted %d", n, w.Code, want)
			}
		}
		if issuer.calls != 2 {
			t.Fatalf("limited request invoked issuer %d times", issuer.calls)
		}
	})

	t.Run("storage outages deny enrollment and maintenance prunes expired only", func(t *testing.T) {
		reset()
		limiter := makeLimiter(2, 3)
		stale := limiter.mac("maintenance-check", nil)
		_, err := db.ExecContext(ctx, "INSERT INTO agent_enrollment_rate_windows(scope,key_digest,window_start,hits) VALUES('peer',$1,1,1)", stale[:])
		if err != nil {
			t.Fatal(err)
		}
		deleted, err := limiter.PruneExpired(ctx)
		if err != nil || deleted != 1 {
			t.Fatalf("stale hashed peer window not pruned: deleted=%d err=%v", deleted, err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		allowed, err := limiter.Allow(ctx, "198.51.100.1")
		if allowed || err == nil || errors.Is(err, ErrInvalidPeer) {
			t.Fatalf("storage failure bypassed shared limiter: allowed=%t err=%v", allowed, err)
		}
	})
}

func fixtureIssued() enrollment.Issued {
	return enrollment.Issued{NodeID: nodeA, CertificatePEM: []byte("test-only-cert"), Serial: "123", NotAfter: time.Now().Add(time.Hour)}
}
