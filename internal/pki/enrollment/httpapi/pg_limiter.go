package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net"
)

var (
	ErrInvalidPeer       = errors.New("invalid enrollment peer address")
	ErrInvalidRateConfig = errors.New("invalid enrollment rate limiter configuration")
)

const maximumRateBudget = 1000000

// PostgresLimiter implements Limiter with atomic, shared, DB-clocked budgets.
// A single HMAC key MUST be provisioned securely to every gateway in the same
// fleet; process-local random keys would defeat cross-gateway rate limiting.
// No raw peer addresses or bearer credentials are persisted.
type PostgresLimiter struct {
	db           *sql.DB
	key          [32]byte
	peerBudget   int
	globalBudget int
}

// NewPostgresLimiter requires a 256-bit fleet-specific HMAC key. The database
// needs the separately migrated agent_enrollment_rate_windows table.
func NewPostgresLimiter(db *sql.DB, hmacKey []byte, peerBudget, globalBudget int) (*PostgresLimiter, error) {
	if db == nil || len(hmacKey) != 32 || peerBudget < 1 || globalBudget < 1 ||
		peerBudget > maximumRateBudget || globalBudget > maximumRateBudget {
		return nil, ErrInvalidRateConfig
	}
	var key [32]byte
	copy(key[:], hmacKey)
	return &PostgresLimiter{db: db, key: key, peerBudget: peerBudget, globalBudget: globalBudget}, nil
}

func (l *PostgresLimiter) mac(label string, content []byte) [32]byte {
	h := hmac.New(sha256.New, l.key[:])
	_, _ = h.Write([]byte(label))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(content)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// peerDigest accepts an IP address only, not a host:port or a forwarded header.
// IPv4-mapped IPv6 must be charged against the same IPv4 budget.
func (l *PostgresLimiter) peerDigest(peer string) ([32]byte, error) {
	ip := net.ParseIP(peer)
	if ip == nil {
		return [32]byte{}, ErrInvalidPeer
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return l.mac("enrollment-peer-ipv4-v1", ipv4), nil
	}
	return l.mac("enrollment-peer-ipv6-v1", ip.To16()), nil
}

const incrementRateWindow = `
INSERT INTO agent_enrollment_rate_windows (scope, key_digest, window_start, hits)
VALUES ($1, $2, $3, 1)
ON CONFLICT (scope, key_digest, window_start)
DO UPDATE SET hits = agent_enrollment_rate_windows.hits + 1
WHERE agent_enrollment_rate_windows.hits < $4
RETURNING hits`

// Allow checks a fleet-wide global and a per-peer budget in one PostgreSQL
// transaction. PostgreSQL's unique row conflict locking serializes increments
// even when requests race across gateway instances. A missing quota row means
// denial. A storage outage never falls back to an in-memory allowance.
func (l *PostgresLimiter) Allow(ctx context.Context, peer string) (bool, error) {
	if l == nil || l.db == nil {
		return false, ErrInvalidRateConfig
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	peerHash, err := l.peerDigest(peer)
	if err != nil {
		return false, err
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("rate limiter storage unavailable: %w", err)
	}
	defer tx.Rollback()
	var window int64
	// Use a database clock, never one gateway's potentially skewed wall clock.
	if err := tx.QueryRowContext(ctx, `SELECT floor(extract(epoch FROM clock_timestamp()) / 60)::bigint`).Scan(&window); err != nil {
		return false, fmt.Errorf("rate limiter clock unavailable: %w", err)
	}
	globalHash := l.mac("enrollment-global-v1", nil)
	for _, bucket := range []struct {
		scope  string
		digest [32]byte
		limit  int
	}{
		{"global", globalHash, l.globalBudget},
		{"peer", peerHash, l.peerBudget},
	} {
		var hits int
		err := tx.QueryRowContext(ctx, incrementRateWindow, bucket.scope, bucket.digest[:], window, bucket.limit).Scan(&hits)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // Roll back both bucket changes.
		}
		if err != nil {
			return false, fmt.Errorf("rate limiter budget unavailable: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("rate limiter transaction failed: %w", err)
	}
	return true, nil
}

// PruneExpired is for an authorized periodic maintenance worker, never an
// HTTP request. It preserves the current and previous 24 hours of windows.
// If it fails, the runtime must report the failure; retention is not automatic.
func (l *PostgresLimiter) PruneExpired(ctx context.Context) (int64, error) {
	if l == nil || l.db == nil {
		return 0, ErrInvalidRateConfig
	}
	result, err := l.db.ExecContext(ctx, `DELETE FROM agent_enrollment_rate_windows
WHERE window_start < floor(extract(epoch FROM clock_timestamp()) / 60)::bigint - 1440`)
	if err != nil {
		return 0, fmt.Errorf("rate limiter maintenance failed: %w", err)
	}
	return result.RowsAffected()
}
