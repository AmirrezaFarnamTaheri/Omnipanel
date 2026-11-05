package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

// SQLSessionChecker checks the live, owner-scoped legacy administrator session
// in PostgreSQL on every request. It does not authenticate a TOTP step-up;
// the desiredapproval service rechecks that separately on every operation.
type SQLSessionChecker struct{ db *sql.DB }

func NewSQLSessionChecker(db *sql.DB) (*SQLSessionChecker, error) {
	if db == nil {
		return nil, errors.New("SQL session database required")
	}
	return &SQLSessionChecker{db: db}, nil
}

const sessionQuery = `SELECT EXISTS (
 SELECT 1 FROM admin_sessions s
 JOIN admins a ON a.id=s.admin_id
 WHERE s.token_hash=$1 AND a.role='owner' AND a.totp_enabled
 AND s.created_at <= clock_timestamp()
 AND s.last_seen_at <= clock_timestamp()
 AND s.created_at > clock_timestamp() - interval '12 hours'
 AND s.last_seen_at > clock_timestamp() - interval '2 hours'
 AND s.expires_at > clock_timestamp()
)`

func (s *SQLSessionChecker) Active(ctx context.Context, token string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s == nil || s.db == nil {
		return false, errors.New("SQL session checker not configured")
	}
	if _, ok := bearerToken(token); !ok {
		return false, nil
	}
	digest := sha256.Sum256([]byte(token))
	var active bool
	if err := s.db.QueryRowContext(ctx, sessionQuery, hex.EncodeToString(digest[:])).Scan(&active); err != nil {
		return false, fmt.Errorf("check live owner session: %w", err)
	}
	return active, nil
}
