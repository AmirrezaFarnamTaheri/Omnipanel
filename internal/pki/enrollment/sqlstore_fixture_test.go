package enrollment

import (
	"context"
	"fmt"
	"time"
)

// createFixtureGrant is TEST-ONLY. Production issuance must run through
// grants.Service's administrator/session/organization approval transaction.
// CreateGrant is a trusted-administrator-only operation. The caller MUST
// authorize this node and deliver the returned bearer token over a separate
// trusted channel; the plaintext is not persisted or logged here.
func (s *SQLStore) createFixtureGrant(ctx context.Context, node string, now, expires time.Time) (string, error) {
	if !nodePattern.MatchString(node) || !expires.After(now) || expires.Sub(now) > 15*time.Minute {
		return "", ErrInvalidToken
	}
	token, digest, err := GenerateToken()
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO agent_enrollment_grants(token_digest,node_id,expires_at,created_at)
        VALUES($1,$2,$3,$4)`, digest[:], node, expires.Unix(), now.Unix())
	if err != nil {
		return "", fmt.Errorf("persist enrollment grant: %w", err)
	}
	return token, nil
}


