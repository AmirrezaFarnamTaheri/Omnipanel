package grants

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	ErrStepUpConfig  = errors.New("invalid step-up verifier configuration")
	ErrStepUpSession = errors.New("step-up session unauthorized")
	ErrStepUpCode    = errors.New("invalid or replayed step-up factor")
	ErrStepUpLimited = errors.New("step-up attempt budget exhausted")
)

const (
	stepUpLifetime = 5 * time.Minute
	stepUpAttempts = 5
)

// TOTPSecretOpener decrypts the existing administrator's totp_secret_enc via
// a protected external key custodian. It must return the legacy uppercase
// unpadded base32 representation of 20 secret bytes; never store plaintext.
// The opener binds key access to the authenticated administrator ID.
type TOTPSecretOpener interface {
	OpenTOTP(ctx context.Context, adminID int64, envelope string) ([]byte, error)
}

type StepUpService struct {
	db     *sql.DB
	opener TOTPSecretOpener
}

func NewStepUpService(db *sql.DB, opener TOTPSecretOpener) (*StepUpService, error) {
	if db == nil || opener == nil {
		return nil, ErrStepUpConfig
	}
	return &StepUpService{db: db, opener: opener}, nil
}

// totpCode follows RFC 4226/6238 HMAC-SHA1 with a 30-second time step and
// six digits, matching the existing OmniPanel prototype's enrollment TOTP.
func totpCode(secret []byte, counter int64) string {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(data[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	n := uint32(sum[offset]&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", n%1000000)
}

// matchTOTP compares all adjacent steps without timing-short-circuiting.
// It never accepts a counter already recorded for this administrator.
func matchTOTP(secret []byte, code string, currentStep, lastUsed int64) (int64, bool) {
	if len(code) != 6 || currentStep < 1 {
		return 0, false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	matched := int64(-1)
	for _, delta := range []int64{-1, 0, 1} {
		step := currentStep + delta
		if step < 0 {
			continue
		}
		calc := totpCode(secret, step)
		if subtle.ConstantTimeCompare([]byte(calc), []byte(code)) == 1 && step > lastUsed {
			if step > matched {
				matched = step
			}
		}
	}
	return matched, matched >= 0
}

func decodeTOTPBase32(raw []byte) ([]byte, error) {
	if len(raw) != 32 {
		return nil, ErrStepUpCode
	}
	for _, b := range raw {
		if !(b >= 'A' && b <= 'Z') && !(b >= '2' && b <= '7') {
			return nil, ErrStepUpCode
		}
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(raw))
	if err != nil || len(decoded) != 20 {
		return nil, ErrStepUpCode
	}
	return decoded, nil
}

// Verify records one independently verified TOTP step-up. Session identity
// and time come only from PostgreSQL; the caller supplies no admin ID, role,
// clock, verification flag, organization or step-up expiry. The budget is
// durably charged even on a bad code; its outage fails closed.
func (s *StepUpService) Verify(ctx context.Context, sessionToken, code string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.db == nil || s.opener == nil {
		return ErrStepUpConfig
	}
	if len(code) != 6 {
		return ErrStepUpCode
	}
	for i := 0; i < 6; i++ {
		if code[i] < '0' || code[i] > '9' {
			return ErrStepUpCode
		}
	}
	if len(sessionToken) != base64.RawURLEncoding.EncodedLen(32) {
		return ErrStepUpSession
	}
	decoded, err := base64.RawURLEncoding.DecodeString(sessionToken)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != sessionToken {
		return ErrStepUpSession
	}
	digest := sha256.Sum256([]byte(sessionToken))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("step-up storage unavailable: %w", err)
	}
	defer tx.Rollback()
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return fmt.Errorf("step-up clock unavailable: %w", err)
	}
	var adminID, sessionID int64
	var cipherText sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT a.id,s.id,a.totp_secret_enc
FROM admin_sessions s JOIN admins a ON a.id=s.admin_id
WHERE s.token_hash=$1 AND a.role='owner' AND a.totp_enabled
  AND s.created_at <= $2 AND s.last_seen_at <= $2
  AND s.expires_at > $2
  AND s.created_at > $2 - interval '12 hours'
  AND s.last_seen_at > $2 - interval '2 hours'
FOR SHARE OF a,s`, hex.EncodeToString(digest[:]), now).Scan(&adminID, &sessionID, &cipherText)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStepUpSession
	}
	if err != nil {
		return fmt.Errorf("verify step-up session: %w", err)
	}
	if !cipherText.Valid || cipherText.String == "" {
		return ErrStepUpSession
	}

	// Charge failed attempts in a shared five-minute database window.
	window := now.Unix() / 300
	var hits int
	err = tx.QueryRowContext(ctx, `INSERT INTO agent_grant_stepup_attempts(admin_id,window_start,hits)
VALUES($1,$2,1)
ON CONFLICT(admin_id,window_start) DO UPDATE
SET hits=agent_grant_stepup_attempts.hits+1
WHERE agent_grant_stepup_attempts.hits < $3
RETURNING hits`, adminID, window, stepUpAttempts).Scan(&hits)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStepUpLimited
	}
	if err != nil {
		return fmt.Errorf("charge step-up attempt: %w", err)
	}

	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_grant_stepup_counters(admin_id,last_counter)
VALUES($1,-1) ON CONFLICT(admin_id) DO NOTHING`, adminID); err != nil {
		return fmt.Errorf("prepare step-up replay gate: %w", err)
	}
	var last int64
	if err = tx.QueryRowContext(ctx, `SELECT last_counter FROM agent_grant_stepup_counters
WHERE admin_id=$1 FOR UPDATE`, adminID).Scan(&last); err != nil {
		return fmt.Errorf("read step-up replay gate: %w", err)
	}
	plain, err := s.opener.OpenTOTP(ctx, adminID, cipherText.String)
	if err != nil {
		return fmt.Errorf("protected step-up secret unavailable: %w", err)
	}
	defer clear(plain)
	secret, err := decodeTOTPBase32(plain)
	if err != nil {
		return ErrStepUpSession
	}
	defer clear(secret)
	matched, valid := matchTOTP(secret, code, now.Unix()/30, last)
	if !valid {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("persist failed step-up attempt: %w", err)
		}
		return ErrStepUpCode
	}
	if _, err = tx.ExecContext(ctx, `UPDATE agent_grant_stepup_counters
SET last_counter=$2,updated_at=$3 WHERE admin_id=$1`, adminID, matched, now); err != nil {
		return fmt.Errorf("persist step-up replay gate: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_grant_stepups(session_id,method,verified_at,expires_at,verified_counter,verified_source)
VALUES($1,'totp',$2,$3,$4,'trusted')
ON CONFLICT(session_id) DO UPDATE SET method='totp',verified_at=EXCLUDED.verified_at,
expires_at=EXCLUDED.expires_at,verified_counter=EXCLUDED.verified_counter,verified_source='trusted'`, sessionID, now, now.Add(stepUpLifetime), matched); err != nil {
		return fmt.Errorf("persist trusted step-up: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit trusted step-up: %w", err)
	}
	return nil
}
