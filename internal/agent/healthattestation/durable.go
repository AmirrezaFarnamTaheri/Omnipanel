package healthattestation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DurableVerifier keeps issued nonces and consumed run identifiers across
// process restarts using an owner-only SQLite WAL with synchronous=FULL.
// It authenticates external witness CLAIMS; it does not perform the probes.
type DurableVerifier struct {
	cfg Config
	db *sql.DB
}

func witnessOwnedByCaller(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func requireWitnessPrivateFile(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode().Perm()&0o077 != 0 || !witnessOwnedByCaller(info) {
			return ErrEvidenceRejected
		}
	}
	return nil
}

// NewDurableVerifier binds the database to the provisioned node and epoch.
// Changing the active generation/profile is allowed only through a newly
// trusted Config for the same node/epoch; old nonces remain scoped to the
// previous generation and are never interchangeable.
func NewDurableVerifier(cfg Config) (*DurableVerifier, error) {
	if cfg.Path == "" || !filepath.IsAbs(cfg.Path) ||
		filepath.Clean(cfg.Path) != cfg.Path ||
		strings.IndexByte(cfg.Path, 0) >= 0 ||
		!cfg.Scope.valid() || !witnessIDPattern.MatchString(cfg.WitnessID) ||
		len(cfg.WitnessKey) != ed25519.PublicKeySize ||
		cfg.TTL < time.Second || cfg.TTL > maxWitnessTTL ||
		cfg.TTL%time.Millisecond != 0 {
		return nil, ErrEvidenceRejected
	}
	parent, err := os.Lstat(filepath.Dir(cfg.Path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 ||
		!witnessOwnedByCaller(parent) {
		return nil, ErrEvidenceRejected
	}
	if err := requireWitnessPrivateFile(cfg.Path); err != nil {
		return nil, err
	}
	_, err = os.Lstat(cfg.Path)
	if errors.Is(err, os.ErrNotExist) {
		fd, createErr := syscall.Open(cfg.Path,
			syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
		if createErr != nil {
			return nil, ErrEvidenceRejected
		}
		if os.NewFile(uintptr(fd), cfg.Path).Close() != nil {
			return nil, ErrEvidenceRejected
		}
	} else if err != nil {
		return nil, ErrEvidenceRejected
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.WitnessKey = append(ed25519.PublicKey(nil), cfg.WitnessKey...)
	dsn := (&url.URL{
		Scheme: "file", Path: cfg.Path,
		RawQuery: "_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL&_synchronous=FULL",
	}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, ErrEvidenceRejected
	}
	db.SetMaxOpenConns(1)
	fail := func() (*DurableVerifier, error) {
		_ = db.Close()
		return nil, ErrEvidenceRejected
	}
	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil ||
		!strings.EqualFold(journalMode, "wal") {
		return fail()
	}
	var syncMode int
	if err := db.QueryRow("PRAGMA synchronous").Scan(&syncMode); err != nil || syncMode != 2 {
		return fail()
	}
	const scopeSQL = "CREATE TABLE IF NOT EXISTS witness_scope (" +
		"singleton INTEGER PRIMARY KEY CHECK (singleton = 1)," +
		"node_id TEXT NOT NULL, epoch TEXT NOT NULL)"
	const challengeSQL = "CREATE TABLE IF NOT EXISTS witness_challenges (" +
		"nonce TEXT PRIMARY KEY NOT NULL, challenge BLOB NOT NULL," +
		"expires_at_ms INTEGER NOT NULL, consumed_digest TEXT," +
		"run_id TEXT UNIQUE)"
	for _, stmt := range []string{scopeSQL, challengeSQL} {
		if _, err := db.Exec(stmt); err != nil {
			return fail()
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return fail()
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO witness_scope(singleton,node_id,epoch) VALUES(1,?,?)",
		cfg.Scope.NodeID, cfg.Scope.Epoch); err != nil {
		_ = tx.Rollback()
		return fail()
	}
	var node, epoch string
	if err := tx.QueryRow("SELECT node_id,epoch FROM witness_scope WHERE singleton=1").
		Scan(&node, &epoch); err != nil || node != cfg.Scope.NodeID || epoch != cfg.Scope.Epoch {
		_ = tx.Rollback()
		return fail()
	}
	if err := tx.Commit(); err != nil {
		return fail()
	}
	return &DurableVerifier{cfg: cfg, db: db}, nil
}

func (v *DurableVerifier) Close() error {
	if v == nil || v.db == nil {
		return nil
	}
	return v.db.Close()
}

// Issue persists a random 256-bit challenge BEFORE it can be sent to an
// external reference client. Only trusted callers may issue challenges after
// activation; this is NOT a public HTTP challenge-issuance endpoint.
func (v *DurableVerifier) Issue(ctx context.Context) (Challenge, error) {
	if v == nil || v.db == nil || ctx == nil || ctx.Err() != nil {
		return Challenge{}, ErrEvidenceRejected
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Challenge{}, ErrEvidenceRejected
	}
	now := v.cfg.Now().UTC().UnixMilli()
	c := Challenge{
		Version: protocolVersion, Scope: v.cfg.Scope,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		WitnessID: v.cfg.WitnessID,
		IssuedAtMillis: now, ExpiresAtMillis: now + v.cfg.TTL.Milliseconds(),
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > MaxEvidenceBytes {
		return Challenge{}, ErrEvidenceRejected
	}
	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return Challenge{}, ErrEvidenceRejected
	}
	defer tx.Rollback()
	// Expired nonces can never be accepted even after deletion. Retain signed
	// consumed evidence identifiers for 30 days; long-term audit is separate.
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM witness_challenges WHERE expires_at_ms <= ? AND (consumed_digest IS NULL OR expires_at_ms < ?)",
		now, now-int64((30*24*time.Hour)/time.Millisecond)); err != nil {
		return Challenge{}, ErrEvidenceRejected
	}
	var pending int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM witness_challenges WHERE consumed_digest IS NULL AND expires_at_ms > ?",
		now).Scan(&pending); err != nil || pending >= maxPendingChallenges {
		return Challenge{}, ErrEvidenceRejected
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO witness_challenges(nonce,challenge,expires_at_ms) VALUES(?,?,?)",
		c.Nonce, raw, c.ExpiresAtMillis); err != nil {
		return Challenge{}, ErrEvidenceRejected
	}
	if err := tx.Commit(); err != nil {
		return Challenge{}, ErrEvidenceRejected
	}
	return c, nil
}

// Verify authenticates the exact canonical, domain-separated Ed25519 report
// from a pinned independent witness and consumes its nonce in one durable
// transaction. A valid signature on fabricated claims is still NOT network
// execution proof, an applied ACK or qualification of M0/M1/M2.
func (v *DurableVerifier) Verify(ctx context.Context, wire []byte) (Accepted, error) {
	if v == nil || v.db == nil || ctx == nil || ctx.Err() != nil ||
		len(wire) == 0 || len(wire) > MaxEvidenceBytes {
		return Accepted{}, ErrEvidenceRejected
	}
	var e Evidence
	if err := json.Unmarshal(wire, &e); err != nil {
		return Accepted{}, ErrEvidenceRejected
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(wire, canonical) {
		// Also rejects duplicate/unknown keys, aliases and trailing content.
		return Accepted{}, ErrEvidenceRejected
	}
	c := e.Challenge
	now := v.cfg.Now().UTC().UnixMilli()
	nonce, err := base64.RawURLEncoding.DecodeString(c.Nonce)
	if err != nil || len(nonce) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != c.Nonce ||
		c.Version != protocolVersion || c.Scope != v.cfg.Scope ||
		c.WitnessID != v.cfg.WitnessID ||
		c.ExpiresAtMillis <= c.IssuedAtMillis ||
		c.ExpiresAtMillis-c.IssuedAtMillis != v.cfg.TTL.Milliseconds() ||
		now < c.IssuedAtMillis || now >= c.ExpiresAtMillis ||
		e.ObservedAtMillis < c.IssuedAtMillis || e.ObservedAtMillis > now ||
		e.ObservedAtMillis >= c.ExpiresAtMillis ||
		!witnessUUIDPattern.MatchString(e.RunID) {
		return Accepted{}, ErrEvidenceRejected
	}
	o := e.Observations
	if !o.RealityVisionOK || !o.ProtectedIPv4Denied || !o.ProtectedIPv6Denied ||
		!o.MetadataDenied || !o.DNSRebindingDenied ||
		o.BytesSent == 0 || o.BytesReceived == 0 ||
		o.BytesSent > 1<<40 || o.BytesReceived > 1<<40 ||
		!witnessRefPattern.MatchString(o.TranscriptDigest) {
		return Accepted{}, ErrEvidenceRejected
	}
	signature, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || len(e.Signature) != 86 || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != e.Signature {
		return Accepted{}, ErrEvidenceRejected
	}
	payload, err := SigningBytes(e)
	if err != nil || !ed25519.Verify(v.cfg.WitnessKey, payload, signature) {
		return Accepted{}, ErrEvidenceRejected
	}
	hash := sha256.Sum256(wire)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	challengeWire, err := json.Marshal(c)
	if err != nil {
		return Accepted{}, ErrEvidenceRejected
	}

	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return Accepted{}, ErrEvidenceRejected
	}
	defer tx.Rollback()
	var stored []byte
	var expires int64
	var consumed sql.NullString
	if err := tx.QueryRowContext(ctx,
		"SELECT challenge,expires_at_ms,consumed_digest FROM witness_challenges WHERE nonce=?",
		c.Nonce).Scan(&stored, &expires, &consumed); err != nil ||
		consumed.Valid || expires != c.ExpiresAtMillis ||
		!bytes.Equal(stored, challengeWire) ||
		v.cfg.Now().UTC().UnixMilli() >= expires {
		return Accepted{}, ErrEvidenceRejected
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE witness_challenges SET consumed_digest=?,run_id=? WHERE nonce=? AND consumed_digest IS NULL AND expires_at_ms > ?",
		digest, e.RunID, c.Nonce, v.cfg.Now().UTC().UnixMilli())
	if err != nil {
		return Accepted{}, ErrEvidenceRejected
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 || tx.Commit() != nil {
		return Accepted{}, ErrEvidenceRejected
	}
	return Accepted{
		Scope: c.Scope, Nonce: c.Nonce,
		RunID: e.RunID, WitnessID: c.WitnessID, EvidenceDigest: digest,
		ObservedAtMillis: e.ObservedAtMillis,
	}, nil
}
