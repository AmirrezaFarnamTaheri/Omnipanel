// Package state persists verified desired-state intent in a node-scoped SQLite
// WAL journal. Recording intent is never proof of deployment or health.
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
	_ "github.com/mattn/go-sqlite3"
)

type Stage string

const (
	Received Stage = "RECEIVED"
	Verified Stage = "VERIFIED"
)

var (
	ErrInvalidScope      = errors.New("invalid local node identity or journal location")
	ErrRevisionConflict  = errors.New("conflicting or replayed node revision")
	ErrInvalidTransition = errors.New("unsupported journal transition")
	digestPattern        = regexp.MustCompile("^[a-f0-9]{64}$")
	uuidPattern          = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
)

type Snapshot struct {
	Epoch              string
	StructuralSequence uint64
	MembershipSequence uint64
	Digest             string
	Stage              Stage
}

// Store is bound to one authorized node and control-plane epoch. The separate
// manifest verifier owns signature and capability checks; do not call
// RecordReceived with data that has not passed manifest.Verifier.Verify.
type Store struct {
	db     *sql.DB
	nodeID string
	epoch  string
}

// Open requires an absolute path in an existing private directory. It refuses
// symlinks and permissive files, and never obtains its path from a manifest.
// The parent directory protects SQLite's -wal and -shm sidecars.
func Open(path, nodeID, epoch string) (*Store, error) {
	if !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 ||
		!uuidPattern.MatchString(nodeID) || !uuidPattern.MatchString(epoch) {
		return nil, fmt.Errorf("%w: invalid path or node/epoch identifier", ErrInvalidScope)
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%w: journal parent cannot be inspected: %v", ErrInvalidScope, err)
	}
	if !directory.IsDir() || directory.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: journal parent must be an owner-only real directory (mode %04o)", ErrInvalidScope, directory.Mode().Perm())
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%w: journal must be a private regular file", ErrInvalidScope)
		}
	case errors.Is(err, os.ErrNotExist):
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, fmt.Errorf("create protected SQLite journal: %w", createErr)
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("inspect SQLite journal: %w", err)
	}

	dsn := (&url.URL{
		Scheme:   "file",
		Path:     path,
		RawQuery: "_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL&_synchronous=FULL",
	}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite journal: %w", err)
	}
	db.SetMaxOpenConns(1)
	fail := func(cause error) (*Store, error) {
		_ = db.Close()
		return nil, cause
	}
	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fail(err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fail(errors.New("node journal requires SQLite WAL mode"))
	}
	var syncMode int
	if err := db.QueryRow("PRAGMA synchronous").Scan(&syncMode); err != nil {
		return fail(err)
	}
	if syncMode != 2 {
		return fail(errors.New("node journal requires synchronous=FULL"))
	}
	const scopeSQL = "CREATE TABLE IF NOT EXISTS node_scope (" +
		" singleton INTEGER PRIMARY KEY CHECK (singleton = 1)," +
		" node_id TEXT NOT NULL, epoch TEXT NOT NULL," +
		" applied_structural INTEGER NOT NULL DEFAULT 0," +
		" applied_membership INTEGER NOT NULL DEFAULT 0," +
		" applied_digest TEXT NOT NULL DEFAULT ''," +
		" last_good_ref TEXT NOT NULL DEFAULT '')"
	const journalSQL = "CREATE TABLE IF NOT EXISTS revisions (" +
		" epoch TEXT NOT NULL, structural INTEGER NOT NULL," +
		" membership INTEGER NOT NULL, digest TEXT NOT NULL," +
		" stage TEXT NOT NULL CHECK (stage IN ('RECEIVED','VERIFIED'))," +
		" created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP," +
		" PRIMARY KEY (epoch, structural))"
	for _, statement := range []string{scopeSQL, journalSQL} {
		if _, err := db.Exec(statement); err != nil {
			return fail(fmt.Errorf("initialize protected node journal: %w", err))
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return fail(err)
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO node_scope(singleton,node_id,epoch) VALUES(1,?,?)", nodeID, epoch); err != nil {
		_ = tx.Rollback()
		return fail(err)
	}
	var actualNode, actualEpoch string
	if err := tx.QueryRow("SELECT node_id,epoch FROM node_scope WHERE singleton=1").Scan(&actualNode, &actualEpoch); err != nil {
		_ = tx.Rollback()
		return fail(err)
	}
	if actualNode != nodeID || actualEpoch != epoch {
		_ = tx.Rollback()
		return fail(fmt.Errorf("%w: persisted scope differs from configured node or epoch", ErrInvalidScope))
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	return &Store{db: db, nodeID: nodeID, epoch: epoch}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// RecordReceived is idempotent for the same signed revision. Conflicting
// digests, lower revisions and scope changes are rejected transactionally.
// The input must be the result of trusted manifest.Verifier.Verify.
func (s *Store) RecordReceived(ctx context.Context, v manifest.Verified) (bool, error) {
	m := v.Manifest
	if v.Decision != manifest.ApplyRevision || m.NodeID != s.nodeID ||
		m.ControlPlaneEpoch != s.epoch || m.SchemaVersion != "2.0" ||
		m.BaseEgressPolicy != "deny-protected-v1" ||
		m.StructuralSequence == 0 || m.StructuralSequence > 9007199254740991 ||
		m.MembershipSequence > 9007199254740991 || !digestPattern.MatchString(v.Digest) {
		return false, ErrRevisionConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var appliedStructural, appliedMembership int64
	if err := tx.QueryRowContext(ctx, "SELECT applied_structural,applied_membership FROM node_scope WHERE singleton=1").
		Scan(&appliedStructural, &appliedMembership); err != nil {
		return false, err
	}
	if m.StructuralSequence <= uint64(appliedStructural) ||
		m.MembershipSequence < uint64(appliedMembership) {
		return false, ErrRevisionConflict
	}
	var latestStructural, latestMembership int64
	var latestDigest string
	err = tx.QueryRowContext(ctx,
		"SELECT structural,membership,digest FROM revisions WHERE epoch=? ORDER BY structural DESC LIMIT 1", s.epoch).
		Scan(&latestStructural, &latestMembership, &latestDigest)
	switch {
	case err == nil:
		if m.StructuralSequence < uint64(latestStructural) {
			return false, ErrRevisionConflict
		}
		if m.StructuralSequence == uint64(latestStructural) {
			if m.MembershipSequence != uint64(latestMembership) || v.Digest != latestDigest {
				return false, ErrRevisionConflict
			}
			return false, nil
		}
		if m.MembershipSequence < uint64(latestMembership) {
			return false, ErrRevisionConflict
		}
	case errors.Is(err, sql.ErrNoRows):
		// First signed intent for this protected node epoch.
	case err != nil:
		return false, err
	}
	_, err = tx.ExecContext(ctx,
		"INSERT INTO revisions(epoch,structural,membership,digest,stage) VALUES(?,?,?,?,?)",
		s.epoch, m.StructuralSequence, m.MembershipSequence, v.Digest, Received)
	if err != nil {
		return false, fmt.Errorf("record verified intent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// Transition can only advance a received record to VERIFIED. This foundation
// deliberately cannot mark revisions APPLIED or mutate the applied cursor.
func (s *Store) Transition(ctx context.Context, structural uint64, digest string, next Stage) error {
	if structural == 0 || structural > 9007199254740991 || !digestPattern.MatchString(digest) ||
		next != Verified {
		return ErrInvalidTransition
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingDigest string
	var current Stage
	if err := tx.QueryRowContext(ctx,
		"SELECT digest,stage FROM revisions WHERE epoch=? AND structural=?", s.epoch, structural).
		Scan(&existingDigest, &current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidTransition
		}
		return err
	}
	if existingDigest != digest {
		return ErrRevisionConflict
	}
	if current == Verified {
		return nil
	}
	if current != Received {
		return ErrInvalidTransition
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE revisions SET stage=? WHERE epoch=? AND structural=? AND stage=?",
		Verified, s.epoch, structural, Received); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Pending(ctx context.Context) ([]Snapshot, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT epoch,structural,membership,digest,stage FROM revisions WHERE epoch=? ORDER BY structural", s.epoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []Snapshot
	for rows.Next() {
		var item Snapshot
		var structural, membership int64
		if err := rows.Scan(&item.Epoch, &structural, &membership, &item.Digest, &item.Stage); err != nil {
			return nil, err
		}
		item.StructuralSequence = uint64(structural)
		item.MembershipSequence = uint64(membership)
		snapshots = append(snapshots, item)
	}
	return snapshots, rows.Err()
}

func (s *Store) Cursor(ctx context.Context) (manifest.Cursor, error) {
	var structural, membership int64
	var digest string
	err := s.db.QueryRowContext(ctx,
		"SELECT applied_structural,applied_membership,applied_digest FROM node_scope WHERE singleton=1").
		Scan(&structural, &membership, &digest)
	if err != nil {
		return manifest.Cursor{}, err
	}
	return manifest.Cursor{
		StructuralSequence: uint64(structural),
		MembershipSequence: uint64(membership),
		Digest:             digest,
	}, nil
}

// LastKnownGood is empty until a separately implemented, independently verified
// apply-and-confirm component commits an observed generation.
func (s *Store) LastKnownGood(ctx context.Context) (string, error) {
	var reference string
	err := s.db.QueryRowContext(ctx,
		"SELECT last_good_ref FROM node_scope WHERE singleton=1").Scan(&reference)
	return reference, err
}
