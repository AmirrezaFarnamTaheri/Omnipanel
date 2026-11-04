package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var ErrTaskNotFound = errors.New("backup task not found")

// Repository stores task lifecycle facts locally in SQLite WAL mode. This is
// a durable metadata ledger, not an artifact store or backup executor.
type Repository struct {
	db *sql.DB
	mu sync.Mutex
}

func OpenRepository(path string) (*Repository, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("repository path must be absolute")
	}
	path = filepath.Clean(path)
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("stat repository directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByProcess(info) {
		return nil, fmt.Errorf("repository directory must be a private caller-owned directory")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByProcess(info) {
			return nil, fmt.Errorf("repository database must be a private caller-owned regular file")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, fmt.Errorf("create private repository database: %w", createErr)
		}
		if createErr = f.Close(); createErr != nil {
			return nil, createErr
		}
	} else {
		return nil, fmt.Errorf("stat repository database: %w", err)
	}

	dsn := "file:" + filepath.ToSlash(path) + "?_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open backup task repository: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect backup task repository: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("protect backup task database: %w", err)
	}
	if err := verifySidecars(path); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS backup_tasks (
		id TEXT PRIMARY KEY, kind TEXT NOT NULL, state TEXT NOT NULL,
		attempt INTEGER NOT NULL, created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL,
		artifact_digest TEXT NOT NULL, error_code TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize backup task repository: %w", err)
	}
	return &Repository{db: db}, nil
}

func ownedByProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func verifySidecars(path string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		p := path + suffix
		info, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect repository sidecar: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByProcess(info) {
			return fmt.Errorf("repository sidecar must be a private caller-owned regular file")
		}
	}
	return nil
}

func (r *Repository) Close() error { return r.db.Close() }

func (r *Repository) Create(ctx context.Context, task Task) error {
	if err := task.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := r.db.ExecContext(ctx, `INSERT INTO backup_tasks(id,kind,state,attempt,created_ns,updated_ns,artifact_digest,error_code) VALUES(?,?,?,?,?,?,?,?)`,
		task.ID, task.Kind, task.State, task.Attempt, task.CreatedAt.UnixNano(), task.UpdatedAt.UnixNano(), task.ArtifactDigest, task.ErrorCode)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
		return fmt.Errorf("task id already exists")
	}
	return err
}

func (r *Repository) Get(ctx context.Context, id string) (Task, error) {
	var t Task
	var created, updated int64
	err := r.db.QueryRowContext(ctx, `SELECT id,kind,state,attempt,created_ns,updated_ns,artifact_digest,error_code FROM backup_tasks WHERE id=?`, id).
		Scan(&t.ID, &t.Kind, &t.State, &t.Attempt, &created, &updated, &t.ArtifactDigest, &t.ErrorCode)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, ErrTaskNotFound
	}
	if err != nil {
		return Task{}, err
	}
	t.CreatedAt = timeFromUnixNano(created)
	t.UpdatedAt = timeFromUnixNano(updated)
	return t, t.Validate()
}

func (r *Repository) Advance(ctx context.Context, id string, next State, now time.Time, digest, errorCode string) (Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, err := r.Get(ctx, id)
	if err != nil {
		return Task{}, err
	}
	n, err := t.Advance(next, now, digest, errorCode)
	if err != nil {
		return Task{}, err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE backup_tasks SET state=?,attempt=?,updated_ns=?,artifact_digest=?,error_code=? WHERE id=? AND state=? AND updated_ns=?`,
		n.State, n.Attempt, n.UpdatedAt.UnixNano(), n.ArtifactDigest, n.ErrorCode, id, t.State, t.UpdatedAt.UnixNano())
	if err != nil {
		return Task{}, err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return Task{}, err
	}
	if count != 1 {
		return Task{}, ErrInvalidTransition
	}
	return n, nil
}

func timeFromUnixNano(ns int64) time.Time { return time.Unix(0, ns).UTC() }
