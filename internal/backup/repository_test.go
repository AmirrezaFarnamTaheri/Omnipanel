package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRepositoryPersistsTaskStateAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tasks.sqlite")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	r, err := OpenRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	var journalMode string
	var synchronous int
	if err := r.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if err := r.db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" || synchronous != 2 {
		t.Fatalf("unsafe SQLite durability: journal=%q synchronous=%d", journalMode, synchronous)
	}
	task, err := NewTask("durable-1", Backup, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, task); err != nil {
		t.Fatal(err)
	}
	running, err := r.Advance(ctx, task.ID, Running, now.Add(time.Second), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	r, err = OpenRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := r.Get(ctx, task.ID)
	if err != nil || got.State != Running || got.Attempt != 1 || !got.UpdatedAt.Equal(running.UpdatedAt) {
		t.Fatalf("reopened task=%+v err=%v", got, err)
	}
	done, err := r.Advance(ctx, task.ID, Succeeded, now.Add(2*time.Second), "sha256:abc", "")
	if err != nil || done.State != Succeeded {
		t.Fatalf("completion=%+v err=%v", done, err)
	}
	if _, err := r.Get(ctx, "missing"); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("missing task error=%v", err)
	}
	if err := r.Create(ctx, task); err == nil {
		t.Fatal("duplicate task id accepted")
	}
}

func TestRepositoryRejectsUnsafeFilesystem(t *testing.T) {
	parent := t.TempDir()
	unsafeDir := filepath.Join(parent, "permissive")
	if err := os.Mkdir(unsafeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRepository(filepath.Join(unsafeDir, "tasks.sqlite")); err == nil {
		t.Fatal("permissive directory accepted")
	}

	dir := filepath.Join(parent, "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tasks.sqlite")
	if err := os.WriteFile(path, []byte("not a private db"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRepository(path); err == nil {
		t.Fatal("permissive DB accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "target"), path+"-wal"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRepository(path); err == nil {
		t.Fatal("symlinked WAL sidecar accepted")
	}
}

func TestRepositoryRejectsRelativePath(t *testing.T) {
	if _, err := OpenRepository("tasks.sqlite"); err == nil {
		t.Fatal("relative repository path accepted")
	}
}
