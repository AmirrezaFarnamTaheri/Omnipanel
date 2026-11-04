package backup

import (
	"errors"
	"testing"
	"time"
)

func TestBackupTaskLifecycleAndRetry(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 12, 0, 0, 0, time.FixedZone("local", 3*60*60))
	task, err := NewTask("backup-1", Backup, t0)
	if err != nil {
		t.Fatal(err)
	}
	if task.Attempt != 1 || task.CreatedAt.Location() != time.UTC {
		t.Fatalf("initial task: %+v", task)
	}
	failed, err := task.Advance(Running, t0.Add(time.Second), "", "")
	if err != nil {
		t.Fatal(err)
	}
	failed, err = failed.Advance(Failed, t0.Add(2*time.Second), "", "storage_unavailable")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := failed.Advance(Queued, t0.Add(3*time.Second), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if retry.Attempt != 2 || retry.ErrorCode != "" {
		t.Fatalf("retry did not reset attempt data: %+v", retry)
	}
	running, _ := retry.Advance(Running, t0.Add(4*time.Second), "", "")
	done, err := running.Advance(Succeeded, t0.Add(5*time.Second), "sha256:abc", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := done.Advance(Queued, t0.Add(6*time.Second), "", ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("completed task mutable: %v", err)
	}
}

func TestRestoreRequiresVerificationAndDigest(t *testing.T) {
	t0 := time.Now().UTC()
	task, err := NewTask("restore-1", Restore, t0)
	if err != nil {
		t.Fatal(err)
	}
	running, _ := task.Advance(Running, t0.Add(time.Second), "", "")
	verified, err := running.Advance(VerifyingRestore, t0.Add(2*time.Second), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verified.Advance(Restored, t0.Add(3*time.Second), "", ""); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("restore without digest accepted: %v", err)
	}
	done, err := verified.Advance(Restored, t0.Add(3*time.Second), "sha256:artifact", "")
	if err != nil {
		t.Fatal(err)
	}
	if done.State != Restored {
		t.Fatalf("unexpected state %s", done.State)
	}
}

func TestTaskRejectsTimeRegressionAndErrorDisclosure(t *testing.T) {
	t0 := time.Now().UTC()
	task, err := NewTask("backup-2", Backup, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := task.Advance(Running, t0.Add(-time.Second), "", ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("backwards timestamp accepted: %v", err)
	}
	if _, err := task.Advance(Running, t0.Add(time.Second), "", ""); err != nil {
		t.Fatal(err)
	}
	bad := task
	bad.ErrorCode = "secret\n/path"
	if err := bad.Validate(); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("unsafe error code accepted: %v", err)
	}
}
