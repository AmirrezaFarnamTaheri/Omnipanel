// Package backup defines a provider-neutral backup and restore task contract.
// It deliberately does not perform storage, database, or key-management work.
package backup

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidTask       = errors.New("invalid backup task")
	ErrInvalidTransition = errors.New("invalid backup task transition")
)

type State string

const (
	Queued           State = "queued"
	Running          State = "running"
	Succeeded        State = "succeeded"
	Failed           State = "failed"
	VerifyingRestore State = "verifying_restore"
	Restored         State = "restored"
)

type Kind string

const (
	Backup  Kind = "backup"
	Restore Kind = "restore"
)

// Task is an operator-visible lifecycle record. ErrorCode is a short stable
// identifier, never a raw error string that may disclose paths or credentials.
type Task struct {
	ID             string
	Kind           Kind
	State          State
	Attempt        uint32
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ArtifactDigest string
	ErrorCode      string
}

func NewTask(id string, kind Kind, now time.Time) (Task, error) {
	t := Task{ID: id, Kind: kind, State: Queued, Attempt: 1, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	if err := t.Validate(); err != nil {
		return Task{}, err
	}
	return t, nil
}

func (t Task) Validate() error {
	if strings.TrimSpace(t.ID) == "" || len(t.ID) > 128 || (t.Kind != Backup && t.Kind != Restore) || !validState(t.State) || t.Attempt == 0 || t.CreatedAt.IsZero() || t.UpdatedAt.Before(t.CreatedAt) {
		return ErrInvalidTask
	}
	if len(t.ArtifactDigest) > 128 || len(t.ErrorCode) > 64 || strings.ContainsAny(t.ErrorCode, "\r\n") {
		return ErrInvalidTask
	}
	if t.State == Succeeded || t.State == Restored {
		if t.ArtifactDigest == "" {
			return fmt.Errorf("%w: successful task requires artifact digest", ErrInvalidTask)
		}
	}
	if t.State == Failed && t.ErrorCode == "" {
		return fmt.Errorf("%w: failed task requires error code", ErrInvalidTask)
	}
	return nil
}

func validState(s State) bool {
	switch s {
	case Queued, Running, Succeeded, Failed, VerifyingRestore, Restored:
		return true
	}
	return false
}

// Advance returns a validated copy. State changes are explicit; failed tasks
// may be retried by advancing back to queued, while completed records are final.
func (t Task) Advance(next State, now time.Time, digest, errorCode string) (Task, error) {
	if err := t.Validate(); err != nil {
		return Task{}, err
	}
	if now.Before(t.UpdatedAt) {
		return Task{}, fmt.Errorf("%w: clock moved backwards", ErrInvalidTransition)
	}
	allowed := false
	switch t.State {
	case Queued:
		allowed = next == Running
	case Running:
		allowed = next == Succeeded || next == Failed || (t.Kind == Restore && next == VerifyingRestore)
	case Failed:
		allowed = next == Queued
	case VerifyingRestore:
		allowed = next == Restored || next == Failed
	}
	if !allowed {
		return Task{}, fmt.Errorf("%w: %s to %s", ErrInvalidTransition, t.State, next)
	}
	n := t
	n.State = next
	n.UpdatedAt = now.UTC()
	n.ArtifactDigest = digest
	n.ErrorCode = errorCode
	if next == Queued {
		n.Attempt++
		n.ArtifactDigest = ""
		n.ErrorCode = ""
	}
	if err := n.Validate(); err != nil {
		return Task{}, err
	}
	return n, nil
}
