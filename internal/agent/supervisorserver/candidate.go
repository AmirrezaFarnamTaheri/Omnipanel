// Package supervisorserver keeps candidate activation distinct from recovery.
// An approved candidate is a root-provisioned, single-use local authorization,
// not an unprivileged journal claim or a remotely supplied configuration.
package supervisorserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const maxCandidateSequence uint64 = 9007199254740991

var (
	ErrCandidateApproval   = errors.New("root candidate approval or durable one-time authorization rejected")
	candidateUUIDPattern   = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
	candidateDigestPattern = regexp.MustCompile("^[a-f0-9]{64}$")
)

// CandidateApproval is loaded ONLY from the 0600 root-owned supervisor
// provisioning file. The unprivileged socket request supplies its SHA-256
// reference alone, never this trust decision, rollback reference, node scope,
// manifest digest, deadline, filesystem paths or service name.
//
// A root operator must separately validate signed manifest intent, compiler
// policy, the native staged bytes and the independent prior LKG before
// provisioning this approval. Root-side signing/issuance is a later milestone;
// this ticket cannot be created by the node poller or a public web action.
type CandidateApproval struct {
	Reference          string
	RollbackRef        string
	ManifestDigest     string
	NodeID             string
	Epoch              string
	StructuralSequence uint64
	MembershipSequence uint64
	ExpiresUnixNano    int64
}

// Validate ensures the candidate NEVER enters the recovery allowlist. The
// source of truth is root-owned local provisioning, not the IPC payload.
func (a CandidateApproval) Validate(recovery map[string]bool, now time.Time) error {
	if now.IsZero() || !generationPattern.MatchString(a.Reference) ||
		!generationPattern.MatchString(a.RollbackRef) ||
		a.Reference == a.RollbackRef ||
		!recovery[a.RollbackRef] || recovery[a.Reference] ||
		!candidateDigestPattern.MatchString(a.ManifestDigest) ||
		!candidateUUIDPattern.MatchString(a.NodeID) ||
		!candidateUUIDPattern.MatchString(a.Epoch) ||
		a.StructuralSequence == 0 || a.StructuralSequence > maxCandidateSequence ||
		a.MembershipSequence > maxCandidateSequence ||
		a.ExpiresUnixNano <= now.UnixNano() ||
		a.ExpiresUnixNano > now.Add(2*time.Minute).UnixNano() {
		return ErrCandidateApproval
	}
	return nil
}

// approvedCandidateBytes requires a root-owned, 0600 exact-generation file.
// It deliberately does not use generationBytes because that function
// authorizes ONLY rollback LKG refs.
func (b *NativeBackend) approvedCandidateBytes(ref string) ([]byte, error) {
	if err := b.protectedDir(b.cfg.GenerationDirectory); err != nil {
		return nil, err
	}
	path := filepath.Join(b.cfg.GenerationDirectory, strings.TrimPrefix(ref, "sha256:")+".json")
	file, info, err := b.checkedFile(path, maxGenerationBytes, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxGenerationBytes+1))
	if err != nil || int64(len(raw)) != info.Size() || len(raw) == 0 {
		return nil, ErrNativeRejected
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != ref {
		return nil, ErrNativeRejected
	}
	return raw, nil
}

func (b *NativeBackend) requireActiveRollback(ref string) error {
	if err := b.protectedDir(filepath.Dir(b.cfg.ActiveConfigPath)); err != nil {
		return err
	}
	file, info, err := b.checkedFile(b.cfg.ActiveConfigPath, maxGenerationBytes, false)
	if err != nil {
		return err
	}
	defer file.Close()
	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(file, maxGenerationBytes+1))
	if err != nil || n != info.Size() ||
		"sha256:"+hex.EncodeToString(sum.Sum(nil)) != ref {
		return ErrNativeRejected
	}
	return nil
}

// consumeCandidateTicket durably records one root-owned use BEFORE active
// replacement. O_EXCL prevents duplicate use across supervisor processes;
// fsync of both marker and parent fences a crash before the host mutation.
// Any uncertain write failure remains fail-closed; the marker is never removed
// to permit retries. The watchdog alone restores the former LKG.
func (b *NativeBackend) consumeCandidateTicket(approval CandidateApproval) error {
	if err := b.protectedDir(b.cfg.GenerationDirectory); err != nil {
		return err
	}
	path := filepath.Join(b.cfg.GenerationDirectory,
		".activation-"+strings.TrimPrefix(approval.Reference, "sha256:")+".used")
	fd, err := syscall.Open(path,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrCandidateApproval
	}
	file := os.NewFile(uintptr(fd), path)
	// Only public hashes and node scope are recorded, never runtime JSON.
	if _, err := file.WriteString(approval.ManifestDigest + "\n" + approval.NodeID + "\n" + approval.Epoch + "\n"); err != nil {
		file.Close()
		return ErrCandidateApproval
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return ErrCandidateApproval
	}
	if err := file.Close(); err != nil {
		return ErrCandidateApproval
	}
	dir, err := os.Open(b.cfg.GenerationDirectory)
	if err != nil {
		return ErrCandidateApproval
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return ErrCandidateApproval
	}
	return nil
}

// ApplyApprovedCandidate is the ONLY privileged candidate transition.
// It refuses unknown/replayed/expired approvals, wrong former active LKG,
// candidate content mutation, unsigned native binary substitutions and native
// syntax errors. It returns when the fixed systemd restart command succeeds;
// it deliberately DOES NOT claim listener health, independent network proof,
// durable applied state or an ACK. A crash/restart failure after the consumed
// marker leaves the separate watchdog rollback lease pending.
func (b *NativeBackend) ApplyApprovedCandidate(ctx context.Context, ref string) error {
	if b == nil || ctx == nil {
		return ErrNativeRejected
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.approval == nil || b.approval.Reference != ref ||
		b.approval.Validate(b.allowed, time.Now()) != nil {
		return ErrCandidateApproval
	}
	approval := *b.approval
	if _, err := b.generationBytes(approval.RollbackRef); err != nil {
		return err
	}
	if err := b.requireActiveRollback(approval.RollbackRef); err != nil {
		return err
	}
	raw, err := b.approvedCandidateBytes(ref)
	if err != nil {
		return err
	}
	if err := b.checkPinnedBinary(b.cfg.SingBoxBinary, b.cfg.SingBoxBinaryDigest); err != nil {
		return err
	}
	if err := b.checkPinnedBinary(b.cfg.SystemctlBinary, b.cfg.SystemctlBinaryDigest); err != nil {
		return err
	}
	dirPath := filepath.Dir(b.cfg.ActiveConfigPath)
	file, err := os.CreateTemp(dirPath, ".candidate-")
	if err != nil {
		return ErrNativeFailed
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return ErrNativeFailed
	}
	n, err := file.Write(raw)
	if err != nil || n != len(raw) {
		return ErrNativeFailed
	}
	if err := file.Sync(); err != nil {
		return ErrNativeFailed
	}
	if err := file.Close(); err != nil {
		return ErrNativeFailed
	}
	if err := b.runPinned(ctx, b.cfg.SingBoxBinary, "check", "-c", tmp); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := approval.Validate(b.allowed, time.Now()); err != nil {
		return err
	}
	// The irrevocable root-owned marker MUST be durable before rename.
	if err := b.consumeCandidateTicket(approval); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.cfg.ActiveConfigPath); err != nil {
		return ErrNativeFailed
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return ErrNativeFailed
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return ErrNativeFailed
	}
	return b.runPinned(ctx, b.cfg.SystemctlBinary, "restart", fixedSingBoxUnit)
}
