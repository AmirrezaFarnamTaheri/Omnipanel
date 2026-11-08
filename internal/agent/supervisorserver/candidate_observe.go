package supervisorserver

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const maxConsumedCandidateMarkerBytes = 512

// requireConsumedCandidateTicket verifies the root-only, fsynced single-use
// marker written BEFORE active replacement. Missing, symlinked, world-readable
// or altered markers cannot prove that a candidate applied via this supervisor.
func (b *NativeBackend) requireConsumedCandidateTicket(approval CandidateApproval) error {
	if err := b.protectedDir(b.cfg.GenerationDirectory); err != nil {
		return err
	}
	path := filepath.Join(b.cfg.GenerationDirectory,
		".activation-"+strings.TrimPrefix(approval.Reference, "sha256:")+".used")
	file, info, err := b.checkedFile(path, maxConsumedCandidateMarkerBytes, false)
	if err != nil {
		return ErrCandidateApproval
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxConsumedCandidateMarkerBytes+1))
	expected := approval.ManifestDigest + "\n" + approval.NodeID + "\n" + approval.Epoch + "\n"
	if err != nil || int64(len(raw)) != info.Size() || string(raw) != expected {
		return ErrCandidateApproval
	}
	return nil
}

// ObserveApprovedCandidate is a read-only, locally rooted host witness, not
// independent public connectivity proof. It requires exact root provisioning,
// a consumed one-use ticket, immutable candidate bytes, former recovery LKG,
// active generation digest and the SAME systemd/MainPID/kernel-socket/SOCKS5
// policy checks as ObserveKnownGood. It never promotes a candidate into the
// rollback allowlist or clears an unconfirmed SQLite activation guard.
func (b *NativeBackend) ObserveApprovedCandidate(ctx context.Context, ref string) (bool, error) {
	if b == nil || ctx == nil {
		return false, ErrNativeRejected
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.approval == nil || b.approval.Reference != ref ||
		b.approval.Validate(b.allowed, time.Now()) != nil {
		return false, ErrCandidateApproval
	}
	approval := *b.approval
	if _, err := b.generationBytes(approval.RollbackRef); err != nil {
		return false, err
	}
	if _, err := b.approvedCandidateBytes(ref); err != nil {
		return false, err
	}
	if err := b.requireConsumedCandidateTicket(approval); err != nil {
		return false, err
	}
	if err := b.checkPinnedBinary(b.cfg.SingBoxBinary, b.cfg.SingBoxBinaryDigest); err != nil {
		return false, err
	}
	return b.observeExactActiveLocked(ctx, ref)
}
