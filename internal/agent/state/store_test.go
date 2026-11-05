package state

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

const (
	testNode  = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	testEpoch = "ea2429da-7540-4e40-ae70-38fd3f19794b"
)

// Go's testing.TempDir can create a 0755 child under the runner's umask.
// A node journal must live in an explicitly owner-only directory.
func privateTestDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node-private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func testRevision() manifest.Verified {
	return manifest.Verified{
		Decision: manifest.ApplyRevision,
		Digest:   strings.Repeat("a", 64),
		Manifest: manifest.Manifest{
			SchemaVersion:      "2.0",
			NodeID:             testNode,
			ControlPlaneEpoch:  testEpoch,
			StructuralSequence: 2,
			MembershipSequence: 3,
			BaseEgressPolicy:   "deny-protected-v1",
		},
	}
}

func TestWALJournalRecoversVerifiedIntentWithoutClaimingDeployment(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "agent.sqlite")
	ctx := context.Background()
	s, err := Open(path, testNode, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	revision := testRevision()
	first, err := s.RecordReceived(ctx, revision)
	if err != nil || !first {
		t.Fatalf("new verified intent must be recorded once: fresh=%t err=%v", first, err)
	}
	if err := s.Transition(ctx, revision.Manifest.StructuralSequence, revision.Digest, Verified); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testNode, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Stage != Verified || pending[0].Digest != revision.Digest ||
		pending[0].StructuralSequence != revision.Manifest.StructuralSequence {
		t.Fatalf("journal did not survive a process restart: %+v", pending)
	}
	repeated, err := reopened.RecordReceived(ctx, revision)
	if err != nil || repeated {
		t.Fatalf("duplicate intent must be idempotent: fresh=%t err=%v", repeated, err)
	}
	cursor, err := reopened.Cursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.StructuralSequence != 0 || cursor.MembershipSequence != 0 || cursor.Digest != "" {
		t.Fatalf("observing signed intent must not advance applied cursor: %+v", cursor)
	}
}

func TestJournalRejectsConflictingOrUnverifiedRevisions(t *testing.T) {
	s, err := Open(filepath.Join(privateTestDir(t), "agent.sqlite"), testNode, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	original := testRevision()
	if _, err := s.RecordReceived(ctx, original); err != nil {
		t.Fatal(err)
	}
	changes := []struct {
		name   string
		change func(*manifest.Verified)
	}{
		{"same structural sequence different digest", func(v *manifest.Verified) { v.Digest = strings.Repeat("b", 64) }},
		{"same sequence different membership", func(v *manifest.Verified) { v.Manifest.MembershipSequence++ }},
		{"wrong node", func(v *manifest.Verified) { v.Manifest.NodeID = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc" }},
		{"wrong epoch", func(v *manifest.Verified) { v.Manifest.ControlPlaneEpoch = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc" }},
		{"unverified decision", func(v *manifest.Verified) { v.Decision = "" }},
		{"lower sequence", func(v *manifest.Verified) { v.Manifest.StructuralSequence = 1 }},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			candidate := testRevision()
			tc.change(&candidate)
			if _, err := s.RecordReceived(ctx, candidate); err == nil {
				t.Fatal("conflicting or unverified desired state entered the journal")
			}
		})
	}
	pending, err := s.Pending(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("rejected revisions must leave the existing record unchanged: %+v, %v", pending, err)
	}
}

func TestJournalProtectsNodeScopeAndRefusesSymlinks(t *testing.T) {
	dir := privateTestDir(t)
	path := filepath.Join(dir, "state.sqlite")
	s, err := Open(path, testNode, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, testNode, "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc"); err == nil {
		t.Fatal("node-local epoch must not be replaced by a new caller")
	}
	link := filepath.Join(dir, "database-link.sqlite")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, testNode, testEpoch); err == nil {
		t.Fatal("refusing symlinked state database is required")
	}
}

// fakeOwnedInfo fabricates POSIX ownership so the uid refusal path is tested
// without root privileges (chown to another uid is not available in CI).
type fakeOwnedInfo struct {
	os.FileInfo
	uid uint32
}

func (f fakeOwnedInfo) Sys() any { return &syscall.Stat_t{Uid: f.uid} }

func TestOwnershipVerificationFailsClosed(t *testing.T) {
	dir := privateTestDir(t)
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ownedByCaller(info) {
		t.Fatal("caller-owned directory rejected")
	}
	if ownedByCaller(fakeOwnedInfo{FileInfo: info, uid: uint32(os.Geteuid() + 1)}) {
		t.Fatal("foreign-owned tree accepted on permission bits alone")
	}
	if ownedByCaller(infoWithoutStat{}) {
		t.Fatal("platform without POSIX stat must fail closed")
	}
}

type infoWithoutStat struct{ os.FileInfo }

func (infoWithoutStat) Sys() any { return nil }

func TestJournalRefusesHostileSidecars(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{
			name: "symlinked wal",
			setup: func(t *testing.T, path string) {
				target := filepath.Join(t.TempDir(), "elsewhere.sqlite-wal")
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path+"-wal"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "group-readable wal",
			setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path+"-wal", nil, 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "world-readable shm",
			setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path+"-shm", nil, 0o604); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory wal",
			setup: func(t *testing.T, path string) {
				if err := os.Mkdir(path+"-wal", 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateTestDir(t)
			path := filepath.Join(dir, "state.sqlite")
			s, err := Open(path, testNode, testEpoch)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			// Remove genuine sidecars from the clean close, then plant the hostile one.
			for _, suffix := range []string{"-wal", "-shm"} {
				if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}
			tc.setup(t, path)
			if _, err := Open(path, testNode, testEpoch); err == nil || !strings.Contains(err.Error(), "sidecar") {
				t.Fatalf("hostile sidecar accepted: %v", err)
			}
		})
	}
}

func TestJournalAcceptsPrivateCallerOwnedSidecars(t *testing.T) {
	dir := privateTestDir(t)
	path := filepath.Join(dir, "state.sqlite")
	s, err := Open(path, testNode, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordReceived(context.Background(), testRevision()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Force private, caller-owned sidecars to exist at open time.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(path+suffix, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err = Open(path, testNode, testEpoch)
	if err != nil {
		t.Fatalf("private sidecars rejected: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
