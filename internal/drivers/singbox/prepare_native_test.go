package singbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
)

// TestPinnedNativeCandidatePreparation exercises the REAL signed Sing-box
// binary on a disposable GitHub Actions runner, then checks a private staged
// artifact and crash-recoverable SQLite rollback obligation. Its manifest
// fixture is test-scoped and synthetic: this is NOT signer authentication,
// root candidate authorization, applied state, protected egress or public M0.
func TestPinnedNativeCandidatePreparation(t *testing.T) {
	binary := os.Getenv("OMNI_NATIVE_TEST_SING_BOX_BIN")
	privateKey := os.Getenv("OMNI_NATIVE_REALITY_KEY")
	if binary == "" && privateKey == "" {
		t.Skip("signed Sing-box runner is required")
	}
	if binary == "" || privateKey == "" {
		t.Fatal("native binary and ephemeral Reality key must both be provided")
	}

	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	build := drivers.BuildIdentity{
		Runtime:        "singbox",
		Version:        "1.14.4+omni.2",
		ArtifactDigest: hex.EncodeToString(digest[:]),
	}

	_, plan := compiledTestPlan()
	plan.Reality.PrivateKey = privateKey
	plan.Revision.Manifest.Components[0].ArtifactDigest = build.ArtifactDigest
	plan.Revision.Manifest.Components[0].ConfigurationDigest = fragmentDigest(t, build, plan)

	root := t.TempDir()
	stageDir := filepath.Join(root, "private-stage")
	journalDir := filepath.Join(root, "private-journal")
	for _, dir := range []string{stageDir, journalDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stager, err := NewNativeStager(binary, stageDir, build)
	if err != nil {
		t.Fatal("the exact pinned runtime must be available for native staging")
	}
	journalPath := filepath.Join(journalDir, "state.sqlite")
	store, err := state.Open(journalPath, plan.Revision.Manifest.NodeID, plan.Revision.Manifest.ControlPlaneEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	if _, err := store.RecordReceived(ctx, plan.Revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(ctx, plan.Revision.Manifest.StructuralSequence, plan.Revision.Digest, state.Verified); err != nil {
		t.Fatal(err)
	}
	// Only the fixture is allowed to seed a known-good reference in SQLite.
	setPreparedTestLKG(t, journalPath, "sha256:"+strings.Repeat("b", 64))

	prepared, err := PrepareActivation(ctx, store, stager, []drivers.ComponentPlan{plan}, ProtectedPolicy{}, build, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("policy compiler + pinned native check + durable guard refused: %v", err)
	}
	if prepared.Guard.CandidateDigest != prepared.Staged.SHA256 ||
		prepared.Guard.ManifestDigest != plan.Revision.Digest ||
		prepared.Guard.RollbackRef != "sha256:"+strings.Repeat("b", 64) {
		t.Fatal("staged bytes and rollback guard do not share the approved generation")
	}
	candidate, err := os.ReadFile(prepared.Staged.Path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(candidate)
	if prepared.Staged.SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("native-checked staged artifact digest differs from private bytes")
	}
	if !bytes.Contains(candidate, []byte(privateKey)) {
		t.Fatal("native-checked candidate did not preserve its compiled Reality identity")
	}
	guard, err := store.UnconfirmedActivation(ctx)
	if err != nil || guard == nil || *guard != prepared.Guard {
		t.Fatalf("the pinned native check must be followed by a durable guard: %v", err)
	}
	cursor, err := store.Cursor(ctx)
	if err != nil || cursor.StructuralSequence != 0 || cursor.MembershipSequence != 0 || cursor.Digest != "" {
		t.Fatal("native staging and durable guard must never advance applied cursor")
	}
}
