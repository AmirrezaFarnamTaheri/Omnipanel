package singbox

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
)

func preparedTestFixture(t *testing.T) (*state.Store, *NativeStager, drivers.BuildIdentity, drivers.ComponentPlan, string) {
	t.Helper()
	stager, _, _, build := nativeFixture(t, passingNative)
	_, plan := compiledTestPlan()
	plan.Revision.Manifest.Components[0].ArtifactDigest = build.ArtifactDigest
	plan.Revision.Manifest.Components[0].ConfigurationDigest = fragmentDigest(t, build, plan)

	private := filepath.Join(t.TempDir(), "node-private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "state.sqlite")
	s, err := state.Open(path, plan.Revision.Manifest.NodeID, plan.Revision.Manifest.ControlPlaneEpoch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	if _, err := s.RecordReceived(ctx, plan.Revision); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(ctx, plan.Revision.Manifest.StructuralSequence, plan.Revision.Digest, state.Verified); err != nil {
		t.Fatal(err)
	}
	// Test-only recovery baseline. Production obtains its root-owned LKG
	// reference from separate trusted deployment bootstrap and health proof.
	setPreparedTestLKG(t, path, "sha256:"+strings.Repeat("b", 64))
	return s, stager, build, plan, path
}

func setPreparedTestLKG(t *testing.T, dbPath, lkg string) {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE node_scope SET last_good_ref=? WHERE singleton=1", lkg); err != nil {
		t.Fatal(err)
	}
}

func setPreparedTestJournalStage(t *testing.T, dbPath string, stage state.Stage) {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE revisions SET stage=?", stage); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareActivationBindsSignedManifestCompiledConfigNativeStageAndRecoveryLease(t *testing.T) {
	store, stager, build, plan, path := preparedTestFixture(t)
	ctx := context.Background()
	expected, err := CompileFull(ctx, []drivers.ComponentPlan{plan}, ProtectedPolicy{}, build)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	prepared, err := PrepareActivation(ctx, store, stager, []drivers.ComponentPlan{plan}, ProtectedPolicy{}, build, deadline)
	if err != nil {
		t.Fatalf("verified compile-stage-reserve unexpectedly failed: %v", err)
	}
	if prepared.Staged.SHA256 != expected.SHA256 ||
		prepared.Staged.ComponentID != expected.ComponentID ||
		prepared.Guard.CandidateDigest != expected.SHA256 ||
		prepared.Guard.ManifestDigest != plan.Revision.Digest ||
		prepared.Guard.StructuralSequence != plan.Revision.Manifest.StructuralSequence ||
		prepared.Guard.MembershipSequence != plan.Revision.Manifest.MembershipSequence ||
		prepared.Guard.RollbackRef != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("preparation failed to bind the candidate and rollback guard: %+v", prepared)
	}
	privateBytes, err := os.ReadFile(prepared.Staged.Path)
	if err != nil || !bytes.Equal(privateBytes, expected.Content) {
		t.Fatal("privately staged bytes differ from the manifest-bound compilation")
	}
	stat, err := os.Stat(prepared.Staged.Path)
	if err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatalf("private candidate file permissions unexpected: %v %v", stat, err)
	}
	pending, err := store.UnconfirmedActivation(ctx)
	if err != nil || pending == nil || *pending != prepared.Guard {
		t.Fatalf("WAL must contain the exact guard before reporting prepared: %+v %v", pending, err)
	}
	cursor, err := store.Cursor(ctx)
	if err != nil || cursor.StructuralSequence != 0 || cursor.MembershipSequence != 0 || cursor.Digest != "" {
		t.Fatalf("preparing candidate must never advance applied cursor: %+v %v", cursor, err)
	}
	// Recovery lease survives process restart. The caller may lose its
	// in-memory receipt but cannot lose crash-safe rollback obligation.
	reopened, err := state.Open(path, plan.Revision.Manifest.NodeID, plan.Revision.Manifest.ControlPlaneEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	saved, err := reopened.UnconfirmedActivation(ctx)
	if err != nil || saved == nil || *saved != prepared.Guard {
		t.Fatalf("reopened journal lost the guard: %+v %v", saved, err)
	}
	if _, err := PrepareActivation(ctx, store, stager, []drivers.ComponentPlan{plan}, ProtectedPolicy{}, build, time.Now().Add(90*time.Second)); err == nil {
		t.Fatal("unconfirmed activation must never be replaced or extended on retry")
	}
	savedAgain, err := reopened.UnconfirmedActivation(ctx)
	if err != nil || savedAgain == nil || *savedAgain != *saved {
		t.Fatal("refused replacement altered the durable rollback guard")
	}
}

func TestPrepareActivationNeverReservesWithoutSignedComponentNativeCheckAndKnownGood(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *state.Store, **NativeStager, *drivers.BuildIdentity, *drivers.ComponentPlan, *string)
	}{
		{"missing native stager", func(_ *testing.T, _ *state.Store, stager **NativeStager, _ *drivers.BuildIdentity, _ *drivers.ComponentPlan, _ *string) {
			*stager = nil
		}},
		{"wrong native build identity", func(_ *testing.T, _ *state.Store, _ **NativeStager, build *drivers.BuildIdentity, _ *drivers.ComponentPlan, _ *string) {
			build.ArtifactDigest = strings.Repeat("f", 64)
		}},
		{"changed user credentials after component signing", func(_ *testing.T, _ *state.Store, _ **NativeStager, _ *drivers.BuildIdentity, plan *drivers.ComponentPlan, _ *string) {
			plan.Reality.PrivateKey = strings.Repeat("B", 43)
		}},
		{"missing certified known-good baseline", func(t *testing.T, _ *state.Store, _ **NativeStager, _ *drivers.BuildIdentity, _ *drivers.ComponentPlan, path *string) {
			setPreparedTestLKG(t, *path, "")
		}},
		{"journal is still RECEIVED", func(t *testing.T, _ *state.Store, _ **NativeStager, _ *drivers.BuildIdentity, _ *drivers.ComponentPlan, path *string) {
			setPreparedTestJournalStage(t, *path, state.Received)
		}},
		{"wrong node scope", func(_ *testing.T, _ *state.Store, _ **NativeStager, _ *drivers.BuildIdentity, plan *drivers.ComponentPlan, _ *string) {
			plan.Revision.Manifest.NodeID = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc"
		}},
		{"native check returns failure", func(t *testing.T, _ *state.Store, stager **NativeStager, build *drivers.BuildIdentity, plan *drivers.ComponentPlan, _ *string) {
			rejected, _, _, nativeBuild := nativeFixture(t, "#!/bin/sh\nexit 27\n")
			*stager = rejected
			*build = nativeBuild
			plan.Revision.Manifest.Components[0].ArtifactDigest = nativeBuild.ArtifactDigest
			plan.Revision.Manifest.Components[0].ConfigurationDigest = fragmentDigest(t, nativeBuild, *plan)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, stager, build, plan, path := preparedTestFixture(t)
			tc.mutate(t, store, &stager, &build, &plan, &path)
			_, err := PrepareActivation(context.Background(), store, stager, []drivers.ComponentPlan{plan}, ProtectedPolicy{}, build, time.Now().Add(time.Minute))
			if err == nil {
				t.Fatal("unauthorized preparation unexpectedly succeeded")
			}
			guard, err := store.UnconfirmedActivation(context.Background())
			if err != nil || guard != nil {
				t.Fatalf("failure must not persist an activation guard: %+v %v", guard, err)
			}
			cursor, err := store.Cursor(context.Background())
			if err != nil || cursor.StructuralSequence != 0 {
				t.Fatalf("failed preparation advanced the applied cursor: %+v %v", cursor, err)
			}
		})
	}
}

func TestPrepareActivationRefusesNilStoreExpiredDeadlineAndCancelledContext(t *testing.T) {
	store, stager, build, plan, _ := preparedTestFixture(t)
	plans := []drivers.ComponentPlan{plan}
	if _, err := PrepareActivation(context.Background(), nil, stager, plans, ProtectedPolicy{}, build, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("missing trusted WAL journal accepted")
	}
	if _, err := PrepareActivation(context.Background(), store, stager, plans, ProtectedPolicy{}, build, time.Now().Add(-time.Minute)); err == nil {
		t.Fatal("deadline in past accepted")
	}
	if _, err := PrepareActivation(context.Background(), store, stager, plans, ProtectedPolicy{Mode: "allow-all"}, build, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("unknown egress mode accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := PrepareActivation(ctx, store, stager, plans, ProtectedPolicy{}, build, time.Now().Add(time.Minute))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled preflight must preserve ctx.Err, got %v", err)
	}
	if pending, err := store.UnconfirmedActivation(context.Background()); err != nil || pending != nil {
		t.Fatal("rejected calls must not leave a rollback guard")
	}
}
