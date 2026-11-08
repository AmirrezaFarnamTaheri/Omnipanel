package supervisorserver

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const candidateJSON = "{\"log\":{\"level\":\"error\"},\"inbounds\":[],\"outbounds\":[{\"type\":\"block\",\"tag\":\"block\"}],\"route\":{\"final\":\"block\"}}"

func candidateApprovalForTest(ref, rollback string) CandidateApproval {
	return CandidateApproval{
		Reference:          ref,
		RollbackRef:        rollback,
		ManifestDigest:     strings.Repeat("a", 64),
		NodeID:             "62c478bb-47c3-4dc6-a363-a2fbde813810",
		Epoch:              "ea2429da-7540-4e40-ae70-38fd3f19794b",
		StructuralSequence: 2,
		MembershipSequence: 3,
		ExpiresUnixNano:    time.Now().Add(time.Minute).UnixNano(),
	}
}

func approvedCandidateFixture(t *testing.T, singScript, systemScript string) (nativeFixture, *NativeBackend, CandidateApproval) {
	t.Helper()
	fixture, _ := makeNativeFixture(t, singScript, systemScript)
	if err := os.WriteFile(fixture.active, []byte(safeRollbackJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	ref := "sha256:" + digestBytes([]byte(candidateJSON))
	candidatePath := filepath.Join(fixture.cfg.GenerationDirectory, strings.TrimPrefix(ref, "sha256:")+".json")
	if err := os.WriteFile(candidatePath, []byte(candidateJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	approval := candidateApprovalForTest(ref, fixture.ref)
	fixture.cfg.CandidateApproval = &approval
	b, err := newNativeBackend(fixture.cfg, map[string]bool{fixture.ref: true}, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("valid root-approved candidate denied: %v", err)
	}
	b.unitWitness = func(context.Context, string, string, string) error { return nil }
	return fixture, b, approval
}

func TestNativeCandidateApplyRequiresRootApprovalAndConsistentFormerKnownGood(t *testing.T) {
	fixture, backend, approval := approvedCandidateFixture(t, "", "")
	if err := backend.ApplyApprovedCandidate(context.Background(), approval.Reference); err != nil {
		t.Fatalf("root-authorized exact candidate refused: %v", err)
	}
	raw, err := os.ReadFile(fixture.active)
	if err != nil || !bytes.Equal(raw, []byte(candidateJSON)) {
		t.Fatalf("wrong active candidate bytes or read error: %v", err)
	}
	if info, err := os.Lstat(fixture.active); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("candidate must be root-private regular file: %v %v", info, err)
	}
	if err := backend.RestoreKnownGood(context.Background(), approval.Reference); err == nil {
		t.Fatal("candidate must NEVER inherit the rollback restore verb")
	}
	if healthy, err := backend.ObserveKnownGood(context.Background(), approval.Reference); err == nil || healthy {
		t.Fatal("candidate cannot masquerade as an independently observed last-known-good generation")
	}
	commands, err := os.ReadFile(fixture.systemLog)
	if err != nil || strings.TrimSpace(string(commands)) != "restart omnipanel-singbox.service" {
		t.Fatalf("candidate activation must restart only the fixed unit once: %v", err)
	}
	if err := backend.ApplyApprovedCandidate(context.Background(), approval.Reference); err == nil {
		t.Fatal("used root authorization must not be replayed")
	}
	second, err := newNativeBackend(fixture.cfg, map[string]bool{fixture.ref: true}, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := second.ApplyApprovedCandidate(context.Background(), approval.Reference); err == nil {
		t.Fatal("root daemon restart must not reset a consumed candidate authorization")
	}
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err != nil {
		t.Fatalf("watchdog must retain permission to restore exact former known-good: %v", err)
	}
	restored, err := os.ReadFile(fixture.active)
	if err != nil || !bytes.Equal(restored, []byte(safeRollbackJSON)) {
		t.Fatal("watchdog restoration did not recover the former immutable generation")
	}
}

func TestNativeCandidatePreflightFailuresNeverMutateRunningGeneration(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, nativeFixture, *NativeBackend, CandidateApproval)
	}{
		{"wrong reference", func(t *testing.T, _ nativeFixture, b *NativeBackend, approval CandidateApproval) {
			if err := b.ApplyApprovedCandidate(context.Background(), "sha256:" + strings.Repeat("c", 64)); err == nil {
				t.Fatal("unapproved generation accepted")
			}
		}},
		{"tampered candidate", func(t *testing.T, f nativeFixture, b *NativeBackend, approval CandidateApproval) {
			path := filepath.Join(f.cfg.GenerationDirectory, strings.TrimPrefix(approval.Reference, "sha256:")+".json")
			if err := os.WriteFile(path, []byte(candidateJSON+" "), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := b.ApplyApprovedCandidate(context.Background(), approval.Reference); err == nil {
				t.Fatal("tampered candidate accepted")
			}
		}},
		{"wrong former active generation", func(t *testing.T, f nativeFixture, b *NativeBackend, approval CandidateApproval) {
			if err := os.WriteFile(f.active, []byte(candidateJSON), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := b.ApplyApprovedCandidate(context.Background(), approval.Reference); err == nil {
				t.Fatal("active generation mismatch accepted")
			}
		}},
		{"expired approval", func(t *testing.T, f nativeFixture, b *NativeBackend, approval CandidateApproval) {
			b.approval.ExpiresUnixNano = time.Now().Add(-time.Minute).UnixNano()
			if err := b.ApplyApprovedCandidate(context.Background(), approval.Reference); err == nil {
				t.Fatal("expired root authorization accepted")
			}
		}},
		{"untrusted candidate permissions", func(t *testing.T, f nativeFixture, b *NativeBackend, approval CandidateApproval) {
			path := filepath.Join(f.cfg.GenerationDirectory, strings.TrimPrefix(approval.Reference, "sha256:")+".json")
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := b.ApplyApprovedCandidate(context.Background(), approval.Reference); err == nil {
				t.Fatal("public-readable candidate accepted")
			}
		}},
		{"cancelled context", func(t *testing.T, _ nativeFixture, b *NativeBackend, approval CandidateApproval) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := b.ApplyApprovedCandidate(ctx, approval.Reference); !errors.Is(err, context.Canceled) {
				t.Fatalf("context cancellation ignored: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture, backend, approval := approvedCandidateFixture(t, "", "")
			tc.mutate(t, fixture, backend, approval)
			if _, err := os.Stat(fixture.systemLog); !os.IsNotExist(err) {
				t.Fatal("rejected candidate restarted the service")
			}
			// A wrong-baseline fixture deliberately changes the initial file,
			// but rejected activation cannot replace it.
			active, err := os.ReadFile(fixture.active)
			if err != nil || len(active) == 0 {
				t.Fatal("rejection destroyed the active generation")
			}
		})
	}
}

func TestNativeCandidateFailedPinnedSyntaxLeavesFormerGenerationAndApprovalUnused(t *testing.T) {
	fixture, backend, approval := approvedCandidateFixture(t, "#!/bin/sh\nexit 37\n", "")
	if err := backend.ApplyApprovedCandidate(context.Background(), approval.Reference); err == nil {
		t.Fatal("native Sing-box preflight failure accepted")
	}
	raw, err := os.ReadFile(fixture.active)
	if err != nil || !bytes.Equal(raw, []byte(safeRollbackJSON)) {
		t.Fatal("invalid candidate destroyed known-good before commit")
	}
	if _, err := os.Stat(fixture.systemLog); !os.IsNotExist(err) {
		t.Fatal("failed native syntax check restarted systemd")
	}
}

func TestNativeCandidateRestartFailureConsumesApprovalButLeavesKnownGoodRestorable(t *testing.T) {
	fixture, backend, approval := approvedCandidateFixture(t, "", "#!/bin/sh\nexit 38\n")
	if err := backend.ApplyApprovedCandidate(context.Background(), approval.Reference); err == nil {
		t.Fatal("failed systemd restart acknowledged as active and healthy")
	}
	if err := backend.ApplyApprovedCandidate(context.Background(), approval.Reference); err == nil {
		t.Fatal("root ticket must stay consumed even after restart failure")
	}
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err == nil {
		t.Fatal("simulated failed systemd restoration acknowledged as recovered")
	}
	// The WAL watchdog guard MUST remain pending. Only an independent
	// successful LKG restoration + health observation may clear that guard.
}

func TestRootCandidateApprovalRequiresScopedBoundedExclusiveTicket(t *testing.T) {
	ref := "sha256:" + strings.Repeat("c", 64)
	good := candidateApprovalForTest(ref, knownGeneration)
	rollback := map[string]bool{knownGeneration: true}
	if err := good.Validate(rollback, time.Now()); err != nil {
		t.Fatalf("valid root-owned ticket refused: %v", err)
	}
	cases := []struct {
		name   string
		change func(*CandidateApproval)
	}{
		{"candidate equals known-good", func(a *CandidateApproval) { a.Reference = a.RollbackRef }},
		{"missing rollback allowlist", func(a *CandidateApproval) { a.RollbackRef = "sha256:" + strings.Repeat("d", 64) }},
		{"candidate has a restore backdoor", func(a *CandidateApproval) { rollback[a.Reference] = true }},
		{"untrusted digest", func(a *CandidateApproval) { a.ManifestDigest = "../etc/shadow" }},
		{"untrusted node", func(a *CandidateApproval) { a.NodeID = "" }},
		{"untrusted epoch", func(a *CandidateApproval) { a.Epoch = "" }},
		{"missing sequence", func(a *CandidateApproval) { a.StructuralSequence = 0 }},
		{"late deadline", func(a *CandidateApproval) { a.ExpiresUnixNano = time.Now().Add(time.Hour).UnixNano() }},
		{"expired deadline", func(a *CandidateApproval) { a.ExpiresUnixNano = time.Now().Add(-time.Minute).UnixNano() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := good
			ownMap := map[string]bool{knownGeneration: true}
			if tc.name == "candidate has a restore backdoor" {
				ownMap[a.Reference] = true
			} else {
				tc.change(&a)
			}
			if err := a.Validate(ownMap, time.Now()); err == nil {
				t.Fatal("unauthorized or ambiguous root activation ticket accepted")
			}
		})
	}
}
