package supervisorserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootCandidateObservationIsDistinctFromRecoveryAndRequiresConsumedTicket(t *testing.T) {
	fixture, backend, approval := approvedCandidateFixture(t, "", "")
	acceptHealthSOCKS(t, fixture.listener, false)
	if healthy, err := backend.ObserveApprovedCandidate(context.Background(), approval.Reference); err == nil && healthy {
		t.Fatal("candidate was observed before its one-use root authorization was consumed")
	}
	if err := backend.ApplyApprovedCandidate(context.Background(), approval.Reference); err != nil {
		t.Fatal(err)
	}
	if healthy, err := backend.ObserveApprovedCandidate(context.Background(), approval.Reference); err != nil || !healthy {
		t.Fatalf("active exact root-approved candidate was not locally observed: %t %v", healthy, err)
	}
	if healthy, err := backend.ObserveKnownGood(context.Background(), approval.Reference); err == nil || healthy {
		t.Fatal("candidate must not inherit independently observed known-good status")
	}
	if healthy, err := backend.ObserveApprovedCandidate(context.Background(), fixture.ref); err == nil && healthy {
		t.Fatal("former LKG cannot impersonate the approved candidate observation")
	}
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err != nil {
		t.Fatal(err)
	}
	if healthy, err := backend.ObserveApprovedCandidate(context.Background(), approval.Reference); err == nil && healthy {
		t.Fatal("former LKG restoration left the old candidate falsely healthy")
	}
}

func TestRootCandidateObservationRejectsTamperedUsedTicketActiveBytesAndExpiredApproval(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, nativeFixture, *NativeBackend, CandidateApproval)
	}{
		{"used marker deleted", func(t *testing.T, f nativeFixture, _ *NativeBackend, a CandidateApproval) {
			path := filepath.Join(f.cfg.GenerationDirectory, ".activation-"+strings.TrimPrefix(a.Reference, "sha256:")+".used")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
		{"used marker tampered", func(t *testing.T, f nativeFixture, _ *NativeBackend, a CandidateApproval) {
			path := filepath.Join(f.cfg.GenerationDirectory, ".activation-"+strings.TrimPrefix(a.Reference, "sha256:")+".used")
			if err := os.WriteFile(path, []byte("forged"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"candidate changed on disk", func(t *testing.T, f nativeFixture, _ *NativeBackend, a CandidateApproval) {
			path := filepath.Join(f.cfg.GenerationDirectory, strings.TrimPrefix(a.Reference, "sha256:")+".json")
			if err := os.WriteFile(path, []byte(candidateJSON+" "), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"active config tampered", func(t *testing.T, f nativeFixture, _ *NativeBackend, _ CandidateApproval) {
			if err := os.WriteFile(f.active, []byte(safeRollbackJSON), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"ticket expired", func(t *testing.T, _ nativeFixture, b *NativeBackend, _ CandidateApproval) {
			b.approval.ExpiresUnix = time.Now().Add(-time.Second).Unix()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture, backend, approval := approvedCandidateFixture(t, "", "")
			acceptHealthSOCKS(t, fixture.listener, false)
			if err := backend.ApplyApprovedCandidate(context.Background(), approval.Reference); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, fixture, backend, approval)
			if healthy, err := backend.ObserveApprovedCandidate(context.Background(), approval.Reference); err == nil && healthy {
				t.Fatal("tampered or expired root candidate was reported locally healthy")
			}
		})
	}
}
