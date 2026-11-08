package supervisorserver

import (
	"context"
	"os"
	"strings"
	"testing"
	"sync"
)

type candidateBackendStub struct {
	*stubBackend
	mu      sync.Mutex
	applied []string
}

func (b *candidateBackendStub) ApplyApprovedCandidate(_ context.Context, ref string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applied = append(b.applied, ref)
	return nil
}

func (b *candidateBackendStub) appliedRecords() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.applied...)
}

func TestSupervisorCandidateRPCRequiresSeparateRootTicketAndNeverReportsHealthy(t *testing.T) {
	stub := &candidateBackendStub{stubBackend: &stubBackend{healthy: true}}
	cfg, _ := serverTestConfig(t, stub.stubBackend)
	approved := "sha256:" + strings.Repeat("c", 64)
	ticket := candidateApprovalForTest(approved, knownGeneration)
	cfg.CandidateApproval = &ticket
	srv, err := newServer(cfg, stub, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	socket := startTestServer(t, cfg, srv)
	reply, err := rpcJSON(t, socket, "apply-approved-candidate", approved)
	if err != nil || !reply.OK || reply.Healthy || reply.Operation != "apply-approved-candidate" || reply.Reference != approved {
		t.Fatalf("candidate RPC must acknowledge only fixed root invocation, never health: %+v %v", reply, err)
	}
	firstApplied := stub.appliedRecords()
	if len(firstApplied) != 1 || firstApplied[0] != approved {
		t.Fatal("candidate backend not given exact root approved digest")
	}
	for _, data := range []string{
		`{"version":1,"operation":"restore-known-good","reference":"` + approved + `"}` + "\n",
		`{"version":1,"operation":"observe-known-good","reference":"` + approved + `"}` + "\n",
		`{"version":1,"operation":"apply-approved-candidate","reference":"` + unknownGeneration + `"}` + "\n",
		`{"version":1,"operation":"apply-approved-candidate","reference":"` + approved + `","path":"/etc/shadow"}` + "\n",
		`{"version":1,"operation":"apply-approved-candidate","reference":"` + approved + `","reference":"` + approved + `"}` + "\n",
	} {
		raw, _ := rpcRaw(t, socket, data)
		if len(raw) != 0 {
			t.Fatalf("untrusted candidate operation received a root response: %q", raw)
		}
	}
	lastApplied := stub.appliedRecords()
	if len(lastApplied) != 1 {
		t.Fatalf("unapproved candidate bypassed root: %+v", lastApplied)
	}
	if a, b := stub.counts(); a != 0 || b != 0 {
		t.Fatal("candidate RPC must not invoke LKG restore or health on behalf of caller")
	}
}

func TestSupervisorRejectsCandidateApprovalWithoutIndependentRootBackendOrSafePolicy(t *testing.T) {
	backend := &stubBackend{}
	cfg, _ := serverTestConfig(t, backend)
	ref := "sha256:" + strings.Repeat("c", 64)
	ticket := candidateApprovalForTest(ref, knownGeneration)
	cfg.CandidateApproval = &ticket
	if _, err := newServer(cfg, backend, uint32(os.Geteuid())); err == nil {
		t.Fatal("an arbitrary rollback backend cannot silently inherit candidate-activation privilege")
	}
	supported := &candidateBackendStub{stubBackend: backend}
	cfg.AllowedGenerations[ref] = true
	if _, err := newServer(cfg, supported, uint32(os.Geteuid())); err == nil {
		t.Fatal("candidate cannot also be allowlisted under recovery/observe verbs")
	}
	delete(cfg.AllowedGenerations, ref)
	ticket.ManifestDigest = "invalid"
	if _, err := newServer(cfg, supported, uint32(os.Geteuid())); err == nil {
		t.Fatal("forged/ambiguous root ticket was accepted")
	}
}
