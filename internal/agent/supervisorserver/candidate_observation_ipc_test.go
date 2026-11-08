package supervisorserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type observedCandidateBackend struct {
	*candidateBackendStub
	healthy bool
	failure error
}

func (b *observedCandidateBackend) ObserveApprovedCandidate(_ context.Context, _ string) (bool, error) {
	return b.healthy, b.failure
}

func TestRootCandidateObservationRPCExposesExactRootTicketOnlyAfterHostObservation(t *testing.T) {
	backend := &observedCandidateBackend{
		candidateBackendStub: &candidateBackendStub{stubBackend: &stubBackend{}},
		healthy: true,
	}
	cfg, _ := serverTestConfig(t, backend.stubBackend)
	ref := "sha256:" + strings.Repeat("c", 64)
	ticket := candidateApprovalForTest(ref, knownGeneration)
	cfg.CandidateApproval = &ticket
	server, err := newServer(cfg, backend, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	socket := startTestServer(t, cfg, server)
	raw, err := rpcRaw(t, socket, `{"version":1,"operation":"observe-approved-candidate","reference":"`+ref+`"}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		OK        bool               `json:"ok"`
		Healthy   bool               `json:"healthy"`
		Operation string             `json:"operation"`
		Reference string             `json:"reference"`
		Approval  *CandidateApproval `json:"approval"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatal(err)
	}
	if !reply.OK || !reply.Healthy || reply.Operation != "observe-approved-candidate" ||
		reply.Reference != ref || reply.Approval == nil || *reply.Approval != ticket {
		t.Fatalf("root candidate observer failed to bind the exact local ticket: %+v", reply)
	}
	backend.healthy = false
	raw, err = rpcRaw(t, socket, `{"version":1,"operation":"observe-approved-candidate","reference":"`+ref+`"}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &reply); err != nil || reply.Healthy {
		t.Fatal("root observer reported unhealthy candidate healthy")
	}
	if strings.Contains(string(raw), "approval") {
		t.Fatal("an unhealthy candidate must not carry root approval evidence")
	}
	backend.failure = errors.New("private runtime config and host details")
	raw, err = rpcRaw(t, socket, `{"version":1,"operation":"observe-approved-candidate","reference":"`+ref+`"}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private runtime") || strings.Contains(string(raw), "approval") {
		t.Fatal("untrusted root diagnostics or approval escaped after a backend failure")
	}
	for _, payload := range []string{
		`{"version":1,"operation":"observe-approved-candidate","reference":"` + knownGeneration + `"}` + "\n",
		`{"version":1,"operation":"observe-approved-candidate","reference":"` + ref + `","path":"/etc/shadow"}` + "\n",
		`{"version":1,"operation":"observe-approved-candidate","reference":"` + ref + `","reference":"` + ref + `"}` + "\n",
	} {
		raw, _ := rpcRaw(t, socket, payload)
		if len(raw) != 0 {
			t.Fatalf("unapproved or malformed root observation reached backend: %q", raw)
		}
	}
}

func TestRootCandidateObservationCannotBeGrantedByRecoveryOnlyBackend(t *testing.T) {
	backend := &candidateBackendStub{stubBackend: &stubBackend{}}
	cfg, _ := serverTestConfig(t, backend.stubBackend)
	ref := "sha256:" + strings.Repeat("c", 64)
	ticket := candidateApprovalForTest(ref, knownGeneration)
	cfg.CandidateApproval = &ticket
	server, err := newServer(cfg, backend, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	socket := startTestServer(t, cfg, server)
	raw, _ := rpcRaw(t, socket, `{"version":1,"operation":"observe-approved-candidate","reference":"`+ref+`"}`+"\n")
	if strings.Contains(string(raw), `"healthy":true`) || strings.Contains(string(raw), "approval") {
		t.Fatal("candidate without a real observer backend was reported healthy")
	}
}
