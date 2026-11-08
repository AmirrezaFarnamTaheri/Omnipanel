package supervisoripc

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCandidateClientUsesOnlyExactHashAndNeverAcceptsHealthFromApply(t *testing.T) {
	ref := "sha256:" + strings.Repeat("c", 64)
	path, requests := serveLocalSupervisor(t, func(req testRequest) string {
		return `{"version":1,"operation":"` + req.Operation + `","reference":"` + req.Reference + `","ok":true,"healthy":false}`
	})
	client, err := newClient(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ApplyApprovedCandidate(context.Background(), ref); err != nil {
		t.Fatalf("the exact root ticket reference was refused by IPC: %v", err)
	}
	request := <-requests
	if request.Operation != "apply-approved-candidate" || request.Reference != ref || request.Version != 1 {
		t.Fatalf("privileged request carried a foreign operation or mismatched reference: %+v", request)
	}
	for _, invalid := range []string{"", "../etc/shadow", "sha256:not-a-digest"} {
		if err := client.ApplyApprovedCandidate(context.Background(), invalid); err == nil {
			t.Fatalf("unsafe candidate reference accepted: %q", invalid)
		}
	}
	select {
	case other := <-requests:
		t.Fatalf("unsafe digest reached root socket: %+v", other)
	default:
	}
}

func TestCandidateClientRefusesRootResponseClaimingHealthDuringApply(t *testing.T) {
	ref := "sha256:" + strings.Repeat("c", 64)
	path, _ := serveLocalSupervisor(t, func(req testRequest) string {
		return `{"version":1,"operation":"` + req.Operation + `","reference":"` + req.Reference + `","ok":true,"healthy":true}`
	})
	c, err := newClient(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyApprovedCandidate(context.Background(), ref); err == nil {
		t.Fatal("a bare systemd restart response is not candidate health or applied ACK")
	}
}
