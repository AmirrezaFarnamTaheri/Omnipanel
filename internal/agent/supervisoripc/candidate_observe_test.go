package supervisoripc

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func clientTestCandidate() CandidateIdentity {
	return CandidateIdentity{
		Reference:          "sha256:" + strings.Repeat("c", 64),
		RollbackRef:        "sha256:" + strings.Repeat("b", 64),
		ManifestDigest:     strings.Repeat("a", 64),
		NodeID:             "62c478bb-47c3-4dc6-a363-a2fbde813810",
		Epoch:              "ea2429da-7540-4e40-ae70-38fd3f19794b",
		StructuralSequence: 2,
		MembershipSequence: 3,
		ExpiresUnix:        time.Now().Add(time.Minute).Unix(),
	}
}

func TestCandidateHostObservationClientRequiresPinnedRootTicketAndNeverSendsPaths(t *testing.T) {
	ticket := clientTestCandidate()
	path, requests := serveLocalSupervisor(t, func(req testRequest) string {
		data, _ := json.Marshal(map[string]any{
			"version": 1, "operation": req.Operation, "reference": req.Reference,
			"ok": true, "healthy": true, "approval": ticket,
		})
		return string(data)
	})
	client, err := newClient(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := client.ObserveApprovedCandidate(context.Background(), ticket.Reference)
	if err != nil || !observation.Healthy || observation.Approval != ticket {
		t.Fatalf("authentic fixed candidate reply was rejected: %+v %v", observation, err)
	}
	req := <-requests
	if req.Operation != "observe-approved-candidate" || req.Reference != ticket.Reference || req.Version != 1 {
		t.Fatalf("read-only candidate observation sent unexpected privileged payload: %+v", req)
	}
	if _, err := client.ObserveApprovedCandidate(context.Background(), "../etc/shadow"); err == nil {
		t.Fatal("arbitrary path reached root candidate observer")
	}
	select {
	case invalid := <-requests:
		t.Fatalf("invalid candidate request reached root socket: %+v", invalid)
	default:
	}
}

func TestCandidateHostObservationClientRejectsForgedOrUnhealthyRootReplies(t *testing.T) {
	ticket := clientTestCandidate()
	for _, tc := range []struct {
		name   string
		modify func(*CandidateIdentity)
		omit   bool
		falseHealth bool
	}{
		{"wrong candidate", func(a *CandidateIdentity) { a.Reference = a.RollbackRef }, false, false},
		{"bad rollback", func(a *CandidateIdentity) { a.RollbackRef = "../etc/passwd" }, false, false},
		{"wrong node", func(a *CandidateIdentity) { a.NodeID = "not-a-uuid" }, false, false},
		{"missing ticket", func(_ *CandidateIdentity) {}, true, false},
		{"unhealthy", func(_ *CandidateIdentity) {}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := ticket
			tc.modify(&candidate)
			path, _ := serveLocalSupervisor(t, func(req testRequest) string {
				response := map[string]any{
					"version": 1, "operation": req.Operation, "reference": req.Reference,
					"ok": true, "healthy": !tc.falseHealth,
				}
				if !tc.omit {
					response["approval"] = candidate
				}
				data, _ := json.Marshal(response)
				return string(data)
			})
			client, err := newClient(path, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.ObserveApprovedCandidate(context.Background(), ticket.Reference)
			if tc.falseHealth {
				if err != nil || result.Healthy {
					t.Fatalf("unhealthy host result was misinterpreted: %+v %v", result, err)
				}
			} else if err == nil {
				t.Fatal("forged, incomplete or mismatched root approval was accepted")
			}
		})
	}
}
