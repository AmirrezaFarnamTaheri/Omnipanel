package healthattestation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/supervisoripc"
)

type guardedJournalStub struct {
	expected state.CandidateBinding
	allowed  bool
	calls    int
	denyAfter int
}

func (j *guardedJournalStub) RequirePendingCandidate(_ context.Context, candidate state.CandidateBinding) error {
	j.calls++
	if !j.allowed || candidate != j.expected || (j.denyAfter > 0 && j.calls >= j.denyAfter) {
		return errors.New("private recovery lease missing")
	}
	return nil
}

type guardedHostStub struct {
	observation supervisoripc.CandidateObservation
	err         error
	calls       int
}

func (h *guardedHostStub) ObserveApprovedCandidate(_ context.Context, _ string) (supervisoripc.CandidateObservation, error) {
	h.calls++
	return h.observation, h.err
}

func guardedFixture(t *testing.T) (*GuardedVerifier, *guardedJournalStub, *guardedHostStub, *DurableVerifier, Config, *time.Time) {
	t.Helper()
	v, cfg, _, now := fixtureDurable(t)
	ticket := supervisoripc.CandidateIdentity{
		Reference: cfg.Scope.Generation,
		RollbackRef: "sha256:" + strings.Repeat("b", 64),
		ManifestDigest: cfg.Scope.ManifestDigest,
		NodeID: cfg.Scope.NodeID,
		Epoch: cfg.Scope.Epoch,
		StructuralSequence: cfg.Scope.StructuralSequence,
		MembershipSequence: cfg.Scope.MembershipSequence,
		ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	}
	journal := &guardedJournalStub{allowed: true, expected: state.CandidateBinding{
		NodeID: ticket.NodeID, Epoch: ticket.Epoch,
		StructuralSequence: ticket.StructuralSequence,
		MembershipSequence: ticket.MembershipSequence,
		ManifestDigest: ticket.ManifestDigest,
		CandidateDigest: strings.TrimPrefix(ticket.Reference, "sha256:"),
		RollbackRef: ticket.RollbackRef,
	}}
	host := &guardedHostStub{observation: supervisoripc.CandidateObservation{Healthy: true, Approval: ticket}}
	g, err := newGuardedVerifier(v, journal, host)
	if err != nil {
		t.Fatal(err)
	}
	return g, journal, host, v, cfg, now
}

func guardedReport(challenge Challenge, now time.Time) Evidence {
	return Evidence{
		Challenge: challenge,
		RunID: "01234567-89ab-4cde-8fab-123456789abc",
		ObservedAtMillis: now.UnixMilli(),
		Observations: Observations{
			RealityVisionOK: true,
			BytesSent: 4096,
			BytesReceived: 8192,
			ProtectedIPv4Denied: true,
			ProtectedIPv6Denied: true,
			MetadataDenied: true,
			DNSRebindingDenied: true,
			TranscriptDigest: "sha256:" + strings.Repeat("e", 64),
		},
	}
}

func TestGuardedWitnessRequiresActiveRootTicketAndVerifiedWALBeforeIssuingNonce(t *testing.T) {
	cases := []struct {
		name string
		mutate func(*guardedJournalStub, *guardedHostStub)
	}{
		{"no verified rollback lease", func(j *guardedJournalStub, _ *guardedHostStub) { j.allowed = false }},
		{"candidate not locally healthy", func(_ *guardedJournalStub, h *guardedHostStub) { h.observation.Healthy = false }},
		{"root observer unavailable", func(_ *guardedJournalStub, h *guardedHostStub) { h.err = errors.New("private root failure") }},
		{"root candidate differs", func(_ *guardedJournalStub, h *guardedHostStub) { h.observation.Approval.Reference = "sha256:" + strings.Repeat("f", 64) }},
		{"signed manifest differs", func(_ *guardedJournalStub, h *guardedHostStub) { h.observation.Approval.ManifestDigest = strings.Repeat("f", 64) }},
		{"root epoch differs", func(_ *guardedJournalStub, h *guardedHostStub) { h.observation.Approval.Epoch = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc" }},
		{"root sequence differs", func(_ *guardedJournalStub, h *guardedHostStub) { h.observation.Approval.StructuralSequence++ }},
		{"root rollback differs", func(_ *guardedJournalStub, h *guardedHostStub) { h.observation.Approval.RollbackRef = "sha256:" + strings.Repeat("f", 64) }},
		{"root ticket expired", func(_ *guardedJournalStub, h *guardedHostStub) { h.observation.Approval.ExpiresUnix = time.Now().Add(-time.Minute).Unix() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, j, h, v, _, _ := guardedFixture(t)
			tc.mutate(j, h)
			if _, err := g.Issue(context.Background()); err == nil {
				t.Fatal("root or rollback guard mismatch authorized a witness nonce")
			}
			var issued int
			if err := v.db.QueryRow("SELECT COUNT(*) FROM witness_challenges").Scan(&issued); err != nil || issued != 0 {
				t.Fatalf("rejected root or journal scope issued a nonce: count=%d err=%v", issued, err)
			}
		})
	}
}

func TestGuardedWitnessRejectsHealthOrLeaseLossBetweenIssueAndVerify(t *testing.T) {
	g, journal, host, v, _, now := guardedFixture(t)
	challenge, err := g.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key := v.cfg.WitnessKey
	_ = key
	// Construct a separately signed valid report with the fixture key.
	_, _, signer, _ := fixtureDurable(t)
	valid := signReport(t, guardedReport(challenge, *now), signer)
	host.observation.Healthy = false
	if _, err := g.Verify(context.Background(), valid); err == nil {
		t.Fatal("candidate host became unhealthy before witness verification")
	}
	host.observation.Healthy = true
	journal.allowed = false
	if _, err := g.Verify(context.Background(), valid); err == nil {
		t.Fatal("watchdog rollback lease vanished before witness verification")
	}
	journal.allowed = true
	if _, err := g.Verify(context.Background(), valid); err != nil {
		t.Fatalf("independently authenticated report lost an intact guard: %v", err)
	}
	if _, err := g.Verify(context.Background(), valid); err == nil {
		t.Fatal("witness report was replayed against the same root approval")
	}
}

func TestGuardedWitnessConsumesNonceIfRootOrGuardDropsAtFinalCheck(t *testing.T) {
	g, journal, _, v, _, now := guardedFixture(t)
	challenge, err := g.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _, signer, _ := fixtureDurable(t)
	valid := signReport(t, guardedReport(challenge, *now), signer)
	// Issue checks the root+guard before and after persisting the challenge.
	// Verify checks once before and once after consuming the report.
	journal.denyAfter = 4
	if _, err := g.Verify(context.Background(), valid); err == nil {
		t.Fatal("post-verification lease removal incorrectly yielded accepted evidence")
	}
	journal.denyAfter = 0
	if _, err := g.Verify(context.Background(), valid); err == nil {
		t.Fatal("a failed final guard check must not make an already consumed nonce reusable")
	}
}

func TestGuardedWitnessConstructorDoesNotSilentlyDowngradeToRawVerifier(t *testing.T) {
	v, _, _, _ := fixtureDurable(t)
	if _, err := newGuardedVerifier(v, nil, nil); err == nil {
		t.Fatal("missing root supervisor and WAL guard accepted")
	}
}
