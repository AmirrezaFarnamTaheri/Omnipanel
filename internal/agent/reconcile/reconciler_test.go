package reconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

const (
	fixtureNode   = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	fixtureEpoch  = "ea2429da-7540-4e40-ae70-38fd3f19794b"
	fixtureDomain = "omnipanel:desired-state:ed25519-jcs-v1\n"
)

type fixturePuller struct {
	payload []byte
	node    string
	calls   int
	err     error
}

func (f *fixturePuller) FetchNodeDesired(_ context.Context, node string) ([]byte, error) {
	f.calls++
	f.node = node
	return f.payload, f.err
}

func signerFixture(t *testing.T) (manifest.Manifest, manifest.Verifier, ed25519.PrivateKey) {
	t.Helper()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	digest := strings.Repeat("a", 64)
	m := manifest.Manifest{
		SchemaVersion: "2.0", ControlPlaneEpoch: fixtureEpoch, NodeID: fixtureNode,
		StructuralSequence: 2, MembershipSequence: 3,
		IssuedAt:             now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:            now.Add(time.Minute).Format(time.RFC3339),
		RequiredCapabilities: []string{"singbox-reality-vision"},
		Components: []manifest.Component{{
			ID: "reality", Driver: "singbox", RuntimeVersion: "1.14.4+omni.2",
			ArtifactDigest: digest, ConfigurationDigest: strings.Repeat("b", 64),
			ConfigurationRef: "reality-config", DependsOn: []string{},
			Listeners:  []manifest.Listener{{Address: "0.0.0.0", Port: 443, Transport: "tcp"}},
			Disruption: "listener_restart",
		}},
		BaseEgressPolicy: "deny-protected-v1",
	}
	v := manifest.Verifier{
		NodeID: fixtureNode, AuthorizedEpoch: fixtureEpoch,
		TrustedSigners:      map[string]ed25519.PublicKey{"local-test": key.Public().(ed25519.PublicKey)},
		AllowedCapabilities: map[string]bool{"singbox-reality-vision": true},
		QualifiedBuilds: map[string]manifest.Build{"singbox": {
			Driver: "singbox", Version: "1.14.4+omni.2", ArtifactDigest: digest,
			Capabilities: []string{"singbox-reality-vision"},
		}},
		Now: func() time.Time { return now }, MaxClockSkew: 5 * time.Second,
	}
	return m, v, key
}

// The fixture uses only ASCII and safe JSON integers. Go map-key ordering
// matches the canonical JSON subset required by the signed manifest verifier.
func signFixture(t *testing.T, m manifest.Manifest, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var obj any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(key, append([]byte(fixtureDomain), canonical...))
	wire, err := json.Marshal(manifest.Envelope{
		SignatureVersion: "ed25519-jcs-v1",
		SignerID:         "local-test", ContentDigest: hex.EncodeToString(digest[:]),
		Signature: base64.RawURLEncoding.EncodeToString(sig), Manifest: m,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func openTestJournal(t *testing.T) (string, *state.Store) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "node.sqlite")
	store, err := state.Open(path, fixtureNode, fixtureEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return path, store
}

func TestAgentInitiatedSignedPullJournalsVerifiedIntentAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path, store := openTestJournal(t)
	m, verifier, key := signerFixture(t)
	wire := signFixture(t, m, key)
	if _, err := verifier.Verify(wire); err != nil {
		t.Fatalf("test envelope must be a valid signature: %v", err)
	}
	p, err := New(store, verifier)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &fixturePuller{payload: wire}
	report, err := p.PollOnce(ctx, gateway)
	if err != nil {
		t.Fatal(err)
	}
	if gateway.calls != 1 || gateway.node != fixtureNode {
		t.Fatalf("processor must request its own node-scoped intent once: %+v", gateway)
	}
	if report.Outcome != PendingApplication || !report.NewlyRecorded ||
		report.StructuralSequence != 2 || report.MembershipSequence != 3 {
		t.Fatalf("verified intent cannot be mistaken for deployment: %+v", report)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(path, fixtureNode, fixtureEpoch)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := New(reopened, verifier)
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := restarted.Process(ctx, wire)
	if err != nil || repeat.NewlyRecorded || repeat.Outcome != PendingApplication {
		t.Fatalf("restart/replay must be idempotent, never applied: %+v, %v", repeat, err)
	}
	pending, err := reopened.Pending(ctx)
	if err != nil || len(pending) != 1 || pending[0].Stage != state.Verified {
		t.Fatalf("journal must survive restart in VERIFIED stage: %+v, %v", pending, err)
	}
	cursor, err := reopened.Cursor(ctx)
	if err != nil || cursor.StructuralSequence != 0 || cursor.Digest != "" {
		t.Fatalf("verified intent must not advance an applied cursor: %+v, %v", cursor, err)
	}
}

func TestTamperedAndLowerRevisionsDoNotMutateVerifiedState(t *testing.T) {
	ctx := context.Background()
	_, store := openTestJournal(t)
	defer store.Close()
	m, verifier, key := signerFixture(t)
	p, err := New(store, verifier)
	if err != nil {
		t.Fatal(err)
	}
	valid := signFixture(t, m, key)
	if _, err := p.Process(ctx, valid); err != nil {
		t.Fatal(err)
	}
	lower := m
	lower.StructuralSequence = 1
	other := m
	other.NodeID = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc"
	invalid := []struct {
		name string
		wire []byte
	}{
		{"tampered signed payload", bytes.Replace(valid, []byte("\"structuralSequence\":2"), []byte("\"structuralSequence\":4"), 1)},
		{"older revision", signFixture(t, lower, key)},
		{"other node", signFixture(t, other, key)},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.Process(ctx, tc.wire); err == nil {
				t.Fatal("untrusted or lower signed intent must not be stored")
			}
		})
	}
	pending, err := store.Pending(ctx)
	if err != nil || len(pending) != 1 || pending[0].StructuralSequence != 2 {
		t.Fatalf("bad intent must not change durable state: %+v %v", pending, err)
	}
}

func TestGatewayFailureDoesNotAdvanceJournal(t *testing.T) {
	ctx := context.Background()
	_, store := openTestJournal(t)
	defer store.Close()
	_, verifier, _ := signerFixture(t)
	p, err := New(store, verifier)
	if err != nil {
		t.Fatal(err)
	}
	puller := &fixturePuller{err: errors.New("offline")}
	if _, err := p.PollOnce(ctx, puller); err == nil {
		t.Fatal("failed authenticated pull must not be a success")
	}
	pending, err := store.Pending(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("failed pull must leave the journal unchanged: %+v, %v", pending, err)
	}
}
