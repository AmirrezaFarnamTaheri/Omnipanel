package healthattestation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureDurable(t *testing.T) (*DurableVerifier, Config, ed25519.PrivateKey, *time.Time) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x39}, ed25519.SeedSize))
	cfg := Config{
		Path: filepath.Join(directory, "witness.sqlite"),
		Scope: Scope{
			NodeID: "62c478bb-47c3-4dc6-a363-a2fbde813810",
			Epoch: "ea2429da-7540-4e40-ae70-38fd3f19794b",
			StructuralSequence: 2,
			MembershipSequence: 3,
			ManifestDigest: strings.Repeat("a", 64),
			Generation: "sha256:" + strings.Repeat("c", 64),
			ProfileDigest: "sha256:" + strings.Repeat("d", 64),
		},
		WitnessID: "external-client-1",
		WitnessKey: key.Public().(ed25519.PublicKey),
		TTL: time.Minute,
		Now: func() time.Time { return now },
	}
	v, err := NewDurableVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, cfg, key, &now
}

func evidenceFor(t *testing.T, v *DurableVerifier, now time.Time) Evidence {
	t.Helper()
	challenge, err := v.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
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

func signReport(t *testing.T, evidence Evidence, key ed25519.PrivateKey) []byte {
	t.Helper()
	message, err := SigningBytes(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDurableExternalWitnessAcceptsOneScopedReportAndNeverClaimsM0(t *testing.T) {
	v, cfg, key, now := fixtureDurable(t)
	e := evidenceFor(t, v, *now)
	wire := signReport(t, e, key)
	accepted, err := v.Verify(context.Background(), wire)
	if err != nil {
		t.Fatalf("authentic nonce-bound reference-client report was rejected: %v", err)
	}
	if accepted.Scope != cfg.Scope || accepted.Nonce != e.Challenge.Nonce ||
		accepted.RunID != e.RunID || accepted.WitnessID != cfg.WitnessID ||
		!strings.HasPrefix(accepted.EvidenceDigest, "sha256:") {
		t.Fatalf("authenticated evidence lost signed generation and witness binding: %+v", accepted)
	}
	if _, err := v.Verify(context.Background(), wire); err == nil {
		t.Fatal("signed evidence was replayed in the same process")
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDurableVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Verify(context.Background(), wire); err == nil {
		t.Fatal("restarted node forgot a consumed challenge")
	}
}

func TestDurableExternalWitnessRejectsSignedWrongScopeAndClaimsWithoutConsumingNonce(t *testing.T) {
	cases := []struct {
		name string
		mutate func(*Evidence)
	}{
		{"wrong node", func(e *Evidence) { e.Challenge.Scope.NodeID = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc" }},
		{"wrong epoch", func(e *Evidence) { e.Challenge.Scope.Epoch = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc" }},
		{"wrong structural", func(e *Evidence) { e.Challenge.Scope.StructuralSequence++ }},
		{"wrong membership", func(e *Evidence) { e.Challenge.Scope.MembershipSequence++ }},
		{"wrong manifest", func(e *Evidence) { e.Challenge.Scope.ManifestDigest = strings.Repeat("f", 64) }},
		{"wrong candidate", func(e *Evidence) { e.Challenge.Scope.Generation = "sha256:" + strings.Repeat("f", 64) }},
		{"wrong profile", func(e *Evidence) { e.Challenge.Scope.ProfileDigest = "sha256:" + strings.Repeat("f", 64) }},
		{"wrong nonce", func(e *Evidence) { e.Challenge.Nonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)) }},
		{"wrong witness", func(e *Evidence) { e.Challenge.WitnessID = "impostor" }},
		{"wrong version", func(e *Evidence) { e.Challenge.Version = "external-health-v2" }},
		{"wrong deadline", func(e *Evidence) { e.Challenge.ExpiresAtMillis++ }},
		{"future observation", func(e *Evidence) { e.ObservedAtMillis += 10000 }},
		{"before issue", func(e *Evidence) { e.ObservedAtMillis-- }},
		{"no real data transfer claim", func(e *Evidence) { e.Observations.BytesReceived = 0 }},
		{"no reality vision claim", func(e *Evidence) { e.Observations.RealityVisionOK = false }},
		{"protected IPv4 permitted", func(e *Evidence) { e.Observations.ProtectedIPv4Denied = false }},
		{"protected IPv6 permitted", func(e *Evidence) { e.Observations.ProtectedIPv6Denied = false }},
		{"metadata permitted", func(e *Evidence) { e.Observations.MetadataDenied = false }},
		{"DNS rebinding permitted", func(e *Evidence) { e.Observations.DNSRebindingDenied = false }},
		{"missing transcript", func(e *Evidence) { e.Observations.TranscriptDigest = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _, key, now := fixtureDurable(t)
			good := evidenceFor(t, v, *now)
			bad := good
			tc.mutate(&bad)
			if _, err := v.Verify(context.Background(), signReport(t, bad, key)); err == nil {
				t.Fatal("signed report with unissued scope or failed suite claims was accepted")
			}
			if _, err := v.Verify(context.Background(), signReport(t, good, key)); err != nil {
				t.Fatalf("invalid prior report improperly consumed the challenge: %v", err)
			}
		})
	}
}

func TestDurableExternalWitnessRejectsNoncanonicalMalformedAndUntrustedSignatures(t *testing.T) {
	v, _, key, now := fixtureDurable(t)
	e := evidenceFor(t, v, *now)
	valid := string(signReport(t, e, key))
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"duplicated top key", []byte(strings.Replace(valid, "\"runId\":", "\"runId\":\"forged\",\"runId\":", 1))},
		{"duplicated nested key", []byte(strings.Replace(valid, "\"nonce\":", "\"nonce\":\"forged\",\"nonce\":", 1))},
		{"unknown field", []byte(strings.Replace(valid, "\"signature\":", "\"extra\":\"bypass\",\"signature\":", 1))},
		{"trailing object", []byte(valid + "{}")},
		{"over bound", bytes.Repeat([]byte(" "), MaxEvidenceBytes+1)},
		{"tampered data", []byte(strings.Replace(valid, "\"bytesReceived\":8192", "\"bytesReceived\":8193", 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), tc.wire); err == nil {
				t.Fatal("ambiguous unsigned or altered report was accepted")
			}
		})
	}
	impostor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	if _, err := v.Verify(context.Background(), signReport(t, e, impostor)); err == nil {
		t.Fatal("unknown witness signing key was accepted")
	}
	if _, err := v.Verify(context.Background(), []byte(valid)); err != nil {
		t.Fatalf("malformed reports consumed the authenticated challenge: %v", err)
	}
}

func TestDurableExternalWitnessAtomicAcrossConcurrentConsumersAndRunIDs(t *testing.T) {
	v, cfg, key, now := fixtureDurable(t)
	e := evidenceFor(t, v, *now)
	wire := signReport(t, e, key)
	second, err := NewDurableVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := v
			if i%2 != 0 {
				target = second
			}
			if _, err := target.Verify(context.Background(), wire); err == nil {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("same challenge accepted in %d concurrent transactions", accepted.Load())
	}
	different := evidenceFor(t, v, *now)
	if _, err := v.Verify(context.Background(), signReport(t, different, key)); err == nil {
		t.Fatal("same external run ID used to consume two distinct challenges")
	}
	different.RunID = "12345678-89ab-4cde-8fab-123456789abc"
	if _, err := v.Verify(context.Background(), signReport(t, different, key)); err != nil {
		t.Fatalf("rejected duplicate run ID consumed the distinct nonce: %v", err)
	}
}

func TestDurableExternalWitnessHonorsExpiryBoundsAndPrivateJournal(t *testing.T) {
	v, cfg, key, now := fixtureDurable(t)
	e := evidenceFor(t, v, *now)
	for i := 0; i < 63; i++ {
		if _, err := v.Issue(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := v.Issue(context.Background()); err == nil {
		t.Fatal("unbounded outstanding witness challenges accepted")
	}
	*now = now.Add(61 * time.Second)
	if _, err := v.Verify(context.Background(), signReport(t, e, key)); err == nil {
		t.Fatal("expired report was accepted")
	}
	if _, err := v.Issue(context.Background()); err != nil {
		t.Fatalf("expired pending challenges never made room for new issuance: %v", err)
	}
	if _, err := v.Issue(nil); err == nil {
		t.Fatal("nil challenge context accepted")
	}
	if _, err := v.Verify(nil, nil); err == nil {
		t.Fatal("nil verify context accepted")
	}
	cfg.Scope.NodeID = ""
	if _, err := NewDurableVerifier(cfg); err == nil {
		t.Fatal("unscoped node verifier constructed")
	}
	cfg.Scope.NodeID = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	cfg.WitnessKey = nil
	if _, err := NewDurableVerifier(cfg); err == nil {
		t.Fatal("unknown remote witness verifier constructed")
	}
}

func TestDurableExternalWitnessRequiresOwnerPrivateFilesAndDistinctEvidenceSigningDomain(t *testing.T) {
	v, cfg, _, now := fixtureDurable(t)
	e := evidenceFor(t, v, *now)
	message, err := SigningBytes(e)
	if err != nil || !bytes.HasPrefix(message, []byte("omnipanel:external-health:ed25519-v2\n")) {
		t.Fatalf("evidence has no separate cryptographic signature domain: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDurableVerifier(cfg); err == nil {
		t.Fatal("world-readable durable witness ledger accepted")
	}
	if err := os.Chmod(cfg.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(cfg.Path), "symlink.sqlite")
	if err := os.Symlink(cfg.Path, link); err != nil {
		t.Fatal(err)
	}
	cfg.Path = link
	if _, err := NewDurableVerifier(cfg); err == nil {
		t.Fatal("symlink durable witness ledger accepted")
	}
}
