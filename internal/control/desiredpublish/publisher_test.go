package desiredpublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
	_ "github.com/mattn/go-sqlite3"
)

const (
	fixtureNode   = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	fixtureEpoch  = "ea2429da-7540-4e40-ae70-38fd3f19794b"
	fixtureDomain = "omnipanel:desired-state:ed25519-jcs-v1\n"
)

func fixtureSignedPublication(t *testing.T, seq, membership uint64) ([]byte, manifest.Verifier) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x54}, ed25519.SeedSize))
	digest := strings.Repeat("a", 64)
	m := manifest.Manifest{
		SchemaVersion: "2.0", NodeID: fixtureNode, ControlPlaneEpoch: fixtureEpoch,
		StructuralSequence: seq, MembershipSequence: membership,
		IssuedAt:             now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:            now.Add(10 * time.Minute).Format(time.RFC3339),
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
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var untyped any
	if err := json.Unmarshal(b, &untyped); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(untyped)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(canonical)
	sig := ed25519.Sign(key, append([]byte(fixtureDomain), canonical...))
	wire, err := json.Marshal(manifest.Envelope{
		SignatureVersion: "ed25519-jcs-v1", SignerID: "publisher-fixture",
		ContentDigest: hex.EncodeToString(hash[:]),
		Signature:     base64.RawURLEncoding.EncodeToString(sig), Manifest: m,
	})
	if err != nil {
		t.Fatal(err)
	}
	v := manifest.Verifier{
		AuthorizedEpoch:     fixtureEpoch,
		TrustedSigners:      map[string]ed25519.PublicKey{"publisher-fixture": key.Public().(ed25519.PublicKey)},
		AllowedCapabilities: map[string]bool{"singbox-reality-vision": true},
		QualifiedBuilds: map[string]manifest.Build{"singbox": {
			Driver: "singbox", Version: "1.14.4+omni.2", ArtifactDigest: digest,
			Capabilities: []string{"singbox-reality-vision"},
		}},
		MaxClockSkew: time.Second,
	}
	return wire, v
}

func TestPublisherRejectsMissingProtectedTrustAndPreapprovals(t *testing.T) {
	wire, v := fixtureSignedPublication(t, 1, 1)
	if _, err := New(nil, v); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("nil PostgreSQL pool was accepted: %v", err)
	}
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, mutate := range []func(*manifest.Verifier){
		func(v *manifest.Verifier) { v.AuthorizedEpoch = "" },
		func(v *manifest.Verifier) { v.TrustedSigners = nil },
		func(v *manifest.Verifier) { v.AllowedCapabilities = nil },
		func(v *manifest.Verifier) { v.QualifiedBuilds = nil },
		func(v *manifest.Verifier) { v.MaxClockSkew = -time.Second },
	} {
		testConfig := v
		mutate(&testConfig)
		if _, err := New(db, testConfig); !errors.Is(err, ErrConfiguration) {
			t.Errorf("untrusted publisher configuration accepted: %v", err)
		}
	}
	p, err := New(db, v)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, approvalID, node string
		wire                   []byte
	}{
		{"invalid UUID", "unapproved", fixtureNode, wire},
		{"invalid node", "7a514a8c-422a-4d0a-bc41-ea144c52911e", "not-a-node", wire},
		{"missing envelope", "7a514a8c-422a-4d0a-bc41-ea144c52911e", fixtureNode, nil},
		{"tampered envelope", "7a514a8c-422a-4d0a-bc41-ea144c52911e", fixtureNode, bytes.Replace(wire, []byte("reality"), []byte("evilxyz"), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.PublishSigned(context.Background(), tc.approvalID, tc.node, tc.wire); !errors.Is(err, ErrUnauthorizedPublication) {
				t.Fatalf("invalid publication escaped: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.PublishSigned(ctx, "7a514a8c-422a-4d0a-bc41-ea144c52911e", fixtureNode, wire); !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation ignored: %v", err)
	}
}

func TestPublisherRequiresSignatureForExactNodeAndEpoch(t *testing.T) {
	wire, v := fixtureSignedPublication(t, 1, 0)
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := New(db, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.PublishSigned(context.Background(), "7a514a8c-422a-4d0a-bc41-ea144c52911e",
		"a2f5a88e-3cc3-4a4c-81f6-45719fb131bc", wire); !errors.Is(err, ErrUnauthorizedPublication) {
		t.Fatalf("cross-node signed publication accepted: %v", err)
	}
	v.AuthorizedEpoch = "32486a70-22d9-4ec4-97bd-21881762f6d0"
	oldEpochPublisher, err := New(db, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldEpochPublisher.PublishSigned(context.Background(),
		"7a514a8c-422a-4d0a-bc41-ea144c52911e", fixtureNode, wire); !errors.Is(err, ErrUnauthorizedPublication) {
		t.Fatalf("old signed epoch accepted after trusted epoch rotation: %v", err)
	}
}
