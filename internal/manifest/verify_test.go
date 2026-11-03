package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	nodeID      = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	epochID     = "ea2429da-7540-4e40-ae70-38fd3f19794b"
	otherNodeID = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc"
)

var fixedTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T) (Manifest, Verifier, ed25519.PrivateKey) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	digest := strings.Repeat("a", 64)
	m := Manifest{
		SchemaVersion: "2.0", ControlPlaneEpoch: epochID, NodeID: nodeID,
		StructuralSequence: 2, MembershipSequence: 3,
		IssuedAt:             fixedTime.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:            fixedTime.Add(time.Minute).Format(time.RFC3339),
		RequiredCapabilities: []string{"singbox-reality-vision"},
		Components: []Component{{
			ID: "reality", Driver: "singbox", RuntimeVersion: "1.12.0",
			ArtifactDigest: digest, ConfigurationDigest: strings.Repeat("b", 64),
			ConfigurationRef: "reality-config", DependsOn: []string{},
			Listeners:  []Listener{{Address: "0.0.0.0", Port: 443, Transport: "tcp", IPv6Only: false}},
			Disruption: "listener_restart",
		}},
		BaseEgressPolicy: "deny-protected-v1",
	}
	verifier := Verifier{
		NodeID: nodeID, AuthorizedEpoch: epochID,
		TrustedSigners:      map[string]ed25519.PublicKey{"lab-signer": private.Public().(ed25519.PublicKey)},
		AllowedCapabilities: map[string]bool{"singbox-reality-vision": true},
		QualifiedBuilds:     map[string]Build{"singbox": {Driver: "singbox", Version: "1.12.0", ArtifactDigest: digest, Capabilities: []string{"singbox-reality-vision"}}},
		Current:             Cursor{StructuralSequence: 1, MembershipSequence: 2},
		Now:                 func() time.Time { return fixedTime },
		MaxClockSkew:        time.Second * 5,
	}
	return m, verifier, private
}

func signed(t *testing.T, m Manifest, private ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalize(decoded)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(canonical)
	signature := ed25519.Sign(private, append([]byte(signatureDomain), canonical...))
	envelope := Envelope{
		SignatureVersion: "ed25519-jcs-v1", SignerID: "lab-signer",
		ContentDigest: hex.EncodeToString(hash[:]),
		Signature:     base64.RawURLEncoding.EncodeToString(signature), Manifest: m,
	}
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestVerifySignedDesiredState(t *testing.T) {
	m, verifier, key := fixture(t)
	result, err := verifier.Verify(signed(t, m, key))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != ApplyRevision || result.Manifest.StructuralSequence != 2 || len(result.Digest) != 64 {
		t.Fatalf("unexpected verified revision: %+v", result)
	}
	verifier.Current = Cursor{StructuralSequence: 2, MembershipSequence: 3, Digest: result.Digest}
	same, err := verifier.Verify(signed(t, m, key))
	if err != nil || same.Decision != AlreadyApplied {
		t.Fatalf("idempotent replay: %+v, %v", same, err)
	}
}

func TestTamperingAndTrustFailures(t *testing.T) {
	m, verifier, key := fixture(t)
	wire := signed(t, m, key)
	t.Run("changed manifest without resign", func(t *testing.T) {
		changed := bytes.Replace(wire, []byte(`"structuralSequence":2`), []byte(`"structuralSequence":4`), 1)
		if _, err := verifier.Verify(changed); err == nil {
			t.Fatal("tampered manifest accepted")
		})
	for _, tc := range []struct {
		name   string
		mutate func(*Verifier, *Manifest)
	}{
		{"unknown signer", func(v *Verifier, _ *Manifest) { v.TrustedSigners = nil }},
		{"different node", func(v *Verifier, _ *Manifest) { v.NodeID = otherNodeID }},
		{"unapproved epoch", func(v *Verifier, _ *Manifest) { v.AuthorizedEpoch = otherNodeID }},
		{"no qualifying build", func(v *Verifier, _ *Manifest) { v.QualifiedBuilds = nil }},
		{"incorrect build digest", func(v *Verifier, _ *Manifest) {
			v.QualifiedBuilds["singbox"] = Build{Driver: "singbox", Version: "1.12.0", ArtifactDigest: strings.Repeat("c", 64)}
		}},
		{"unknown capability", func(v *Verifier, _ *Manifest) { v.AllowedCapabilities = nil }},
		{"expired", func(v *Verifier, _ *Manifest) { v.Now = func() time.Time { return fixedTime.Add(5 * time.Minute) } }},
		{"future issued", func(v *Verifier, _ *Manifest) { v.Now = func() time.Time { return fixedTime.Add(-5 * time.Minute) } }},
		{"negative skew", func(v *Verifier, _ *Manifest) { v.MaxClockSkew = -time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := verifier
			tc.mutate(&candidate, &m)
			if _, err := candidate.Verify(wire); err == nil {
				t.Fatal("unauthorized manifest accepted")
			}
		})
	}
}

func TestQualifiedBuildMustDeclareRequestedCapability(t *testing.T) {
	m, verifier, private := fixture(t)
	qualified := verifier.QualifiedBuilds["singbox"]
	qualified.Capabilities = []string{"singbox-hysteria2"}
	verifier.QualifiedBuilds["singbox"] = qualified
	if _, err := verifier.Verify(signed(t, m, private)); err == nil {
		t.Fatal("requested protocol capability not provided by qualified build")
	}
}

func TestRevisionAndMembershipReplay(t *testing.T) {
	m, verifier, key := fixture(t)
	for _, tc := range []struct {
		name       string
		cursor     Cursor
		sequence   uint64
		membership uint64
	}{
		{"lower structural", Cursor{StructuralSequence: 3}, 2, 3},
		{"same structural different digest", Cursor{StructuralSequence: 2, Digest: strings.Repeat("c", 64)}, 2, 3},
		{"lower membership", Cursor{StructuralSequence: 1, MembershipSequence: 4}, 2, 3},
		{"missing digest for already applied", Cursor{StructuralSequence: 2, MembershipSequence: 3}, 2, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier.Current = tc.cursor
			m.StructuralSequence = tc.sequence
			m.MembershipSequence = tc.membership
			if _, err := verifier.Verify(signed(t, m, key)); err == nil {
				t.Fatal("rollback/replay accepted")
			}
		})
	}
}

func TestRejectMalformedAndNonSchemaDocuments(t *testing.T) {
	m, verifier, key := fixture(t)
	valid := signed(t, m, key)
	tests := []struct {
		name    string
		payload []byte
	}{
		{"trailing bytes", append(append([]byte{}, valid...), []byte(" true")...)},
		{"duplicate manifest key", bytes.Replace(valid, []byte(`"schemaVersion":"2.0"`), []byte(`"schemaVersion":"2.0","schemaVersion":"2.0"`), 1)},
		{"unknown nested field", bytes.Replace(valid, []byte(`"id":"reality"`), []byte(`"id":"reality","exec":"rm -rf /"`), 1)},
		{"null components", bytes.Replace(valid, []byte(`"components":[`), []byte(`"components":null,"unused":[`), 1)},
		{"null required string", bytes.Replace(valid, []byte(`"baseEgressPolicy":"deny-protected-v1"`), []byte(`"baseEgressPolicy":null`), 1)},
		{"missing epoch", bytes.Replace(valid, []byte(`"controlPlaneEpoch":"`+epochID+`",`), nil, 1)},
		{"signed arbitrary path", bytes.Replace(valid, []byte(`"configurationRef":"reality-config"`), []byte(`"configurationRef":"/etc/shadow"`), 1)},
		{"invalid UTF-8", append(append([]byte{}, valid...), 0xff)},
		{"unpaired surrogate", bytes.Replace(valid, []byte(`"reality"`), []byte(`"\ud800"`), 1)},
		{"too large", bytes.Repeat([]byte("x"), maxEnvelopeBytes+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifier.Verify(tc.payload); err == nil {
				t.Fatal("malformed or unsupported input accepted")
			}
		})
	}
}

func TestStructuralPreflight(t *testing.T) {
	m, verifier, key := fixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"self dependency", func(m *Manifest) { m.Components[0].DependsOn = []string{"reality"} }},
		{"unknown dependency", func(m *Manifest) { m.Components[0].DependsOn = []string{"missing"} }},
		{"duplicate capability", func(m *Manifest) {
			m.RequiredCapabilities = []string{"singbox-reality-vision", "singbox-reality-vision"}
		}},
		{"duplicate component id", func(m *Manifest) { m.Components = append(m.Components, m.Components[0]) }},
		{"wildcard conflict", func(m *Manifest) {
			m.Components[0].Listeners = append(m.Components[0].Listeners, Listener{Address: "203.0.113.1", Port: 443, Transport: "tcp"})
		}},
		{"dualstack conflict", func(m *Manifest) {
			m.Components[0].Listeners = append(m.Components[0].Listeners, Listener{Address: "::", Port: 443, Transport: "tcp"})
		}},
		{"mapped IPv4 conflict", func(m *Manifest) {
			m.Components[0].Listeners = []Listener{{Address: "::ffff:203.0.113.1", Port: 443, Transport: "tcp"}, {Address: "203.0.113.1", Port: 443, Transport: "tcp"}}
		}},
		{"v4-only flag", func(m *Manifest) { m.Components[0].Listeners[0].IPv6Only = true }},
		{"invalid scoped IPv6", func(m *Manifest) { m.Components[0].Listeners[0].Address = "fe80::1%eth0" }},
		{"unexpected driver", func(m *Manifest) { m.Components[0].Driver = "bash" }},
		{"wrong runtime version", func(m *Manifest) { m.Components[0].RuntimeVersion = "latest" }},
		{"unknown disruption", func(m *Manifest) { m.Components[0].Disruption = "execute" }},
		{"zero structural revision", func(m *Manifest) { m.StructuralSequence = 0 }},
		{"unsafe structural revision", func(m *Manifest) { m.StructuralSequence = maxSafeInteger + 1 }},
		{"invalid timestamp order", func(m *Manifest) { m.ExpiresAt = m.IssuedAt }},
		{"invalid capability id", func(m *Manifest) { m.RequiredCapabilities = []string{"../../root"} }},
		{"inbound without policy", func(m *Manifest) { m.BaseEgressPolicy = "direct-fail-open" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newM, v, pk := fixture(t)
			tc.mutate(&newM)
			if _, err := v.Verify(signed(t, newM, pk)); err == nil {
				t.Fatal("invalid topology accepted")
			}
		})
	}
	t.Run("UDP and TCP same port are independent", func(t *testing.T) {
		m.Components[0].Listeners = append(m.Components[0].Listeners, Listener{Address: "0.0.0.0", Port: 443, Transport: "udp"})
		if _, err := verifier.Verify(signed(t, m, key)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("IPv6-only wildcard independent of IPv4", func(t *testing.T) {
		m.Components[0].Listeners = []Listener{{Address: "::", Port: 443, Transport: "tcp", IPv6Only: true}, {Address: "0.0.0.0", Port: 443, Transport: "tcp"}}
		if _, err := verifier.Verify(signed(t, m, key)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCanonicalizationMatchesJCSSubset(t *testing.T) {
	input := []byte(`{"\uE000":2,"\ud800\udc00":3,"a":1,"escaping":"<>&\u2028","exponent":1e1}`)
	value, err := decodeUnique(input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := canonicalize(value)
	if err != nil {
		t.Fatal(err)
	}
	expected := "{\"a\":1,\"escaping\":\"<>&\u2028\",\"exponent\":10,\"\U00010000\":3,\"\ue000\":2}"
	if string(result) != expected {
		t.Fatalf("JCS canonicalization differed\nwant: %q\n got: %q", expected, result)
	}
}
