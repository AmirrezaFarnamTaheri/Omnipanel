package healthattestation

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "strings"
    "sync"
    "sync/atomic"
    "testing"
    "time"
)

func fixture(t *testing.T) (*Verifier, ed25519.PrivateKey, *time.Time) {
    t.Helper()
    clock := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
    key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
    v, err := NewVerifier(Config{
        NodeID: "node-1", Epoch: "epoch-1",
        Generation: "sha256:" + strings.Repeat("a", 64),
        ProfileDigest: "sha256:" + strings.Repeat("b", 64),
        WitnessKeys: map[string]ed25519.PublicKey{"remote-witness-1": key.Public().(ed25519.PublicKey)},
        TTL: 30 * time.Second, Now: func() time.Time { return clock },
    })
    if err != nil { t.Fatal(err) }
    return v, key, &clock
}

func reportFor(t *testing.T, v *Verifier, clock time.Time) Evidence {
    t.Helper()
    challenge, err := v.Issue(context.Background())
    if err != nil { t.Fatal(err) }
    return Evidence{
        Challenge: challenge, WitnessID: "remote-witness-1",
        ObservedAtMillis: clock.UnixMilli(), RealityVisionOK: true,
        ProtectedEgressDenied: true,
    }
}

func signed(t *testing.T, e Evidence, key ed25519.PrivateKey) []byte {
    t.Helper()
    msg, err := SigningBytes(e)
    if err != nil { t.Fatal(err) }
    e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, msg))
    wire, err := json.Marshal(e)
    if err != nil { t.Fatal(err) }
    return wire
}

func TestSignedExternalEvidenceExactScopeAndOneTimeUse(t *testing.T) {
    v, key, now := fixture(t)
    r := reportFor(t, v, *now)
    wire := signed(t, r, key)
    verified, err := v.Verify(context.Background(), wire)
    if err != nil { t.Fatal(err) }
    if verified.NodeID != r.Challenge.NodeID || verified.Generation != r.Challenge.Generation ||
        verified.ProfileDigest != r.Challenge.ProfileDigest || verified.WitnessID != r.WitnessID ||
        verified.ObservedAtMillis != r.ObservedAtMillis {
        t.Fatalf("wrong verified scope: %+v", verified)
    }
    if _, err := v.Verify(context.Background(), wire); err == nil {
        t.Fatal("replay accepted")
    }
}

func TestSignedButIncorrectScopeOrProbeClaimsFailClosed(t *testing.T) {
    cases := []struct{name string; mutate func(*Evidence)}{
        {"node", func(r *Evidence){ r.Challenge.NodeID = "node-2" }},
        {"epoch", func(r *Evidence){ r.Challenge.Epoch = "epoch-2" }},
        {"generation", func(r *Evidence){ r.Challenge.Generation = "sha256:" + strings.Repeat("c",64) }},
        {"probe profile", func(r *Evidence){ r.Challenge.ProfileDigest = "sha256:" + strings.Repeat("c",64) }},
        {"nonce", func(r *Evidence){ r.Challenge.Nonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3},32)) }},
        {"version", func(r *Evidence){ r.Challenge.Version = "unknown" }},
        {"expires", func(r *Evidence){ r.Challenge.ExpiresAtMillis += 60000 }},
        {"issued", func(r *Evidence){ r.Challenge.IssuedAtMillis++ }},
        {"witness identity", func(r *Evidence){ r.WitnessID = "untrusted-witness" }},
        {"no reality vision", func(r *Evidence){ r.RealityVisionOK = false }},
        {"protected route permitted", func(r *Evidence){ r.ProtectedEgressDenied = false }},
        {"observation before challenge", func(r *Evidence){ r.ObservedAtMillis-- }},
        {"observation after challenge expiry", func(r *Evidence){ r.ObservedAtMillis = r.Challenge.ExpiresAtMillis + 1 }},
        {"future observation", func(r *Evidence){ r.ObservedAtMillis += 60000 }},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            v, key, now := fixture(t)
            report := reportFor(t, v, *now)
            tc.mutate(&report)
            if _, err := v.Verify(context.Background(), signed(t, report, key)); err == nil {
                t.Fatal("invalid evidence accepted")
            }
        })
    }
}

func TestInvalidSignatureAndAmbiguousJSONCannotConsumeChallenge(t *testing.T) {
    v, key, now := fixture(t)
    report := reportFor(t, v, *now)
    valid := string(signed(t, report, key))
    for _, tc := range []struct{name string; wire []byte}{
        {"altered claim", []byte(strings.Replace(valid, "\"witnessId\":\"remote-witness-1\"", "\"witnessId\":\"unknown\"", 1))},
        {"duplicate witness id", []byte(strings.Replace(valid, "\"witnessId\":", "\"witnessId\":\"spoof\",\"witnessId\":", 1))},
        {"duplicate nested node", []byte(strings.Replace(valid, "\"nodeId\":", "\"nodeId\":\"spoof\",\"nodeId\":", 1))},
        {"unknown top field", []byte(strings.Replace(valid, "\"signature\":", "\"extra\":true,\"signature\":", 1))},
        {"trailing object", []byte(valid + "{}")},
        {"oversize", bytes.Repeat([]byte(" "), 4097)},
        {"bad base64", []byte(strings.Replace(valid, "\"signature\":\"", "\"signature\":\"!", 1))},
    } {
        t.Run(tc.name, func(t *testing.T) {
            if _, err := v.Verify(context.Background(), tc.wire); err == nil {
                t.Fatal("ambiguous or forged evidence accepted")
            }
        })
    }
    impostor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
    if _, err := v.Verify(context.Background(), signed(t, report, impostor)); err == nil {
        t.Fatal("untrusted signing key accepted")
    }
    if _, err := v.Verify(context.Background(), []byte(valid)); err != nil {
        t.Fatalf("failed hostile attempts consumed legitimate nonce: %v", err)
    }
}

func TestExpiredAndUnissuedChallengeFailClosed(t *testing.T) {
    v, key, now := fixture(t)
    wire := signed(t, reportFor(t, v, *now), key)
    cold, _, _ := fixture(t)
    if _, err := cold.Verify(context.Background(), wire); err == nil {
        t.Fatal("fresh verifier accepted unknown nonce")
    }
    *now = now.Add(31 * time.Second)
    if _, err := v.Verify(context.Background(), wire); err == nil {
        t.Fatal("expired challenge accepted")
    }
}

func TestOnlyOneConcurrentVerifierCanAcceptSignedReport(t *testing.T) {
    v, key, now := fixture(t)
    wire := signed(t, reportFor(t, v, *now), key)
    var accepted atomic.Int32
    var wg sync.WaitGroup
    for i := 0; i < 24; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            if _, err := v.Verify(context.Background(), wire); err == nil { accepted.Add(1) }
        }()
    }
    wg.Wait()
    if accepted.Load() != 1 { t.Fatalf("accepted %d times", accepted.Load()) }
}

func TestBoundedChallengesInvalidSettingsAndSigningDomain(t *testing.T) {
    v, _, now := fixture(t)
    for i := 0; i < 64; i++ {
        if _, err := v.Issue(context.Background()); err != nil { t.Fatal(err) }
    }
    if _, err := v.Issue(context.Background()); err == nil { t.Fatal("unbounded outstanding nonces") }
    *now = now.Add(31 * time.Second)
    if _, err := v.Issue(context.Background()); err != nil { t.Fatal("expired nonces not pruned", err) }
    if _, err := v.Issue(nil); err == nil { t.Fatal("nil issue context accepted") }
    if _, err := v.Verify(nil,nil); err == nil { t.Fatal("nil verify context accepted") }

    key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
    cfg := Config{NodeID: "node-1", Epoch: "epoch-1",
        Generation: "sha256:" + strings.Repeat("a", 64),
        ProfileDigest: "sha256:" + strings.Repeat("b", 64),
        WitnessKeys: map[string]ed25519.PublicKey{"witness-1": key.Public().(ed25519.PublicKey)},
        TTL: 30*time.Second}
    for _, tc := range []struct{name string; mutate func(*Config)}{
        {"missing node", func(c *Config){c.NodeID = ""}},
        {"missing epoch", func(c *Config){c.Epoch = ""}},
        {"bad generation", func(c *Config){c.Generation = "bad"}},
        {"bad profile", func(c *Config){c.ProfileDigest = "bad"}},
        {"missing keys", func(c *Config){c.WitnessKeys = nil}},
        {"bad public key", func(c *Config){c.WitnessKeys["witness-1"] = []byte{1}}},
        {"ttl zero", func(c *Config){c.TTL = 0}},
        {"ttl too long", func(c *Config){c.TTL = 3*time.Minute}},
    } {
        t.Run(tc.name, func(t *testing.T) {
            candidate := cfg
            candidate.WitnessKeys = map[string]ed25519.PublicKey{"witness-1": cfg.WitnessKeys["witness-1"]}
            tc.mutate(&candidate)
            if _, err := NewVerifier(candidate); err == nil { t.Fatal("invalid verifier accepted") }
        })
    }
    fresh, _, fixed := fixture(t)
    payload, err := SigningBytes(reportFor(t,fresh,*fixed))
    if err != nil || !bytes.HasPrefix(payload, []byte("omnipanel:external-health:ed25519-v1\n")) {
        t.Fatalf("missing signed domain: %v", err)
    }
}
