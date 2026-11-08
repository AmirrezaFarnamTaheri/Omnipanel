// Package healthattestation verifies bounded, nonce-bound reports signed by a
// separately provisioned external reference-client witness. It does NOT
// perform a network probe or authorize deployment, applied ACK or M0 release.
package healthattestation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"
)

const (
	version = "external-health-v1"
	signingDomain = "omnipanel:external-health:ed25519-v1\n"
	maxEvidenceBytes = 4096
	maxChallenges = 64
	maxTTL = 2 * time.Minute
)

var (
	ErrUntrustedEvidence = errors.New("independent health evidence rejected")
	digestPattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
	identityPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
)

// Config is local verifier policy. The witness public keys, expected generation,
// node, epoch and immutable test-profile digest NEVER come from signed evidence.
type Config struct {
	NodeID string
	Epoch string
	Generation string
	ProfileDigest string
	WitnessKeys map[string]ed25519.PublicKey
	TTL time.Duration
	Now func() time.Time
}

// Challenge is issued by the verifier and must be carried without modification
// into an external witness report. The profile digest must identify a separately
// reviewed suite of reference-client and protected-egress checks.
type Challenge struct {
	Version string `json:"version"`
	NodeID string `json:"nodeId"`
	Epoch string `json:"epoch"`
	Generation string `json:"generation"`
	ProfileDigest string `json:"profileDigest"`
	Nonce string `json:"nonce"`
	IssuedAtMillis int64 `json:"issuedAtMillis"`
	ExpiresAtMillis int64 `json:"expiresAtMillis"`
}

// Evidence claims observed external connectivity and protected-route denial.
// Its signature covers all fields except Signature, with domain separation.
type Evidence struct {
	Challenge Challenge `json:"challenge"`
	WitnessID string `json:"witnessId"`
	ObservedAtMillis int64 `json:"observedAtMillis"`
	RealityVisionOK bool `json:"realityVisionOk"`
	ProtectedEgressDenied bool `json:"protectedEgressDenied"`
	Signature string `json:"signature"`
}

// Accepted is a scoped cryptographic verification result, NOT a release
// qualification or evidence that the checker actually executed real traffic.
type Accepted struct {
	NodeID string
	Epoch string
	Generation string
	ProfileDigest string
	WitnessID string
	ObservedAtMillis int64
}

type Verifier struct {
	cfg Config
	mu sync.Mutex
	outstanding map[string]Challenge
}

func NewVerifier(cfg Config) (*Verifier, error) {
	if !identityPattern.MatchString(cfg.NodeID) ||
		!identityPattern.MatchString(cfg.Epoch) ||
		!digestPattern.MatchString(cfg.Generation) ||
		!digestPattern.MatchString(cfg.ProfileDigest) ||
		cfg.TTL < time.Second || cfg.TTL > maxTTL ||
		len(cfg.WitnessKeys) == 0 || len(cfg.WitnessKeys) > 32 {
		return nil, ErrUntrustedEvidence
	}
	keys := make(map[string]ed25519.PublicKey, len(cfg.WitnessKeys))
	for id, key := range cfg.WitnessKeys {
		if !identityPattern.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrUntrustedEvidence
		}
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	cfg.WitnessKeys = keys
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg, outstanding: make(map[string]Challenge)}, nil
}

func (v *Verifier) Issue(ctx context.Context) (Challenge, error) {
	if v == nil || ctx == nil || ctx.Err() != nil {
		return Challenge{}, ErrUntrustedEvidence
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Challenge{}, ErrUntrustedEvidence
	}
	now := v.cfg.Now().UTC()
	c := Challenge{
		Version: version, NodeID: v.cfg.NodeID, Epoch: v.cfg.Epoch,
		Generation: v.cfg.Generation, ProfileDigest: v.cfg.ProfileDigest,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		IssuedAtMillis: now.UnixMilli(),
		ExpiresAtMillis: now.Add(v.cfg.TTL).UnixMilli(),
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if ctx.Err() != nil {
		return Challenge{}, ErrUntrustedEvidence
	}
	for key, old := range v.outstanding {
		if now.UnixMilli() > old.ExpiresAtMillis {
			delete(v.outstanding, key)
		}
	}
	if len(v.outstanding) >= maxChallenges {
		return Challenge{}, ErrUntrustedEvidence
	}
	if _, collision := v.outstanding[c.Nonce]; collision {
		return Challenge{}, ErrUntrustedEvidence
	}
	v.outstanding[c.Nonce] = c
	return c, nil
}

// SigningBytes is the exact interoperable signing contract. It uses a bounded
// fixed-field JSON struct with a domain prefix. Signature must not be included.
func SigningBytes(e Evidence) ([]byte, error) {
	e.Signature = ""
	raw, err := json.Marshal(struct {
		Challenge Challenge `json:"challenge"`
		WitnessID string `json:"witnessId"`
		ObservedAtMillis int64 `json:"observedAtMillis"`
		RealityVisionOK bool `json:"realityVisionOk"`
		ProtectedEgressDenied bool `json:"protectedEgressDenied"`
	}{
		Challenge: e.Challenge, WitnessID: e.WitnessID,
		ObservedAtMillis: e.ObservedAtMillis,
		RealityVisionOK: e.RealityVisionOK,
		ProtectedEgressDenied: e.ProtectedEgressDenied,
	})
	if err != nil || len(raw) > maxEvidenceBytes {
		return nil, ErrUntrustedEvidence
	}
	return append([]byte(signingDomain), raw...), nil
}

// Verify requires *exactly* the serialized fixed-field wire representation.
// This deliberately narrow v1 contract rejects duplicate keys, unknown fields,
// trailing data and alternate encodings without relying on permissive JSON
// unmarshal semantics. It is safe to verify only a verifier-issued challenge.
func (v *Verifier) Verify(ctx context.Context, wire []byte) (Accepted, error) {
	if v == nil || ctx == nil || ctx.Err() != nil ||
		len(wire) == 0 || len(wire) > maxEvidenceBytes {
		return Accepted{}, ErrUntrustedEvidence
	}
	var e Evidence
	if err := json.Unmarshal(wire, &e); err != nil {
		return Accepted{}, ErrUntrustedEvidence
	}
	reencoded, err := json.Marshal(e)
	if err != nil || !bytes.Equal(wire, reencoded) {
		return Accepted{}, ErrUntrustedEvidence
	}
	c := e.Challenge
	now := v.cfg.Now().UTC().UnixMilli()
	if c.Version != version || c.NodeID != v.cfg.NodeID ||
		c.Epoch != v.cfg.Epoch || c.Generation != v.cfg.Generation ||
		c.ProfileDigest != v.cfg.ProfileDigest ||
		c.ExpiresAtMillis <= c.IssuedAtMillis ||
		c.ExpiresAtMillis-c.IssuedAtMillis != v.cfg.TTL.Milliseconds() ||
		now < c.IssuedAtMillis || now > c.ExpiresAtMillis ||
		e.ObservedAtMillis < c.IssuedAtMillis ||
		e.ObservedAtMillis > c.ExpiresAtMillis ||
		e.ObservedAtMillis > now ||
		!e.RealityVisionOK || !e.ProtectedEgressDenied {
		return Accepted{}, ErrUntrustedEvidence
	}
	nonce, err := base64.RawURLEncoding.DecodeString(c.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != c.Nonce {
		return Accepted{}, ErrUntrustedEvidence
	}
	key, trusted := v.cfg.WitnessKeys[e.WitnessID]
	if !trusted {
		return Accepted{}, ErrUntrustedEvidence
	}
	signature, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != e.Signature {
		return Accepted{}, ErrUntrustedEvidence
	}
	message, err := SigningBytes(e)
	if err != nil || !ed25519.Verify(key, message, signature) {
		return Accepted{}, ErrUntrustedEvidence
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if ctx.Err() != nil {
		return Accepted{}, ErrUntrustedEvidence
	}
	issued, ok := v.outstanding[c.Nonce]
	if !ok || issued != c || v.cfg.Now().UTC().UnixMilli() > issued.ExpiresAtMillis {
		return Accepted{}, ErrUntrustedEvidence
	}
	delete(v.outstanding, c.Nonce)
	return Accepted{
		NodeID: c.NodeID, Epoch: c.Epoch, Generation: c.Generation,
		ProfileDigest: c.ProfileDigest, WitnessID: e.WitnessID,
		ObservedAtMillis: e.ObservedAtMillis,
	}, nil
}
