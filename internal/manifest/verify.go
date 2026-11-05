package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Verify validates signed intent but does not deploy, write to disk, or install
// a runtime. The returned revision is advisory until safely journaled and
// applied by a separately verified node reconciler.
func (v Verifier) Verify(data []byte) (Verified, error) {
	if len(data) == 0 || len(data) > maxEnvelopeBytes {
		return Verified{}, errors.New("desired-state envelope outside size limit")
	}
	root, err := decodeUnique(data)
	if err != nil {
		return Verified{}, fmt.Errorf("invalid envelope: %w", err)
	}
	if err := ensureShape(root); err != nil {
		return Verified{}, fmt.Errorf("invalid contract: %w", err)
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Verified{}, fmt.Errorf("invalid typed manifest: %w", err)
	}
	if err := validateManifest(envelope.Manifest); err != nil {
		return Verified{}, err
	}
	if envelope.SignatureVersion != "ed25519-jcs-v1" || !identifierPattern.MatchString(envelope.SignerID) || !digestPattern.MatchString(envelope.ContentDigest) {
		return Verified{}, errors.New("unsupported signature envelope")
	}
	pub := v.TrustedSigners[envelope.SignerID]
	if len(pub) != ed25519.PublicKeySize {
		return Verified{}, errors.New("signer is not locally trusted")
	}
	canonical, err := canonicalize(root.(map[string]any)["manifest"])
	if err != nil {
		return Verified{}, err
	}
	digest := sha256.Sum256(canonical)
	contentDigest := hex.EncodeToString(digest[:])
	if envelope.ContentDigest != contentDigest {
		return Verified{}, errors.New("manifest digest mismatch")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(envelope.Signature) != 86 || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pub, append([]byte(signatureDomain), canonical...), signature) {
		return Verified{}, errors.New("manifest signature invalid")
	}
	m := envelope.Manifest
	if m.NodeID != v.NodeID || m.ControlPlaneEpoch != v.AuthorizedEpoch {
		return Verified{}, errors.New("manifest outside trusted node or authorized epoch")
	}
	if v.MaxClockSkew < 0 {
		return Verified{}, errors.New("invalid clock-skew configuration")
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	issued, _ := time.Parse(time.RFC3339Nano, m.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	if issued.After(now.Add(v.MaxClockSkew)) || !expires.After(now.Add(-v.MaxClockSkew)) {
		return Verified{}, errors.New("manifest outside authorized validity window")
	}
	for _, capability := range m.RequiredCapabilities {
		if !v.AllowedCapabilities[capability] {
			return Verified{}, fmt.Errorf("capability %s not approved", capability)
		}
	}
	qualifiedCapabilities := make(map[string]bool)
	for _, component := range m.Components {
		qualified, exists := v.QualifiedBuilds[component.Driver]
		if !exists || qualified.Driver != component.Driver || qualified.Version != component.RuntimeVersion || qualified.ArtifactDigest != component.ArtifactDigest {
			return Verified{}, fmt.Errorf("component %s has no exact qualified runtime build", component.ID)
		}
		for _, capability := range qualified.Capabilities {
			qualifiedCapabilities[capability] = true
		}
	}
	for _, capability := range m.RequiredCapabilities {
		if !qualifiedCapabilities[capability] {
			return Verified{}, fmt.Errorf("required capability %s absent from verified runtime build", capability)
		}
	}
	if m.MembershipSequence < v.Current.MembershipSequence {
		return Verified{}, errors.New("membership cursor would move backwards")
	}
	if m.StructuralSequence < v.Current.StructuralSequence {
		return Verified{}, errors.New("structural replay or rollback requires a new higher revision")
	}
	if m.StructuralSequence == v.Current.StructuralSequence {
		if v.Current.Digest == "" || v.Current.Digest != contentDigest || m.MembershipSequence != v.Current.MembershipSequence {
			return Verified{}, errors.New("conflicting or untracked equal-sequence revision")
		}
		return Verified{Manifest: m, Digest: contentDigest, Decision: AlreadyApplied}, nil
	}
	return Verified{Manifest: m, Digest: contentDigest, Decision: ApplyRevision}, nil
}
