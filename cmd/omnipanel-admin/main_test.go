package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/control/adminruntime"
	"strings"
	"testing"
)

func TestVerifierTrustMustComeFromProtectedConfiguration(t *testing.T) {
	pub := ed25519.NewKeyFromSeed([]byte(strings.Repeat("X", 32))).Public().(ed25519.PublicKey)
	trust := adminruntime.Trust{
		AuthorizedEpoch:     "ea2429da-7540-4e40-ae70-38fd3f19794b",
		Signers:             map[string]string{"signer-test": base64.RawURLEncoding.EncodeToString(pub)},
		Capabilities:        []string{"singbox-reality-vision"},
		Builds:              map[string]adminruntime.Build{"singbox": {Driver: "singbox", Version: "1.14.4+omni.2", ArtifactDigest: strings.Repeat("a", 64), Capabilities: []string{"singbox-reality-vision"}}},
		MaxClockSkewSeconds: 5,
	}
	got := makeVerifier(trust)
	if got.AuthorizedEpoch != trust.AuthorizedEpoch || !got.AllowedCapabilities["singbox-reality-vision"] || !ed25519.PublicKey(got.TrustedSigners["signer-test"]).Equal(pub) || got.QualifiedBuilds["singbox"].Version != "1.14.4+omni.2" {
		t.Fatal("trusted manifest verifier was not derived from protected config")
	}
	if got.NodeID != "" || got.Current.StructuralSequence != 0 {
		t.Fatal("startup trust was contaminated by an incoming node cursor")
	}
	trust.Capabilities[0] = "altered"
	trust.Builds["singbox"] = adminruntime.Build{}
	if !got.AllowedCapabilities["singbox-reality-vision"] || got.QualifiedBuilds["singbox"].Version != "1.14.4+omni.2" {
		t.Fatal("trusted verification data aliased mutable config")
	}
}

func TestUnknownDatabasePurposeRejectedBeforeOpeningConnection(t *testing.T) {
	_, err := openRole(context.Background(), "postgres://invalid", "omni_session", "publisher")
	if err == nil || !strings.Contains(err.Error(), "invalid administrator database purpose") {
		t.Fatalf("unsafe runtime database role intent was not rejected: %v", err)
	}
}

func TestRuntimeRejectsNoncanonicalPurposeDatabaseUsername(t *testing.T) {
	_, err := openRole(context.Background(), "postgres://invalid", "omni_session", "session")
	if err == nil || !strings.Contains(err.Error(), "canonical administrator database identity") {
		t.Fatalf("unprotected database username was not rejected: %v", err)
	}
}
