package desiredapproval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

const (
	testNode = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	testOrg = "4b0895aa-1701-4c6d-8b31-91d642c23e1c"
	testEpoch = "ea2429da-7540-4e40-ae70-38fd3f19794b"
	testProposal = "f090a8e3-12fd-48d5-8dc4-0ab999a3da10"
)

func testVerifier() manifest.Verifier {
	return manifest.Verifier{
		AuthorizedEpoch: testEpoch,
		TrustedSigners: map[string]ed25519.PublicKey{"trusted-test": bytes.Repeat([]byte{0x09}, ed25519.PublicKeySize)},
		AllowedCapabilities: map[string]bool{"singbox-reality-vision": true},
		QualifiedBuilds: map[string]manifest.Build{"singbox": {
			Driver: "singbox", Version: "1.14.4+omni.2",
			ArtifactDigest: strings.Repeat("a", 64),
			Capabilities: []string{"singbox-reality-vision"},
		}},
		MaxClockSkew: time.Second,
	}
}

func testToken() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa3}, 32))
}

func TestConstructorRefusesUntrustedEpochKeysOrStore(t *testing.T) {
	if _, err := NewService(nil, testVerifier()); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("nil database accepted: %v", err)
	}
	for _, change := range []func(*manifest.Verifier){
		func(v *manifest.Verifier) { v.AuthorizedEpoch = "" },
		func(v *manifest.Verifier) { v.TrustedSigners = nil },
		func(v *manifest.Verifier) { v.TrustedSigners["trusted-test"] = []byte{1} },
		func(v *manifest.Verifier) { v.AllowedCapabilities = nil },
		func(v *manifest.Verifier) { v.QualifiedBuilds = nil },
		func(v *manifest.Verifier) { v.MaxClockSkew = -time.Second },
	} {
		config := testVerifier()
		change(&config)
		if _, err := NewService(new(sql.DB), config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("untrusted configuration accepted: %v", err)
		}
	}
}

func TestTwoStageApprovalsRejectMalformedIdentityAndSessionBeforeDatabase(t *testing.T) {
	svc, err := NewService(new(sql.DB), testVerifier())
	if err != nil {
		t.Fatal(err)
	}
	good := ProposalRequest{
		SessionToken: testToken(), ProposalID: testProposal,
		OrganizationID: testOrg, NodeID: testNode,
		Envelope: []byte("untrusted wire"), Lifetime: 5 * time.Minute,
	}
	for _, invalid := range []ProposalRequest{
		{},
		{SessionToken: "bad", ProposalID: good.ProposalID, OrganizationID: good.OrganizationID, NodeID: good.NodeID, Envelope: good.Envelope, Lifetime: good.Lifetime},
		{SessionToken: good.SessionToken, ProposalID: "not-uuid", OrganizationID: good.OrganizationID, NodeID: good.NodeID, Envelope: good.Envelope, Lifetime: good.Lifetime},
		{SessionToken: good.SessionToken, ProposalID: good.ProposalID, OrganizationID: good.OrganizationID, NodeID: good.NodeID, Envelope: nil, Lifetime: good.Lifetime},
		{SessionToken: good.SessionToken, ProposalID: good.ProposalID, OrganizationID: good.OrganizationID, NodeID: good.NodeID, Envelope: good.Envelope, Lifetime: time.Second},
		{SessionToken: good.SessionToken, ProposalID: good.ProposalID, OrganizationID: good.OrganizationID, NodeID: good.NodeID, Envelope: good.Envelope, Lifetime: 30 * time.Minute},
	} {
		if _, err := svc.Propose(context.Background(), invalid); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("malformed proposal escaped input validation: %v", err)
		}
	}
	for _, invalid := range []ApprovalRequest{
		{},
		{SessionToken: "bad", ProposalID: testProposal, ExpectedSHA256: strings.Repeat("a", 64)},
		{SessionToken: testToken(), ProposalID: "bad", ExpectedSHA256: strings.Repeat("a", 64)},
		{SessionToken: testToken(), ProposalID: testProposal, ExpectedSHA256: "not-a-digest"},
		{SessionToken: testToken(), ProposalID: testProposal, ExpectedSHA256: strings.Repeat("A", 64)},
	} {
		if _, err := svc.Approve(context.Background(), invalid); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("malformed approval escaped input validation: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.Propose(ctx, good); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled proposal entered database: %v", err)
	}
	if _, err := svc.Approve(ctx, ApprovalRequest{SessionToken: testToken(), ProposalID: testProposal, ExpectedSHA256: strings.Repeat("a", 64)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled approval entered database: %v", err)
	}
}

func TestSessionTokensUseCanonical32ByteBearerEncoding(t *testing.T) {
	valid := testToken()
	if _, validToken := sessionDigest(valid); !validToken {
		t.Fatal("valid canonical 32-byte session token rejected")
	}
	for _, invalid := range []string{"", valid+"=", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 31)), "not-base64", "    "+valid} {
		if _, ok := sessionDigest(invalid); ok {
			t.Fatalf("noncanonical or malformed token accepted: %q", invalid)
		}
	}
}
