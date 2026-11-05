// Package manifest verifies node-scoped desired-state intent. It never executes
// commands, writes configuration files, or grants runtime qualification.
package manifest

import (
	"crypto/ed25519"
	"time"
)

const (
	signatureDomain         = "omnipanel:desired-state:ed25519-jcs-v1\n"
	maxSafeInteger   uint64 = 9007199254740991
	maxEnvelopeBytes        = 1 << 20
)

// Envelope is the proposed v2 signed desired-state wire envelope.
type Envelope struct {
	SignatureVersion string   `json:"signatureVersion"`
	SignerID         string   `json:"signerId"`
	ContentDigest    string   `json:"contentDigest"`
	Signature        string   `json:"signature"`
	Manifest         Manifest `json:"manifest"`
}

type Manifest struct {
	SchemaVersion        string      `json:"schemaVersion"`
	ControlPlaneEpoch    string      `json:"controlPlaneEpoch"`
	NodeID               string      `json:"nodeId"`
	StructuralSequence   uint64      `json:"structuralSequence"`
	MembershipSequence   uint64      `json:"membershipSequence"`
	IssuedAt             string      `json:"issuedAt"`
	ExpiresAt            string      `json:"expiresAt"`
	RequiredCapabilities []string    `json:"requiredCapabilities"`
	Components           []Component `json:"components"`
	BaseEgressPolicy     string      `json:"baseEgressPolicy"`
}

type Component struct {
	ID                  string     `json:"id"`
	Driver              string     `json:"driver"`
	RuntimeVersion      string     `json:"runtimeVersion"`
	ArtifactDigest      string     `json:"artifactDigest"`
	ConfigurationDigest string     `json:"configurationDigest"`
	ConfigurationRef    string     `json:"configurationRef"`
	DependsOn           []string   `json:"dependsOn"`
	Listeners           []Listener `json:"listeners"`
	Disruption          string     `json:"disruption"`
}

type Listener struct {
	Address   string `json:"address"`
	Port      uint16 `json:"port"`
	Transport string `json:"transport"`
	IPv6Only  bool   `json:"ipv6Only"`
}

// Build is provisioned only from separately reviewed, exact-build lab evidence.
type Build struct {
	Driver         string
	Version        string
	ArtifactDigest string
	Capabilities   []string
}

type Cursor struct {
	StructuralSequence uint64
	MembershipSequence uint64
	Digest             string
}

type Decision string

const (
	ApplyRevision  Decision = "apply_revision"
	AlreadyApplied Decision = "already_applied"
)

type Verified struct {
	Manifest Manifest
	Digest   string
	Decision Decision
}

// Verifier binds an independently approved signer and epoch to one node.
// Credentials, qualification and cursors are supplied by a separate trusted
// local store; an incoming signed manifest cannot add its own trust anchors.
type Verifier struct {
	NodeID              string
	AuthorizedEpoch     string
	TrustedSigners      map[string]ed25519.PublicKey
	AllowedCapabilities map[string]bool
	QualifiedBuilds     map[string]Build
	Current             Cursor
	Now                 func() time.Time
	MaxClockSkew        time.Duration
}
