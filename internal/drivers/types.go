// Package drivers defines the capability-gated boundary between verified
// desired state and independently supervised network runtimes.
package drivers

import (
	"context"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

// BuildIdentity is supplied by trusted local qualification state, never by
// the untrusted input being rendered.
type BuildIdentity struct {
	Runtime        string
	Version        string
	ArtifactDigest string
}

// CapabilitySet lists supported adapter operations, NOT qualified network
// protocols or verified quota semantics.
type CapabilitySet struct {
	Operations []string
}

// ComponentPlan references a separately verified manifest. Secrets and
// runtime-specific parameters are supplied through bounded typed fields.
type ComponentPlan struct {
	Revision    manifest.Verified
	ComponentID string
	Capability  string
	Reality     *RealityInbound
}

// RealityInbound describes one VLESS/Reality/Vision inbound fragment. It does
// not contain egress routing or operational host commands.
type RealityInbound struct {
	Listen          manifest.Listener
	HandshakeServer string
	HandshakePort   uint16
	PrivateKey      string
	ShortIDs        []string
	Users           []Principal
}

type Principal struct {
	ID   string
	UUID string
}

// ConfigArtifact may contain credentials. Never include its Content in logs,
// audit events, error strings or API responses.
type ConfigArtifact struct {
	ComponentID     string
	Format          string
	Content         []byte
	SHA256          string
	ContainsSecrets bool
}

type PreflightReport struct {
	ComponentID string
	Detail      string
}
type Disruption string
type ApplyResult struct {
	ComponentID string
	Generation  string
}
type MembershipDelta struct {
	ComponentID string
	Sequence    uint64
	Changes     []Principal
}
type HealthReport struct {
	ComponentID string
	Status      string
}
type CounterObservation struct {
	PrincipalID   string
	Generation    string
	Sequence      uint64
	UploadBytes   uint64
	DownloadBytes uint64
}
type CounterBatch struct{ Observations []CounterObservation }
type PrincipalRef struct {
	ID         string
	Generation uint64
}
type RevocationReport struct {
	Closed     int
	Unclosable int
}
type DiagnosticReport struct {
	ComponentID string
	Messages    []string
}

// Driver separates structural rendering from native preflight, application,
// membership, metering and session revocation. An unimplemented operation MUST
// report ErrUnsupportedCapability and must not return a fabricated success.
type Driver interface {
	Capabilities(context.Context, BuildIdentity) (CapabilitySet, error)
	Render(context.Context, ComponentPlan) (ConfigArtifact, error)
	Validate(context.Context, ConfigArtifact) error
	Preflight(context.Context, ComponentPlan) (PreflightReport, error)
	ClassifyDisruption(context.Context, ComponentPlan) (Disruption, error)
	ApplyStructure(context.Context, ComponentPlan) (ApplyResult, error)
	ApplyMembership(context.Context, MembershipDelta) (ApplyResult, error)
	Health(context.Context) (HealthReport, error)
	ObserveCounters(context.Context) (CounterBatch, error)
	RevokeSessions(context.Context, []PrincipalRef) (RevocationReport, error)
	Rollback(context.Context, ConfigArtifact) (ApplyResult, error)
	Diagnose(context.Context) (DiagnosticReport, error)
}
