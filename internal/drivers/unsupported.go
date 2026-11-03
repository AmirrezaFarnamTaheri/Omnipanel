package drivers

import "context"

// Unsupported is an explicit fail-closed default for adapters that have not
// yet passed native driver validation and independent operational qualification.
type Unsupported struct{ Runtime string }

func (u Unsupported) unsupported(operation string) error {
	return &CapabilityError{Driver: u.Runtime, Operation: operation}
}
func (u Unsupported) Capabilities(context.Context, BuildIdentity) (CapabilitySet, error) {
	return CapabilitySet{}, u.unsupported("capabilities")
}
func (u Unsupported) Render(context.Context, ComponentPlan) (ConfigArtifact, error) {
	return ConfigArtifact{}, u.unsupported("render")
}
func (u Unsupported) Validate(context.Context, ConfigArtifact) error {
	return u.unsupported("validate")
}
func (u Unsupported) Preflight(context.Context, ComponentPlan) (PreflightReport, error) {
	return PreflightReport{}, u.unsupported("preflight")
}
func (u Unsupported) ClassifyDisruption(context.Context, ComponentPlan) (Disruption, error) {
	return "", u.unsupported("classify_disruption")
}
func (u Unsupported) ApplyStructure(context.Context, ComponentPlan) (ApplyResult, error) {
	return ApplyResult{}, u.unsupported("apply_structure")
}
func (u Unsupported) ApplyMembership(context.Context, MembershipDelta) (ApplyResult, error) {
	return ApplyResult{}, u.unsupported("apply_membership")
}
func (u Unsupported) Health(context.Context) (HealthReport, error) {
	return HealthReport{}, u.unsupported("health")
}
func (u Unsupported) ObserveCounters(context.Context) (CounterBatch, error) {
	return CounterBatch{}, u.unsupported("observe_counters")
}
func (u Unsupported) RevokeSessions(context.Context, []PrincipalRef) (RevocationReport, error) {
	return RevocationReport{}, u.unsupported("revoke_sessions")
}
func (u Unsupported) Rollback(context.Context, ConfigArtifact) (ApplyResult, error) {
	return ApplyResult{}, u.unsupported("rollback")
}
func (u Unsupported) Diagnose(context.Context) (DiagnosticReport, error) {
	return DiagnosticReport{}, u.unsupported("diagnose")
}
