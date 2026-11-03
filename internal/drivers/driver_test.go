package drivers

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedOperationsReturnTypedCapabilityErrors(t *testing.T) {
	d := Unsupported{Runtime: "singbox"}
	tests := []struct {
		name string
		run  func() error
	}{
		{"capabilities", func() error { _, err := d.Capabilities(context.Background(), BuildIdentity{}); return err }},
		{"render", func() error { _, err := d.Render(context.Background(), ComponentPlan{}); return err }},
		{"validate", func() error { return d.Validate(context.Background(), ConfigArtifact{}) }},
		{"preflight", func() error { _, err := d.Preflight(context.Background(), ComponentPlan{}); return err }},
		{"classify disruption", func() error { _, err := d.ClassifyDisruption(context.Background(), ComponentPlan{}); return err }},
		{"apply structure", func() error { _, err := d.ApplyStructure(context.Background(), ComponentPlan{}); return err }},
		{"apply membership", func() error { _, err := d.ApplyMembership(context.Background(), MembershipDelta{}); return err }},
		{"health", func() error { _, err := d.Health(context.Background()); return err }},
		{"counters", func() error { _, err := d.ObserveCounters(context.Background()); return err }},
		{"revoke", func() error { _, err := d.RevokeSessions(context.Background(), nil); return err }},
		{"rollback", func() error { _, err := d.Rollback(context.Background(), ConfigArtifact{}); return err }},
		{"diagnostics", func() error { _, err := d.Diagnose(context.Background()); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if !errors.Is(err, ErrUnsupportedCapability) {
				t.Fatalf("expected ErrUnsupportedCapability, got %v", err)
			}
			var capabilityError *CapabilityError
			if !errors.As(err, &capabilityError) || capabilityError.Driver != "singbox" || capabilityError.Operation == "" {
				t.Fatalf("expected scoped typed capability error, got %v", err)
			}
		})
	}
}

func TestCapabilityErrorDoesNotLeakSensitiveDetails(t *testing.T) {
	got := (&CapabilityError{Driver: "singbox", Operation: "revoke_sessions"}).Error()
	if got != "singbox: revoke_sessions: unsupported capability" {
		t.Fatalf("unexpected error: %q", got)
	}
}
