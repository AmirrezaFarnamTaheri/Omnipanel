package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

func approvedTestPlan() (drivers.BuildIdentity, drivers.ComponentPlan) {
	digest := strings.Repeat("a", 64)
	build := drivers.BuildIdentity{Runtime: "singbox", Version: "1.14.4+omni.2", ArtifactDigest: digest}
	component := manifest.Component{ID: "reality", Driver: "singbox", RuntimeVersion: build.Version, ArtifactDigest: build.ArtifactDigest,
		ConfigurationDigest: strings.Repeat("b", 64), ConfigurationRef: "reality-config",
		Listeners: []manifest.Listener{{Address: "0.0.0.0", Port: 24443, Transport: "tcp"}}, Disruption: "listener_restart"}
	verified := manifest.Verified{
		Manifest: manifest.Manifest{SchemaVersion: "2.0", NodeID: "62c478bb-47c3-4dc6-a363-a2fbde813810", ControlPlaneEpoch: "ea2429da-7540-4e40-ae70-38fd3f19794b",
			RequiredCapabilities: []string{"singbox-reality-vision"}, Components: []manifest.Component{component}, BaseEgressPolicy: "deny-protected-v1"},
		Digest: strings.Repeat("c", 64), Decision: manifest.ApplyRevision,
	}
	return build, drivers.ComponentPlan{
		Revision: verified, ComponentID: "reality", Capability: "singbox-reality-vision",
		Reality: &drivers.RealityInbound{
			Listen:          manifest.Listener{Address: "0.0.0.0", Port: 24443, Transport: "tcp"},
			HandshakeServer: "127.0.0.1", HandshakePort: 18443,
			PrivateKey: strings.Repeat("A", 43), ShortIDs: []string{"aabbccdd"},
			Users: []drivers.Principal{{ID: "user-two", UUID: "f85acbc7-6f7c-4c8b-a7dc-a2296ce36f29"}, {ID: "user-one", UUID: "a77556d4-4ab6-4a80-bfd3-10f129a0aa8e"}},
		},
	}
}

func TestRealityInboundRenderingIsDeterministicAndNotDeployable(t *testing.T) {
	build, plan := approvedTestPlan()
	adapter, err := New(build)
	if err != nil {
		t.Fatal(err)
	}
	first, err := adapter.Render(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.Reality.Users[0], plan.Reality.Users[1] = plan.Reality.Users[1], plan.Reality.Users[0]
	second, err := adapter.Render(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Content, second.Content) {
		t.Fatal("equivalent memberships must render identically")
	}
	if first.ContainsSecrets != true || first.Format != "singbox/inbound-fragment+json" || first.ComponentID != "reality" || len(first.SHA256) != 64 {
		t.Fatalf("unexpected artifact: %+v", first)
	}
	var payload map[string]any
	if err := json.Unmarshal(first.Content, &payload); err != nil {
		t.Fatal(err)
	}
	if _, present := payload["route"]; present {
		t.Fatal("an inbound fragment must not pretend to be a complete protected egress configuration")
	}
	if _, present := payload["outbounds"]; present {
		t.Fatal("an inbound fragment must not include an unqualified direct outbound")
	}
	inbounds, ok := payload["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("expected one vless inbound, got %v", payload)
	}
	inbound := inbounds[0].(map[string]any)
	if inbound["type"] != "vless" || inbound["listen_port"] != float64(24443) {
		t.Fatalf("wrong protocol/port: %v", inbound)
	}
	users := inbound["users"].([]any)
	if users[0].(map[string]any)["name"] != "user-one" || users[1].(map[string]any)["name"] != "user-two" {
		t.Fatalf("unstable member ordering: %v", users)
	}
	if !bytes.Contains(first.Content, []byte("xtls-rprx-vision")) || !bytes.Contains(first.Content, []byte("\"reality\"")) {
		t.Fatal("Reality/Vision identity lost")
	}
}

func TestUnqualifiedOrUnsafeRenderInputFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*drivers.BuildIdentity, *drivers.ComponentPlan)
	}{
		{"wrong build hash", func(b *drivers.BuildIdentity, _ *drivers.ComponentPlan) { b.ArtifactDigest = strings.Repeat("d", 64) }},
		{"wrong build version", func(b *drivers.BuildIdentity, _ *drivers.ComponentPlan) { b.Version = "1.14.0" }},
		{"wrong driver", func(b *drivers.BuildIdentity, _ *drivers.ComponentPlan) { b.Runtime = "xray" }},
		{"missing verified decision", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) { p.Revision.Decision = "" }},
		{"unprotected egress", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) {
			p.Revision.Manifest.BaseEgressPolicy = "allow-all"
		}},
		{"unknown component", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) { p.ComponentID = "missing" }},
		{"capability mismatch", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) { p.Capability = "hysteria2" }},
		{"listener mismatch", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) { p.Reality.Listen.Port = 443 }},
		{"unqualified path", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) { p.Reality.Listen.Address = "/etc/shadow" }},
		{"missing users", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) { p.Reality.Users = nil }},
		{"duplicate users", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) {
			p.Reality.Users = append(p.Reality.Users, p.Reality.Users[0])
		}},
		{"invalid credential", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) { p.Reality.Users[0].UUID = "shell-command" }},
		{"unqualified reality key", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) { p.Reality.PrivateKey = "not-a-valid-key" }},
		{"no handshake port", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) { p.Reality.HandshakePort = 0 }},
		{"duplicate short IDs", func(_ *drivers.BuildIdentity, p *drivers.ComponentPlan) {
			p.Reality.ShortIDs = []string{"aabb", "aabb"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			build, plan := approvedTestPlan()
			tc.mutate(&build, &plan)
			adapter, err := New(build)
			if err == nil {
				_, err = adapter.Render(context.Background(), plan)
			}
			if err == nil {
				t.Fatal("invalid input unexpectedly rendered")
			}
		})
	}
}

func TestUnimplementedRuntimeOperationsRemainErrors(t *testing.T) {
	build, plan := approvedTestPlan()
	adapter, err := New(build)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Preflight(context.Background(), plan)
	if !errors.Is(err, drivers.ErrUnsupportedCapability) {
		t.Fatalf("native preflight must not be claimed: %v", err)
	}
	err = adapter.Validate(context.Background(), drivers.ConfigArtifact{})
	if !errors.Is(err, drivers.ErrUnsupportedCapability) {
		t.Fatalf("native validation must not be claimed: %v", err)
	}
	_, err = adapter.ApplyStructure(context.Background(), plan)
	if !errors.Is(err, drivers.ErrUnsupportedCapability) {
		t.Fatalf("no host application should be possible: %v", err)
	}
}
