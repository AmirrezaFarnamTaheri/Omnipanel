package singbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

func compiledTestPlan() (drivers.BuildIdentity, drivers.ComponentPlan) {
	build, plan := approvedTestPlan()
	plan.Revision.Manifest.StructuralSequence = 3
	plan.Revision.Manifest.MembershipSequence = 1
	return build, plan
}

func parseCompiledDocument(t *testing.T, artifact drivers.ConfigArtifact) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(artifact.Content, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestFullConfigDefaultFailsClosedWithoutAnyDirectEgress(t *testing.T) {
	build, plan := compiledTestPlan()
	artifact, err := CompileFull(context.Background(), []drivers.ComponentPlan{plan}, ProtectedPolicy{}, build)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Format != "singbox/full-config+json" || !artifact.ContainsSecrets || artifact.ComponentID != "reality" {
		t.Fatalf("not a protected full-config artifact: %+v", artifact)
	}
	sum := sha256.Sum256(artifact.Content)
	if artifact.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("full config digest differs from emitted content")
	}
	root := parseCompiledDocument(t, artifact)
	if _, present := root["dns"]; present {
		t.Fatal("block-all default must not start an implicit remote DNS resolver")
	}
	route := root["route"].(map[string]any)
	if route["final"] != "omni-block" {
		t.Fatal("default route must block, not direct")
	}
	outs := root["outbounds"].([]any)
	if len(outs) != 1 || outs[0].(map[string]any)["type"] != "block" {
		t.Fatal("block-all policy unexpectedly installed a routable outbound")
	}
	inbounds := root["inbounds"].([]any)
	if len(inbounds) != 1 || inbounds[0].(map[string]any)["type"] != "vless" {
		t.Fatal("approved Reality inbound missing from full config")
	}
}

func TestFullConfigExplicitPublicPolicyResolvesAndBlocksProtectedEgress(t *testing.T) {
	build, plan := compiledTestPlan()
	policy := ProtectedPolicy{
		Mode: EgressPublicOnly,
		ResolverIP: "1.1.1.1",
		ResolverServerName: "one.one.one.one",
	}
	artifact, err := CompileFull(context.Background(), []drivers.ComponentPlan{plan}, policy, build)
	if err != nil {
		t.Fatal(err)
	}
	root := parseCompiledDocument(t, artifact)
	dns := root["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if len(servers) != 1 || dns["final"] != "omni-dns" {
		t.Fatal("DNS must use exactly one locally authorized resolver")
	}
	resolver := servers[0].(map[string]any)
	if resolver["server"] != "1.1.1.1" || resolver["type"] != "tls" ||
		resolver["tls"].(map[string]any)["server_name"] != "one.one.one.one" {
		t.Fatal("authorized TLS resolver identity was lost")
	}
	if _, insecure := resolver["tls"].(map[string]any)["insecure"]; insecure {
		t.Fatal("DNS TLS verification must never be bypassed")
	}
	route := root["route"].(map[string]any)
	if route["final"] != "omni-public" {
		t.Fatal("explicit public policy must have a qualified named final outbound")
	}
	rules := route["rules"].([]any)
	if len(rules) < 5 {
		t.Fatal("DNS interception, resolution, and protected-range rejection are required")
	}
	if rules[0].(map[string]any)["action"] != "hijack-dns" {
		t.Fatal("DNS interception must precede all normal route processing")
	}
	if rules[1].(map[string]any)["action"] != "reject" {
		t.Fatal("unencrypted or alternate DNS transport must not silently bypass authorized resolver")
	}
	if rules[2].(map[string]any)["action"] != "resolve" || rules[2].(map[string]any)["server"] != "omni-dns" {
		t.Fatal("destination resolution must happen before protected-IP classification")
	}
	if rules[3].(map[string]any)["action"] != "reject" || rules[3].(map[string]any)["ip_is_private"] != true {
		t.Fatal("nonpublic IPs must be rejected before direct egress")
	}
	guard := rules[4].(map[string]any)
	cidrs := guard["ip_cidr"].([]any)
	for _, required := range []string{"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "192.168.0.0/16", "fc00::/7", "fe80::/10", "2001:db8::/32", "::ffff:0:0/96"} {
		found := false
		for _, value := range cidrs {
			if value == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing protected egress range %s", required)
		}
	}
	if guard["action"] != "reject" {
		t.Fatal("protected CIDR rule cannot route through a direct outbound")
	}
	outbounds := root["outbounds"].([]any)
	if len(outbounds) != 2 || outbounds[0].(map[string]any)["type"] != "block" ||
		outbounds[1].(map[string]any)["type"] != "direct" {
		t.Fatal("public mode must have only named block and direct outbounds")
	}
}

func TestFullConfigIsDeterministicAcrossPlanOrdering(t *testing.T) {
	build, first := compiledTestPlan()
	secondComponent := first.Revision.Manifest.Components[0]
	secondComponent.ID = "backup"
	secondComponent.ConfigurationRef = "backup-config"
	secondComponent.Listeners = []manifest.Listener{{Address: "0.0.0.0", Port: 24444, Transport: "tcp"}}
	first.Revision.Manifest.Components = append(first.Revision.Manifest.Components, secondComponent)
	second := first
	second.ComponentID = "backup"
	secondReality := *first.Reality
	secondReality.Listen = secondComponent.Listeners[0]
	secondReality.Users = []drivers.Principal{{ID: "user-three", UUID: "cca0f909-af54-4c6d-8a2f-695f0a7ab127"}}
	second.Reality = &secondReality

	policy := ProtectedPolicy{Mode: EgressBlockAll}
	a, err := CompileFull(context.Background(), []drivers.ComponentPlan{second, first}, policy, build)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CompileFull(context.Background(), []drivers.ComponentPlan{first, second}, policy, build)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Content, b.Content) || a.SHA256 != b.SHA256 {
		t.Fatal("equivalent plan sets must compile to identical bytes and SHA-256")
	}
	inbounds := parseCompiledDocument(t, a)["inbounds"].([]any)
	if len(inbounds) != 2 || inbounds[0].(map[string]any)["tag"] != "backup" ||
		inbounds[1].(map[string]any)["tag"] != "reality" {
		t.Fatal("full config inbounds must be sorted by stable component identity")
	}
}

func TestFullConfigRejectsInvalidPlansOrUntrustedEgressPolicy(t *testing.T) {
	cases := []struct {
		name string
		change func(*drivers.BuildIdentity, *[]drivers.ComponentPlan, *ProtectedPolicy)
	}{
		{"missing plans", func(_ *drivers.BuildIdentity, p *[]drivers.ComponentPlan, _ *ProtectedPolicy) { *p = nil }},
		{"wrong build", func(b *drivers.BuildIdentity, _ *[]drivers.ComponentPlan, _ *ProtectedPolicy) { b.ArtifactDigest = strings.Repeat("f", 64) }},
		{"unknown egress mode", func(_ *drivers.BuildIdentity, _ *[]drivers.ComponentPlan, p *ProtectedPolicy) { p.Mode = "allow-all" }},
		{"block-all with DNS settings", func(_ *drivers.BuildIdentity, _ *[]drivers.ComponentPlan, p *ProtectedPolicy) { p.ResolverIP = "1.1.1.1" }},
		{"public mode without resolver", func(_ *drivers.BuildIdentity, _ *[]drivers.ComponentPlan, p *ProtectedPolicy) { p.Mode = EgressPublicOnly }},
		{"public mode with private resolver", func(_ *drivers.BuildIdentity, _ *[]drivers.ComponentPlan, p *ProtectedPolicy) {
			p.Mode, p.ResolverIP, p.ResolverServerName = EgressPublicOnly, "127.0.0.1", "one.one.one.one"
		}},
		{"public mode with CGNAT resolver", func(_ *drivers.BuildIdentity, _ *[]drivers.ComponentPlan, p *ProtectedPolicy) {
			p.Mode, p.ResolverIP, p.ResolverServerName = EgressPublicOnly, "100.64.0.1", "one.one.one.one"
		}},
		{"public mode with IPv6 documentation resolver", func(_ *drivers.BuildIdentity, _ *[]drivers.ComponentPlan, p *ProtectedPolicy) {
			p.Mode, p.ResolverIP, p.ResolverServerName = EgressPublicOnly, "2001:db8::1", "one.one.one.one"
		}},
		{"resolver with invalid SNI", func(_ *drivers.BuildIdentity, _ *[]drivers.ComponentPlan, p *ProtectedPolicy) {
			p.Mode, p.ResolverIP, p.ResolverServerName = EgressPublicOnly, "1.1.1.1", "127.0.0.1"
		}},
		{"resolver with endpoint URL instead of IP", func(_ *drivers.BuildIdentity, _ *[]drivers.ComponentPlan, p *ProtectedPolicy) {
			p.Mode, p.ResolverIP, p.ResolverServerName = EgressPublicOnly, "https://one.one.one.one", "one.one.one.one"
		}},
		{"unchecked revision decision", func(_ *drivers.BuildIdentity, p *[]drivers.ComponentPlan, _ *ProtectedPolicy) {
			(*p)[0].Revision.Decision = ""
		}},
		{"wrong base policy", func(_ *drivers.BuildIdentity, p *[]drivers.ComponentPlan, _ *ProtectedPolicy) {
			(*p)[0].Revision.Manifest.BaseEgressPolicy = "allow-all"
		}},
		{"zero structural sequence", func(_ *drivers.BuildIdentity, p *[]drivers.ComponentPlan, _ *ProtectedPolicy) {
			(*p)[0].Revision.Manifest.StructuralSequence = 0
		}},
		{"missing manifest component", func(_ *drivers.BuildIdentity, p *[]drivers.ComponentPlan, _ *ProtectedPolicy) {
			(*p)[0].Revision.Manifest.Components = nil
		}},
		{"duplicate plan", func(_ *drivers.BuildIdentity, p *[]drivers.ComponentPlan, _ *ProtectedPolicy) {
			*p = append(*p, (*p)[0])
		}},
		{"reserved inbound tag", func(_ *drivers.BuildIdentity, p *[]drivers.ComponentPlan, _ *ProtectedPolicy) {
			(*p)[0].ComponentID = "omni-public"
			(*p)[0].Revision.Manifest.Components[0].ID = "omni-public"
		}},
		{"unexpected uncompiled component", func(_ *drivers.BuildIdentity, p *[]drivers.ComponentPlan, _ *ProtectedPolicy) {
			extra := (*p)[0].Revision.Manifest.Components[0]
			extra.ID = "uncompiled"
			(*p)[0].Revision.Manifest.Components = append((*p)[0].Revision.Manifest.Components, extra)
		}},
		{"changed listener", func(_ *drivers.BuildIdentity, p *[]drivers.ComponentPlan, _ *ProtectedPolicy) {
			(*p)[0].Reality.Listen.Port = 24445
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			build, plan := compiledTestPlan()
			plans := []drivers.ComponentPlan{plan}
			policy := ProtectedPolicy{}
			tc.change(&build, &plans, &policy)
			if _, err := CompileFull(context.Background(), plans, policy, build); err == nil {
				t.Fatal("unverified compiler input unexpectedly accepted")
			}
		})
	}
}

func TestFullConfigRejectsListenerPortCollisionsAndMixedRevisions(t *testing.T) {
	build, first := compiledTestPlan()
	secondComponent := first.Revision.Manifest.Components[0]
	secondComponent.ID = "secondary"
	secondComponent.ConfigurationRef = "secondary-config"
	first.Revision.Manifest.Components = append(first.Revision.Manifest.Components, secondComponent)
	second := first
	second.ComponentID = "secondary"
	other := *first.Reality
	other.Users = []drivers.Principal{{ID: "user-four", UUID: "53da4424-08ee-4590-9d25-939ad250eab1"}}
	second.Reality = &other
	if _, err := CompileFull(context.Background(), []drivers.ComponentPlan{first, second}, ProtectedPolicy{}, build); err == nil {
		t.Fatal("same listening port in two components unexpectedly accepted")
	}
	second.Reality.Listen.Port = 24444
	second.Revision.Manifest.Components[1].Listeners[0].Port = 24444
	second.Revision.Digest = strings.Repeat("d", 64)
	if _, err := CompileFull(context.Background(), []drivers.ComponentPlan{first, second}, ProtectedPolicy{}, build); err == nil {
		t.Fatal("mixed verified generations unexpectedly compiled into one artifact")
	}
}

func TestFullConfigCancelledAndNilContextsCannotCompile(t *testing.T) {
	build, plan := compiledTestPlan()
	if _, err := CompileFull(nil, []drivers.ComponentPlan{plan}, ProtectedPolicy{}, build); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CompileFull(ctx, []drivers.ComponentPlan{plan}, ProtectedPolicy{}, build); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled compilation returned %v", err)
	}
}

func TestFullConfigNeverExposesRuntimePrivateKeyInValidationErrors(t *testing.T) {
	build, plan := compiledTestPlan()
	private := plan.Reality.PrivateKey
	plan.Reality.Listen.Port = 0
	_, err := CompileFull(context.Background(), []drivers.ComponentPlan{plan}, ProtectedPolicy{}, build)
	if err == nil || strings.Contains(err.Error(), private) {
		t.Fatalf("validation must fail without leaking Reality private key: %v", err)
	}
}

// Executed only by the signed native CI workflow. Never commit the generated
// credential-bearing file or print it to workflow output.
func TestEmitFullConfigForPinnedNativeSingBoxCheck(t *testing.T) {
	path := os.Getenv("OMNI_NATIVE_FULL_CONFIG_OUTPUT")
	key := os.Getenv("OMNI_NATIVE_REALITY_KEY")
	if path == "" && key == "" {
		t.Skip("native-only fixture, executed by the pinned Sing-box runtime workflow")
	}
	if path == "" || key == "" {
		t.Fatal("native full-config output and Reality key must be supplied together")
	}
	build, plan := compiledTestPlan()
	plan.Reality.PrivateKey = key
	policy := ProtectedPolicy{
		Mode: EgressPublicOnly,
		ResolverIP: "1.1.1.1",
		ResolverServerName: "one.one.one.one",
	}
	artifact, err := CompileFull(context.Background(), []drivers.ComponentPlan{plan}, policy, build)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, artifact.Content, 0o600); err != nil {
		t.Fatal("cannot write private native test fixture")
	}
}
