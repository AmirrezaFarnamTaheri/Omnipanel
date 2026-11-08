// Package singbox compiles only a bounded, previously verified Reality/Vision
// component set into a complete native configuration. This package does NOT
// authorize application, serve traffic, or qualify external network policy.
package singbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"sort"
	"strings"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

const (
	// Only this exact native runtime has a reviewed route-rule schema.
	fullConfigRuntimeVersion = "1.14.4+omni.2"
	fullConfigFormat         = "singbox/full-config+json"
	maxFullConfigBytes       = 2 << 20
	maxFullConfigComponents  = 16

	fullConfigBlockTag  = "omni-block"
	fullConfigPublicTag = "omni-public"
	fullConfigDNSTag    = "omni-dns"
)

// EgressMode controls the shape of an unprivileged config artifact; it does
// not authorize the root supervisor to deploy it.
type EgressMode string

const (
	// EgressBlockAll is the default. No DNS resolver or direct outbound exists.
	EgressBlockAll EgressMode = "block-all"
	// EgressPublicOnly requires a separately trusted, public, TLS-authenticated
	// DNS resolver. Its security is not externally qualified until the native
	// reference-client routing and DNS-rebinding tests pass.
	EgressPublicOnly EgressMode = "public-only"
)

// ProtectedPolicy MUST come from locally approved operator policy, never from
// fields in the signed desired-state manifest or an unauthenticated API.
type ProtectedPolicy struct {
	Mode               EgressMode
	ResolverIP         string
	ResolverServerName string
}

var ErrFullConfigRejected = errors.New("sing-box full config is unverified or unsafe")

// Protected ranges include the private and metadata networks plus shared,
// reserved, translation and documentation addresses. IPv4-mapped IPv6 and
// NAT64 are deliberately denied to prevent alternate-address bypasses.
var protectedDestinationPrefixes = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"::ffff:0:0/96",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// approvedResolver reports false for all literal private, loopback, link-local,
// non-unicast, mapped, shared, reserved, tunnel and documentation addresses.
func approvedResolver(raw string) bool {
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" || addr.Is4In6() ||
		!addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, cidr := range protectedDestinationPrefixes {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func validatedPolicy(p ProtectedPolicy) (EgressMode, error) {
	mode := p.Mode
	if mode == "" {
		mode = EgressBlockAll
	}
	switch mode {
	case EgressBlockAll:
		if p.ResolverIP != "" || p.ResolverServerName != "" {
			return "", ErrFullConfigRejected
		}
	case EgressPublicOnly:
		if !approvedResolver(p.ResolverIP) ||
			len(p.ResolverServerName) > 253 ||
			!strings.Contains(p.ResolverServerName, ".") ||
			!serverNamePattern.MatchString(p.ResolverServerName) ||
			isIPLiteral(p.ResolverServerName) {
			return "", ErrFullConfigRejected
		}
	default:
		return "", ErrFullConfigRejected
	}
	return mode, nil
}

// CompileFull composes only typed Reality components belonging to the SAME
// already-verified manifest and exact locally approved runtime. Each component
// configurationDigest must equal the deterministic inbound fragment digest,
// binding the manifest's signed configuration identity to the secret-bearing
// bytes compiled here. The independent manifest verifier owns signature trust.
//
// A successful return is a deterministic FULL CONFIG ARTIFACT ONLY, not native
// validation, deployment, positive policy-evasion proof or applied ACK.
func CompileFull(ctx context.Context, plans []drivers.ComponentPlan, policy ProtectedPolicy, build drivers.BuildIdentity) (drivers.ConfigArtifact, error) {
	if ctx == nil {
		return drivers.ConfigArtifact{}, ErrFullConfigRejected
	}
	if err := ctx.Err(); err != nil {
		return drivers.ConfigArtifact{}, err
	}
	if len(plans) == 0 || len(plans) > maxFullConfigComponents ||
		build.Runtime != "singbox" || build.Version != fullConfigRuntimeVersion ||
		!digestPattern.MatchString(build.ArtifactDigest) {
		return drivers.ConfigArtifact{}, ErrFullConfigRejected
	}
	mode, err := validatedPolicy(policy)
	if err != nil {
		return drivers.ConfigArtifact{}, err
	}
	revision := plans[0].Revision
	m := revision.Manifest
	if (revision.Decision != manifest.ApplyRevision && revision.Decision != manifest.AlreadyApplied) ||
		!digestPattern.MatchString(revision.Digest) || m.StructuralSequence == 0 ||
		!uuidPattern.MatchString(m.NodeID) || !uuidPattern.MatchString(m.ControlPlaneEpoch) ||
		m.SchemaVersion != "2.0" || m.BaseEgressPolicy != "deny-protected-v1" ||
		len(m.Components) != len(plans) {
		return drivers.ConfigArtifact{}, ErrFullConfigRejected
	}
	adapter, err := New(build)
	if err != nil {
		return drivers.ConfigArtifact{}, ErrFullConfigRejected
	}
	components := make(map[string]manifest.Component, len(m.Components))
	for _, component := range m.Components {
		if component.ID == fullConfigBlockTag || component.ID == fullConfigPublicTag || component.ID == fullConfigDNSTag ||
			!principalPattern.MatchString(component.ID) || !digestPattern.MatchString(component.ConfigurationDigest) {
			return drivers.ConfigArtifact{}, ErrFullConfigRejected
		}
		if _, repeated := components[component.ID]; repeated {
			return drivers.ConfigArtifact{}, ErrFullConfigRejected
		}
		components[component.ID] = component
	}
	inbounds := make([]inbound, 0, len(plans))
	listeningPorts := make(map[uint16]bool, len(plans))
	seen := make(map[string]bool, len(plans))
	for _, plan := range plans {
		if err := ctx.Err(); err != nil {
			return drivers.ConfigArtifact{}, err
		}
		if !reflect.DeepEqual(revision, plan.Revision) || seen[plan.ComponentID] {
			return drivers.ConfigArtifact{}, ErrFullConfigRejected
		}
		seen[plan.ComponentID] = true
		component, ok := components[plan.ComponentID]
		if !ok || plan.Reality == nil || listeningPorts[plan.Reality.Listen.Port] {
			return drivers.ConfigArtifact{}, ErrFullConfigRejected
		}
		listeningPorts[plan.Reality.Listen.Port] = true
		fragment, err := adapter.Render(ctx, plan)
		if err != nil || fragment.Format != artifactFormat ||
			fragment.SHA256 != component.ConfigurationDigest || !fragment.ContainsSecrets {
			return drivers.ConfigArtifact{}, ErrFullConfigRejected
		}
		var decoded inboundFragment
		decoder := json.NewDecoder(bytes.NewReader(fragment.Content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&decoded); err != nil || len(decoded.Inbounds) != 1 ||
			decoded.Inbounds[0].Tag != plan.ComponentID {
			return drivers.ConfigArtifact{}, ErrFullConfigRejected
		}
		if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
			return drivers.ConfigArtifact{}, ErrFullConfigRejected
		}
		inbounds = append(inbounds, decoded.Inbounds[0])
	}
	sort.Slice(inbounds, func(i, j int) bool { return inbounds[i].Tag < inbounds[j].Tag })

	document := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"inbounds":  inbounds,
		"outbounds": []map[string]any{{"type": "block", "tag": fullConfigBlockTag}},
		"route":     map[string]any{"final": fullConfigBlockTag},
	}
	if mode == EgressPublicOnly {
		blocked := append([]string(nil), protectedDestinationPrefixes...)
		sort.Strings(blocked)
		document["dns"] = map[string]any{
			"servers": []map[string]any{{
				"type": "tls", "tag": fullConfigDNSTag,
				"server": policy.ResolverIP, "server_port": 853,
				"tls": map[string]any{"enabled": true, "server_name": policy.ResolverServerName},
			}},
			"rules": []map[string]any{
				{"domain_suffix": []string{"home.arpa", "internal", "invalid", "lan", "local", "localdomain", "localhost", "test"}, "action": "reject"},
				{"domain": []string{"metadata", "metadata.google.internal"}, "action": "reject"},
			},
			"final": fullConfigDNSTag,
		}
		document["outbounds"] = []map[string]any{
			{"type": "block", "tag": fullConfigBlockTag},
			{"type": "direct", "tag": fullConfigPublicTag},
		}
		// Resolve first, then reject both native nonpublic classification and
		// explicit reserved CIDRs. No arbitrary caller-supplied route rules,
		// direct bypass, private exceptions, or implicit DNS fallbacks.
		document["route"] = map[string]any{
			"default_domain_resolver": fullConfigDNSTag,
			"rules": []map[string]any{
				{"port": []int{53}, "action": "hijack-dns"},
				{"port": []int{853, 5353, 5355}, "action": "reject"},
				{"action": "resolve", "server": fullConfigDNSTag},
				{"ip_is_private": true, "action": "reject"},
				{"ip_cidr": blocked, "action": "reject"},
			},
			"final": fullConfigPublicTag,
		}
	}
	if err := ctx.Err(); err != nil {
		return drivers.ConfigArtifact{}, err
	}
	content, err := json.MarshalIndent(document, "", "  ")
	if err != nil || len(content) == 0 || len(content) > maxFullConfigBytes {
		return drivers.ConfigArtifact{}, ErrFullConfigRejected
	}
	digest := sha256.Sum256(content)
	componentID := inbounds[0].Tag
	if len(inbounds) > 1 {
		componentID = "omni-runtime"
	}
	return drivers.ConfigArtifact{
		ComponentID:     componentID,
		Format:          fullConfigFormat,
		Content:         content,
		SHA256:          hex.EncodeToString(digest[:]),
		ContainsSecrets: true,
	}, nil
}
