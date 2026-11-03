package manifest

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)
	digestPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	uuidPattern       = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func validateManifest(m Manifest) error {
	if m.SchemaVersion != "2.0" || m.BaseEgressPolicy != "deny-protected-v1" {
		return errors.New("unsupported schema or protected-egress policy")
	}
	if !uuidPattern.MatchString(m.NodeID) || !uuidPattern.MatchString(m.ControlPlaneEpoch) {
		return errors.New("invalid node identity or epoch")
	}
	if m.StructuralSequence == 0 || m.StructuralSequence > maxSafeInteger || m.MembershipSequence > maxSafeInteger {
		return errors.New("sequence outside supported range")
	}
	issued, err := time.Parse(time.RFC3339Nano, m.IssuedAt)
	if err != nil {
		return errors.New("invalid issuedAt")
	}
	expires, err := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return errors.New("invalid expiry order")
	}
	if len(m.RequiredCapabilities) == 0 || len(m.RequiredCapabilities) > 64 {
		return errors.New("capability count invalid")
	}
	capabilities := map[string]bool{}
	for _, capability := range m.RequiredCapabilities {
		if !identifierPattern.MatchString(capability) || capabilities[capability] {
			return errors.New("invalid or repeated required capability")
		}
		capabilities[capability] = true
	}
	if len(m.Components) == 0 || len(m.Components) > 64 {
		return errors.New("component count invalid")
	}
	components := map[string]Component{}
	var listeners []Listener
	for _, c := range m.Components {
		if !identifierPattern.MatchString(c.ID) || components[c.ID].ID != "" {
			return errors.New("invalid or repeated component id")
		}
		if !identifierPattern.MatchString(c.ConfigurationRef) || !versionPattern.MatchString(c.RuntimeVersion) ||
			!digestPattern.MatchString(c.ArtifactDigest) || !digestPattern.MatchString(c.ConfigurationDigest) {
			return fmt.Errorf("invalid references or build for component %s", c.ID)
		}
		switch c.Driver {
		case "singbox", "hysteria2", "xray":
		default:
			return errors.New("unsupported runtime driver")
		}
		switch c.Disruption {
		case "hot", "reload", "listener_restart", "network":
		default:
			return errors.New("unsupported disruption classification")
		}
		if len(c.DependsOn) > 64 || len(c.Listeners) > 64 {
			return errors.New("component exceeds limits")
		}
		dependencies := map[string]bool{}
		for _, dep := range c.DependsOn {
			if !identifierPattern.MatchString(dep) || dependencies[dep] {
				return errors.New("invalid or repeated dependency")
			}
			dependencies[dep] = true
		}
		for _, l := range c.Listeners {
			if _, err := parsedListener(l); err != nil {
				return err
			}
			listeners = append(listeners, l)
		}
		components[c.ID] = c
	}
	visit := map[string]uint8{}
	var walk func(string) error
	walk = func(id string) error {
		if visit[id] == 1 {
			return errors.New("component dependency cycle")
		}
		if visit[id] == 2 {
			return nil
		}
		visit[id] = 1
		for _, dep := range components[id].DependsOn {
			if _, ok := components[dep]; !ok {
				return errors.New("unknown component dependency")
			}
			if err := walk(dep); err != nil {
				return err
			}
		}
		visit[id] = 2
		return nil
	}
	for id := range components {
		if err := walk(id); err != nil {
			return err
		}
	}
	for i, left := range listeners {
		for _, right := range listeners[i+1:] {
			if conflicts(left, right) {
				return errors.New("effective ingress socket conflict")
			}
		}
	}
	return nil
}

func parsedListener(l Listener) (netip.Addr, error) {
	ip, err := netip.ParseAddr(l.Address)
	if err != nil || ip.Zone() != "" || l.Port == 0 ||
		(l.Transport != "tcp" && l.Transport != "udp") ||
		(ip.Is4() && l.IPv6Only) || (ip.Is4In6() && l.IPv6Only) {
		return netip.Addr{}, errors.New("invalid listener address, port, transport or IPv6 policy")
	}
	return ip.Unmap(), nil
}

func conflicts(a, b Listener) bool {
	if a.Port != b.Port || a.Transport != b.Transport {
		return false
	}
	left, leftErr := parsedListener(a)
	right, rightErr := parsedListener(b)
	if leftErr != nil || rightErr != nil {
		return true
	}
	if left.Is4() == right.Is4() {
		return left.IsUnspecified() || right.IsUnspecified() || left == right
	}
	// Dual-stack unspecified IPv6 includes IPv4 unless IPV6_V6ONLY=1.
	return (left.Is6() && left.IsUnspecified() && !a.IPv6Only) ||
		(right.Is6() && right.IsUnspecified() && !b.IPv6Only)
}
