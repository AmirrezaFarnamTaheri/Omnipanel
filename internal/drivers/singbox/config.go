// Package singbox renders a bounded VLESS/Reality inbound fragment. It does not
// install binaries, apply configurations or claim native runtime validation.
package singbox

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

const protocolCapability = "singbox-reality-vision"
const artifactFormat = "singbox/inbound-fragment+json"
const visionFlow = "xtls-rprx-vision"

var (
	buildVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:\+[a-zA-Z0-9._-]+)?$`)
	digestPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	principalPattern    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	uuidPattern         = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	shortIDPattern      = regexp.MustCompile(`^(?:[a-f0-9]{2}){1,8}$`)
	namePattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type Adapter struct {
	drivers.Unsupported
	build drivers.BuildIdentity
}

var _ drivers.Driver = (*Adapter)(nil)

// New requires the exact build identity from an independently reviewed local
// registry. Its constructor is not evidence that the build has been qualified.
func New(build drivers.BuildIdentity) (*Adapter, error) {
	if build.Runtime != "singbox" || !buildVersionPattern.MatchString(build.Version) || !digestPattern.MatchString(build.ArtifactDigest) {
		return nil, errors.New("invalid exact Sing-box build identity")
	}
	return &Adapter{Unsupported: drivers.Unsupported{Runtime: "singbox"}, build: build}, nil
}

func (d *Adapter) Capabilities(ctx context.Context, build drivers.BuildIdentity) (drivers.CapabilitySet, error) {
	if err := ctx.Err(); err != nil {
		return drivers.CapabilitySet{}, err
	}
	if build != d.build {
		return drivers.CapabilitySet{}, errors.New("runtime build does not match approved identity")
	}
	return drivers.CapabilitySet{Operations: []string{"render_inbound_fragment"}}, nil
}

// Render emits a deterministic INBOUND FRAGMENT only. It intentionally has no
// route or outbound fields: composing protected egress, native validation and
// applying a structural revision remain separately gated operations.
func (d *Adapter) Render(ctx context.Context, plan drivers.ComponentPlan) (drivers.ConfigArtifact, error) {
	if err := ctx.Err(); err != nil {
		return drivers.ConfigArtifact{}, err
	}
	m := plan.Revision
	if (m.Decision != manifest.ApplyRevision && m.Decision != manifest.AlreadyApplied) || !digestPattern.MatchString(m.Digest) ||
		m.Manifest.SchemaVersion != "2.0" || m.Manifest.BaseEgressPolicy != "deny-protected-v1" ||
		plan.Capability != protocolCapability || plan.ComponentID == "" || plan.Reality == nil {
		return drivers.ConfigArtifact{}, errors.New("unverified or unsupported Reality component plan")
	}
	requested := false
	for _, c := range m.Manifest.RequiredCapabilities {
		if c == protocolCapability {
			requested = true
		}
	}
	if !requested {
		return drivers.ConfigArtifact{}, errors.New("Reality capability absent from verified manifest")
	}
	var component *manifest.Component
	for i := range m.Manifest.Components {
		if m.Manifest.Components[i].ID == plan.ComponentID {
			component = &m.Manifest.Components[i]
			break
		}
	}
	if component == nil || component.Driver != "singbox" || component.RuntimeVersion != d.build.Version || component.ArtifactDigest != d.build.ArtifactDigest ||
		!principalPattern.MatchString(component.ID) || !principalPattern.MatchString(component.ConfigurationRef) || len(component.Listeners) != 1 ||
		component.Listeners[0] != plan.Reality.Listen {
		return drivers.ConfigArtifact{}, errors.New("component build, reference or listener differs from verified manifest")
	}
	in := plan.Reality
	listener := in.Listen
	addr, err := netip.ParseAddr(listener.Address)
	if err != nil || addr.Zone() != "" || listener.Port == 0 || listener.Transport != "tcp" || listener.IPv6Only && addr.Is4() {
		return drivers.ConfigArtifact{}, errors.New("invalid TCP listening socket")
	}
	if in.HandshakePort == 0 || !namePattern.MatchString(in.HandshakeServer) && !isIPLiteral(in.HandshakeServer) {
		return drivers.ConfigArtifact{}, errors.New("invalid Reality handshake destination")
	}
	key, err := base64.RawURLEncoding.DecodeString(in.PrivateKey)
	if err != nil || len(in.PrivateKey) != 43 || len(key) != 32 {
		return drivers.ConfigArtifact{}, errors.New("invalid Reality key encoding")
	}
	if len(in.ShortIDs) == 0 || len(in.ShortIDs) > 8 || len(in.Users) == 0 || len(in.Users) > 2048 {
		return drivers.ConfigArtifact{}, errors.New("Reality short ID or user count outside limits")
	}
	ids := make([]string, len(in.ShortIDs))
	copy(ids, in.ShortIDs)
	seenShortIDs := make(map[string]bool, len(ids))
	for _, s := range ids {
		if !shortIDPattern.MatchString(s) || seenShortIDs[s] {
			return drivers.ConfigArtifact{}, errors.New("invalid or duplicate Reality short ID")
		}
		seenShortIDs[s] = true
	}
	sort.Strings(ids)
	users := make([]inboundUser, 0, len(in.Users))
	seenNames, seenUUIDs := map[string]bool{}, map[string]bool{}
	for _, u := range in.Users {
		if !principalPattern.MatchString(u.ID) || !uuidPattern.MatchString(u.UUID) || seenNames[u.ID] || seenUUIDs[u.UUID] {
			return drivers.ConfigArtifact{}, errors.New("invalid or repeated endpoint principal")
		}
		seenNames[u.ID], seenUUIDs[u.UUID] = true, true
		users = append(users, inboundUser{Name: u.ID, UUID: u.UUID, Flow: visionFlow})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	fragment := inboundFragment{Inbounds: []inbound{{
		Type: "vless", Tag: component.ID, Listen: listener.Address, ListenPort: listener.Port, Users: users,
		TLS: inboundTLS{Enabled: true, Reality: realitySettings{Enabled: true, Handshake: handshake{Server: in.HandshakeServer, ServerPort: in.HandshakePort}, PrivateKey: in.PrivateKey, ShortIDs: ids}},
	}}}
	content, err := json.MarshalIndent(fragment, "", "  ")
	if err != nil {
		return drivers.ConfigArtifact{}, fmt.Errorf("encode Reality inbound: %w", err)
	}
	digest := sha256.Sum256(content)
	return drivers.ConfigArtifact{ComponentID: component.ID, Format: artifactFormat, Content: content, SHA256: hex.EncodeToString(digest[:]), ContainsSecrets: true}, nil
}

func isIPLiteral(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Zone() == ""
}

type inboundFragment struct {
	Inbounds []inbound `json:"inbounds"`
}
type inbound struct {
	Type       string        `json:"type"`
	Tag        string        `json:"tag"`
	Listen     string        `json:"listen"`
	ListenPort uint16        `json:"listen_port"`
	Users      []inboundUser `json:"users"`
	TLS        inboundTLS    `json:"tls"`
}
type inboundUser struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Flow string `json:"flow"`
}
type inboundTLS struct {
	Enabled bool            `json:"enabled"`
	Reality realitySettings `json:"reality"`
}
type realitySettings struct {
	Enabled    bool      `json:"enabled"`
	Handshake  handshake `json:"handshake"`
	PrivateKey string    `json:"private_key"`
	ShortIDs   []string  `json:"short_id"`
}
type handshake struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}
