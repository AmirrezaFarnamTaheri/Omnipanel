// Package bootstrap loads node-local trust from protected POSIX files.
// A remote manifest cannot modify signer, build, TLS or journal authority.
package bootstrap

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

const maxBootstrapBytes = 64 << 10
const maxPrivatePEMBytes = 64 << 10

var (
	ErrInvalidBootstrap = errors.New("invalid protected node bootstrap configuration")
	identifier          = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{0,63}$`)
	capabilityName      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	uuid                = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digest              = regexp.MustCompile(`^[0-9a-f]{64}$`)
	version             = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:\+[a-zA-Z0-9._-]+)?$`)
)

// Config is provisioned out-of-band by a trusted node operator. Declaring a
// qualified build in a file is NOT evidence that external qualification ran.
// An installer must independently verify the build and approved signer first.
type Config struct {
	GatewayOrigin       string                    `json:"gatewayOrigin"`
	NodeID              string                    `json:"nodeId"`
	ControlPlaneEpoch   string                    `json:"controlPlaneEpoch"`
	JournalPath         string                    `json:"journalPath"`
	RootCAFile          string                    `json:"rootCAFile"`
	ClientCertFile      string                    `json:"clientCertFile"`
	ClientKeyFile       string                    `json:"clientKeyFile"`
	TrustedSigners      map[string]string         `json:"trustedSigners"`
	AllowedCapabilities []string                  `json:"allowedCapabilities"`
	QualifiedBuilds     map[string]manifest.Build `json:"qualifiedBuilds"`
	PollSeconds         int                       `json:"pollSeconds"`
	MaxClockSkewSeconds int                       `json:"maxClockSkewSeconds"`
}

// privateRead refuses symlinks, non-owner files and group/world access before
// reading a bounded amount. O_NOFOLLOW also protects the open race on the leaf.
func privateRead(path string, max int64) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrInvalidBootstrap
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0o077 != 0 || !ownedByCaller(dir) {
		return nil, ErrInvalidBootstrap
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidBootstrap
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByCaller(info) || info.Size() < 1 || info.Size() > max {
		return nil, ErrInvalidBootstrap
	}
	content, err := io.ReadAll(io.LimitReader(bufio.NewReader(file), max+1))
	if err != nil || len(content) == 0 || int64(len(content)) > max {
		return nil, ErrInvalidBootstrap
	}
	return content, nil
}

func ownedByCaller(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

// ReadPrivatePEM loads a node credential only from a protected local file.
// Parsing and certificate hostname/identity enforcement are done by gateway.New.
func ReadPrivatePEM(path string) ([]byte, error) {
	return privateRead(path, maxPrivatePEMBytes)
}

// Load refuses missing, unknown, repeated or trailing bootstrap JSON values.
func Load(path string) (Config, error) {
	raw, err := privateRead(path, maxBootstrapBytes)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, ErrInvalidBootstrap
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, ErrInvalidBootstrap
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func protectedPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexByte(path, 0) < 0
}

func (c Config) validate() error {
	u, err := url.Parse(c.GatewayOrigin)
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return ErrInvalidBootstrap
	}
	if !uuid.MatchString(c.NodeID) || !uuid.MatchString(c.ControlPlaneEpoch) || !protectedPath(c.JournalPath) ||
		!protectedPath(c.RootCAFile) || !protectedPath(c.ClientCertFile) || !protectedPath(c.ClientKeyFile) ||
		c.PollSeconds < 5 || c.PollSeconds > 3600 || c.MaxClockSkewSeconds < 0 || c.MaxClockSkewSeconds > 300 {
		return ErrInvalidBootstrap
	}
	if len(c.TrustedSigners) == 0 || len(c.TrustedSigners) > 16 || len(c.AllowedCapabilities) == 0 || len(c.AllowedCapabilities) > 32 || len(c.QualifiedBuilds) == 0 || len(c.QualifiedBuilds) > 16 {
		return ErrInvalidBootstrap
	}
	for id, key := range c.TrustedSigners {
		if !identifier.MatchString(id) {
			return ErrInvalidBootstrap
		}
		raw, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil || len(raw) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(raw) != key {
			return ErrInvalidBootstrap
		}
	}
	allowed := make(map[string]bool, len(c.AllowedCapabilities))
	for _, capability := range c.AllowedCapabilities {
		if !capabilityName.MatchString(capability) || allowed[capability] {
			return ErrInvalidBootstrap
		}
		allowed[capability] = true
	}
	qualified := make(map[string]bool)
	for driver, build := range c.QualifiedBuilds {
		if !capabilityName.MatchString(driver) || build.Driver != driver || !version.MatchString(build.Version) || !digest.MatchString(build.ArtifactDigest) || len(build.Capabilities) == 0 || len(build.Capabilities) > 32 {
			return ErrInvalidBootstrap
		}
		seen := map[string]bool{}
		for _, capability := range build.Capabilities {
			if !allowed[capability] || seen[capability] {
				return ErrInvalidBootstrap
			}
			seen[capability] = true
			qualified[capability] = true
		}
	}
	for capability := range allowed {
		if !qualified[capability] {
			return ErrInvalidBootstrap
		}
	}
	return nil
}

// Verifier returns defensive copies of the locally authorized Ed25519 signers
// and exact build identities; no remote input can add authority to this map.
func (c Config) Verifier() (manifest.Verifier, error) {
	if err := c.validate(); err != nil {
		return manifest.Verifier{}, err
	}
	v := manifest.Verifier{
		NodeID: c.NodeID, AuthorizedEpoch: c.ControlPlaneEpoch,
		TrustedSigners:      make(map[string]ed25519.PublicKey, len(c.TrustedSigners)),
		AllowedCapabilities: make(map[string]bool, len(c.AllowedCapabilities)),
		QualifiedBuilds:     make(map[string]manifest.Build, len(c.QualifiedBuilds)),
		MaxClockSkew:        time.Duration(c.MaxClockSkewSeconds) * time.Second,
	}
	for id, encoded := range c.TrustedSigners {
		key, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return manifest.Verifier{}, fmt.Errorf("%w: signer", ErrInvalidBootstrap)
		}
		v.TrustedSigners[id] = append(ed25519.PublicKey(nil), key...)
	}
	for _, capability := range c.AllowedCapabilities {
		v.AllowedCapabilities[capability] = true
	}
	for id, b := range c.QualifiedBuilds {
		b.Capabilities = append([]string(nil), b.Capabilities...)
		v.QualifiedBuilds[id] = b
	}
	return v, nil
}
