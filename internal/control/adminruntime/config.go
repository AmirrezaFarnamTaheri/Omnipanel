// Package adminruntime validates file-backed secrets, exact signer trust, and
// independent database identities before an admin approval service may start.
// It does not sign manifests or authorize an operator action.
package adminruntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maxConfigBytes = 32 << 10
	maxTrustBytes  = 64 << 10
	maxSecretBytes = 16 << 10
	maxCertBytes   = 64 << 10
)

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Config struct {
	Listen         string `json:"listen"`
	Origin         string `json:"origin"`
	TLSCertFile    string `json:"tlsCertFile"`
	TLSKeyFile     string `json:"tlsKeyFile"`
	CSRFKeyFile    string `json:"csrfKeyFile"`
	TrustFile      string `json:"trustFile"`
	SessionDSNFile string `json:"sessionDSNFile"`
	ProposeDSNFile string `json:"proposeDSNFile"`
	ReviewDSNFile  string `json:"reviewDSNFile"`
}

type Trust struct {
	AuthorizedEpoch     string            `json:"authorizedEpoch"`
	Signers             map[string]string `json:"signers"` // raw URL-safe base64 Ed25519 public keys
	Capabilities        []string          `json:"capabilities"`
	Builds              map[string]Build  `json:"builds"`
	MaxClockSkewSeconds int               `json:"maxClockSkewSeconds"`
}

type Build struct {
	Driver         string   `json:"driver"`
	Version        string   `json:"version"`
	ArtifactDigest string   `json:"artifactDigest"`
	Capabilities   []string `json:"capabilities"`
}

type Loaded struct {
	Config  Config
	Trust   Trust
	TLSCert tls.Certificate
	CSRFKey []byte
	DSNs    map[string]*url.URL // never log, serialize or embed these URLs in errors
}

// Load refuses ambient environment credentials, database-controlled signer
// trust, plaintext DB transport and privileges shared between roles.
func Load(path string) (Loaded, error) {
	raw, err := readFile(path, maxConfigBytes, true)
	if err != nil {
		return Loaded{}, fmt.Errorf("read admin runtime configuration: %w", err)
	}
	var cfg Config
	if err := strictJSON(raw, &cfg); err != nil {
		return Loaded{}, fmt.Errorf("invalid runtime configuration: %w", err)
	}
	if err := validateOriginAndListen(cfg.Origin, cfg.Listen); err != nil {
		return Loaded{}, err
	}
	trustRaw, err := readFile(cfg.TrustFile, maxTrustBytes, true)
	if err != nil {
		return Loaded{}, fmt.Errorf("read separately protected trust file: %w", err)
	}
	var trust Trust
	if err := strictJSON(trustRaw, &trust); err != nil {
		return Loaded{}, fmt.Errorf("invalid protected trust file: %w", err)
	}
	if err := validateTrust(trust); err != nil {
		return Loaded{}, err
	}

	csrf, err := readFile(cfg.CSRFKeyFile, maxSecretBytes, true)
	if err != nil {
		return Loaded{}, fmt.Errorf("read CSRF key: %w", err)
	}
	if len(csrf) < 32 {
		return Loaded{}, errors.New("CSRF key must contain at least 256 bits")
	}
	certData, err := readFile(cfg.TLSCertFile, maxCertBytes, false)
	if err != nil {
		return Loaded{}, fmt.Errorf("read server certificate: %w", err)
	}
	privateKey, err := readFile(cfg.TLSKeyFile, maxSecretBytes, true)
	if err != nil {
		return Loaded{}, fmt.Errorf("read TLS private key: %w", err)
	}
	cert, err := tls.X509KeyPair(certData, privateKey)
	if err != nil {
		return Loaded{}, errors.New("invalid server TLS certificate/private-key pair")
	}
	u, _ := url.Parse(cfg.Origin) // validated above
	if cert.Leaf == nil || time.Now().Before(cert.Leaf.NotBefore) || !time.Now().Before(cert.Leaf.NotAfter) || cert.Leaf.VerifyHostname(u.Hostname()) != nil {
		return Loaded{}, errors.New("server TLS certificate must be currently valid for exact configured origin")
	}
	dbFiles := map[string]string{"session": cfg.SessionDSNFile, "propose": cfg.ProposeDSNFile, "review": cfg.ReviewDSNFile}
	dsns := make(map[string]*url.URL, len(dbFiles))
	seenRoles := make(map[string]bool, len(dbFiles))
	for _, role := range []string{"session", "propose", "review"} {
		data, err := readFile(dbFiles[role], maxSecretBytes, true)
		if err != nil {
			return Loaded{}, fmt.Errorf("read %s database credential: %w", role, err)
		}
		uri, name, err := validatePostgresDSN(strings.TrimSpace(string(data)))
		if err != nil {
			return Loaded{}, fmt.Errorf("unsafe %s database connection configuration: %w", role, err)
		}
		if seenRoles[name] {
			return Loaded{}, errors.New("administrator DB accounts must use three distinct, nonprivileged roles")
		}
		seenRoles[name] = true
		dsns[role] = uri
	}
	return Loaded{Config: cfg, Trust: trust, TLSCert: cert, CSRFKey: csrf, DSNs: dsns}, nil
}

func validateOriginAndListen(origin, listen string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || u.String() != origin {
		return errors.New("administrator origin must be exact HTTPS authority")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return errors.New("administrator listener must be a loopback address with explicit port")
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || n < 1 || n > 65535 {
		return errors.New("administrator listener must bind explicitly to loopback")
	}
	return nil
}

func validateTrust(t Trust) error {
	if !uuidPattern.MatchString(t.AuthorizedEpoch) || len(t.Signers) == 0 || len(t.Capabilities) == 0 || len(t.Builds) == 0 || t.MaxClockSkewSeconds < 0 || t.MaxClockSkewSeconds > 60 {
		return errors.New("missing or unsafe independently provisioned signer/epoch/build trust")
	}
	for name, key := range t.Signers {
		k, err := base64.RawURLEncoding.DecodeString(key)
		if !identifierPattern.MatchString(name) || err != nil || len(k) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(k) != key {
			return errors.New("malformed independently provisioned Ed25519 signer")
		}
	}
	allowed := make(map[string]bool, len(t.Capabilities))
	for _, c := range t.Capabilities {
		if !identifierPattern.MatchString(c) || allowed[c] {
			return errors.New("invalid or duplicate approved capability")
		}
		allowed[c] = true
	}
	for id, build := range t.Builds {
		if !identifierPattern.MatchString(id) || build.Driver != id || build.Version == "" || !digestPattern.MatchString(build.ArtifactDigest) || len(build.Capabilities) == 0 {
			return errors.New("unqualified exact runtime build")
		}
		for _, capability := range build.Capabilities {
			if !allowed[capability] {
				return errors.New("build capability missing from independent allowlist")
			}
		}
	}
	return nil
}

func validatePostgresDSN(text string) (*url.URL, string, error) {
	u, err := url.Parse(text)
	if err != nil || u == nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.User == nil || u.Fragment != "" || u.Opaque != "" || u.Path == "" {
		return nil, "", errors.New("PostgreSQL URI with explicit user, password, database and host required")
	}
	name := u.User.Username()
	password, ok := u.User.Password()
	if !ok || password == "" || !pgRolePattern.MatchString(name) || name == "postgres" || name == "root" || name == "admin" {
		return nil, "", errors.New("dedicated non-superuser PostgreSQL account required")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) != 2 || len(query["sslmode"]) != 1 || query.Get("sslmode") != "verify-full" || len(query["sslrootcert"]) != 1 || query.Get("sslrootcert") == "" {
		return nil, "", errors.New("PostgreSQL TLS verify-full and explicit trust root required")
	}
	pemBytes, err := readFile(query.Get("sslrootcert"), maxCertBytes, true)
	if err != nil {
		return nil, "", errors.New("PostgreSQL trust-root certificate must exist as a regular file")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, "", errors.New("PostgreSQL TLS trust root must contain PEM certificates")
	}
	return u, name, nil
}

// readFile avoids symlink traversal, rejects ambient/redistributed secrets,
// enforces ownership and mode, and bounds reads before decoding JSON or keys.
func readFile(path string, max int, secret bool) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || max <= 0 {
		return nil, errors.New("absolute, bounded file path required")
	}
	fd, err := openNoSymlink(path)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > int64(max) {
		return nil, errors.New("invalid file type or length")
	}
	if secret {
		ownership, ok := st.Sys().(*syscall.Stat_t)
		if !ok || int(ownership.Uid) != os.Geteuid() || st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("secret file requires owner-only permissions and process ownership")
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(data) == 0 || len(data) > max {
		return nil, errors.New("file outside permitted length")
	}
	return data, nil
}

// strictJSON rejects duplicate keys at ANY depth, unknown typed fields and
// trailing input; security configuration cannot depend on last-key-wins JSON.
func strictJSON(data []byte, value any) error {
	if err := rejectDuplicates(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := d.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}

func rejectDuplicates(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON exceeds permitted nesting depth")
		}
		t, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				name, ok := k.(string)
				if !ok || seen[name] {
					return errors.New("duplicate or malformed JSON key")
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("unterminated JSON object")
			}
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("unterminated JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

// openNoSymlink walks every path component relative to an already-opened
// directory. O_NOFOLLOW on the leaf alone does not protect parent directories.
// Reject ambiguous paths rather than resolving them through ambient symlinks.
func openNoSymlink(path string) (int, error) {
	if !strings.HasPrefix(path, "/") {
		return -1, errors.New("absolute path required")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 {
		return -1, errors.New("missing file")
	}
	dirFD, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer func() { _ = syscall.Close(dirFD) }()
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return -1, errors.New("non-canonical file path")
		}
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(dirFD, part, flags, 0)
		if err != nil {
			return -1, err
		}
		if i == len(parts)-1 {
			return next, nil
		}
		_ = syscall.Close(dirFD)
		dirFD = next
	}
	return -1, errors.New("missing file")
}
