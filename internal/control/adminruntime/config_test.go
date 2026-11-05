package adminruntime

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func secretFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if e := os.WriteFile(p, data, 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func certFixture(t *testing.T, dir, hostname string) (string, string) {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{hostname}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, e := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if e != nil {
		t.Fatal(e)
	}
	b, e := x509.MarshalPKCS8PrivateKey(priv)
	if e != nil {
		t.Fatal(e)
	}
	certPath := secretFile(t, dir, "tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
	keyPath := secretFile(t, dir, "tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
	return certPath, keyPath
}
func validFixture(t *testing.T) (string, Config) {
	t.Helper()
	d := t.TempDir()
	cert, key := certFixture(t, d, "admin.omnipanel.test")
	certPEM, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	ca := secretFile(t, d, "postgres-ca.pem", certPEM)
	makeDSN := func(role string) string {
		q := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {ca}}
		return "postgresql://" + role + ":password@db.omnipanel.test/omnipanel?" + q.Encode()
	}
	priv := ed25519.NewKeyFromSeed([]byte(strings.Repeat("K", 32)))
	pub := priv.Public().(ed25519.PublicKey)
	trust := Trust{AuthorizedEpoch: "ea2429da-7540-4e40-ae70-38fd3f19794b", Signers: map[string]string{"signer-1": base64.RawURLEncoding.EncodeToString(pub)}, Capabilities: []string{"singbox-reality-vision"}, Builds: map[string]Build{"singbox": {Driver: "singbox", Version: "1.14.4+omni.2", ArtifactDigest: strings.Repeat("a", 64), Capabilities: []string{"singbox-reality-vision"}}}, MaxClockSkewSeconds: 5}
	cfg := Config{Listen: "127.0.0.1:8443", Origin: "https://admin.omnipanel.test", TLSCertFile: cert, TLSKeyFile: key, CSRFKeyFile: secretFile(t, d, "csrf.key", []byte(strings.Repeat("Q", 32))), TrustFile: secretFile(t, d, "trust.json", mustJSON(t, trust)), SessionDSNFile: secretFile(t, d, "session.dsn", []byte(makeDSN("omni_session"))), ProposeDSNFile: secretFile(t, d, "proposal.dsn", []byte(makeDSN("omni_proposer"))), ReviewDSNFile: secretFile(t, d, "review.dsn", []byte(makeDSN("omni_reviewer")))}
	return secretFile(t, d, "admin.json", mustJSON(t, cfg)), cfg
}
func TestLoadProtectedRuntimeConfiguration(t *testing.T) {
	path, _ := validFixture(t)
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if c.Config.Listen != "127.0.0.1:8443" || len(c.CSRFKey) != 32 || len(c.TLSCert.Certificate) == 0 || len(c.Trust.Signers) != 1 || len(c.DSNs) != 3 {
		t.Fatalf("incomplete secure config %+v", c.Config)
	}
	if c.DSNs["session"].User.Username() == c.DSNs["propose"].User.Username() || c.DSNs["review"].User.Username() == c.DSNs["propose"].User.Username() {
		t.Fatal("DB role separation absent")
	}
	if c.TLSCert.Leaf == nil || c.TLSCert.Leaf.VerifyHostname("admin.omnipanel.test") != nil {
		t.Fatal("server TLS certificate not bound to origin")
	}
	_ = tls.VersionTLS13
}
func TestRejectUnsafeSecretPermissionsAndSymlinks(t *testing.T) {
	path, cfg := validFixture(t)
	if e := os.Chmod(cfg.CSRFKeyFile, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(path); e == nil {
		t.Fatal("world-readable CSRF key admitted")
	}
	if e := os.Chmod(cfg.CSRFKeyFile, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(filepath.Dir(path), "secret-link")
	if e := os.Symlink(cfg.CSRFKeyFile, link); e != nil {
		t.Fatal(e)
	}
	cfg.CSRFKeyFile = link
	if e := os.WriteFile(path, mustJSON(t, cfg), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(path); e == nil {
		t.Fatal("symlink to secret accepted")
	}
}
func TestRejectUnsafeDSNAndRoleOverlap(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, cfg *Config)
	}{
		{"same roles", func(t *testing.T, c *Config) { c.ReviewDSNFile = c.ProposeDSNFile }},
		{"postgres superuser", func(t *testing.T, c *Config) {
			s, _ := os.ReadFile(c.ProposeDSNFile)
			os.WriteFile(c.ProposeDSNFile, []byte(strings.Replace(string(s), "omni_proposer", "postgres", 1)), 0600)
		}},
		{"ssl downgrade", func(t *testing.T, c *Config) {
			s, _ := os.ReadFile(c.SessionDSNFile)
			os.WriteFile(c.SessionDSNFile, []byte(strings.Replace(string(s), "verify-full", "disable", 1)), 0600)
		}},
		{"missing CA", func(t *testing.T, c *Config) {
			s, _ := os.ReadFile(c.SessionDSNFile)
			u, _ := url.Parse(string(s))
			q := u.Query()
			q.Del("sslrootcert")
			u.RawQuery = q.Encode()
			os.WriteFile(c.SessionDSNFile, []byte(u.String()), 0600)
		}},
		{"unreadable CA file", func(t *testing.T, c *Config) {
			s, _ := os.ReadFile(c.SessionDSNFile)
			u, _ := url.Parse(string(s))
			q := u.Query()
			q.Set("sslrootcert", "/tmp/omnipanel-missing-ca-file-for-test.pem")
			u.RawQuery = q.Encode()
			os.WriteFile(c.SessionDSNFile, []byte(u.String()), 0600)
		}},
		{"non-loopback bind", func(t *testing.T, c *Config) { c.Listen = "0.0.0.0:8443" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, c := validFixture(t)
			tc.mutate(t, &c)
			if e := os.WriteFile(path, mustJSON(t, c), 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := Load(path); e == nil {
				t.Fatal("unsafe runtime configuration accepted")
			}
		})
	}
}
func TestRejectUntrustedSignerAndMalformedOrigin(t *testing.T) {
	path, c := validFixture(t)
	c.Origin = "http://admin.omnipanel.test"
	os.WriteFile(path, mustJSON(t, c), 0600)
	if _, e := Load(path); e == nil {
		t.Fatal("plaintext origin accepted")
	}
	path, c = validFixture(t)
	data, _ := os.ReadFile(c.TrustFile)
	var trust Trust
	if e := json.Unmarshal(data, &trust); e != nil {
		t.Fatal(e)
	}
	trust.Signers["signer-1"] = "bad"
	os.WriteFile(c.TrustFile, mustJSON(t, trust), 0600)
	if _, e := Load(path); e == nil {
		t.Fatal("wrong-sized signer key accepted")
	}
}
func TestRejectAmbiguousAndUnknownConfigKeys(t *testing.T) {
	path, _ := validFixture(t)
	old, _ := os.ReadFile(path)
	ambiguous := append([]byte(strings.TrimSuffix(string(old), "}")), []byte(`,"listen":"127.0.0.1:9443"}`)...)
	os.WriteFile(path, ambiguous, 0600)
	if _, e := Load(path); e == nil {
		t.Fatal("duplicate key accepted")
	}
	unknown := append([]byte(strings.TrimSuffix(string(old), "}")), []byte(`,"allowInsecureHTTP":true}`)...)
	os.WriteFile(path, unknown, 0600)
	if _, e := Load(path); e == nil {
		t.Fatal("unknown config field accepted")
	}
}

func TestRejectDatabaseConnectionStringParameterInjection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		queryKey   string
		queryValue string
	}{
		{"server options", "options", "-csearch_path=public,pg_temp"},
		{"alternate client certificate", "sslcert", "/tmp/forged.pem"},
		{"alternate client key", "sslkey", "/tmp/forged.key"},
		{"unknown connection knob", "fallback_application_name", "uncontrolled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, cfg := validFixture(t)
			raw, err := os.ReadFile(cfg.SessionDSNFile)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			q.Set(tc.queryKey, tc.queryValue)
			u.RawQuery = q.Encode()
			if err := os.WriteFile(cfg.SessionDSNFile, []byte(u.String()), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("unexpected %q DSN parameter accepted", tc.queryKey)
			}
		})
	}
}
