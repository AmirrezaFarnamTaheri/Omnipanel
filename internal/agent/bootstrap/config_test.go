package bootstrap

import (
  "bytes"
  "crypto/ed25519"
  "encoding/base64"
  "encoding/json"
  "os"
  "path/filepath"
  "strings"
  "testing"
  "time"
  "github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

const testNode = "62c478bb-47c3-4dc6-a363-a2fbde813810"
const testEpoch = "ea2429da-7540-4e40-ae70-38fd3f19794b"

func setupConfig(t *testing.T) (string, Config) {
  t.Helper()
  dir := filepath.Join(t.TempDir(), "private")
  if err := os.Mkdir(dir, 0o700); err != nil { t.Fatal(err) }
  ca := filepath.Join(dir, "ca.pem")
  cert := filepath.Join(dir, "node.pem")
  key := filepath.Join(dir, "node.key")
  for _, p := range []string{ca, cert, key} {
    if err := os.WriteFile(p, []byte("private-test-data"), 0o600); err != nil { t.Fatal(err) }
  }
  pub := bytes.Repeat([]byte{8}, ed25519.PublicKeySize)
  cfg := Config{
    GatewayOrigin: "https://control.example.test:8443",
    NodeID: testNode,
    ControlPlaneEpoch: testEpoch,
    JournalPath: filepath.Join(dir, "node.sqlite"),
    RootCAFile: ca, ClientCertFile: cert, ClientKeyFile: key,
    TrustedSigners: map[string]string{"trusted-owner": base64.RawURLEncoding.EncodeToString(pub)},
    AllowedCapabilities: []string{"singbox-reality-vision"},
    QualifiedBuilds: map[string]manifest.Build{"singbox": {Driver:"singbox", Version:"1.14.4+omni.2", ArtifactDigest: strings.Repeat("a", 64), Capabilities: []string{"singbox-reality-vision"}}},
    PollSeconds: 30, MaxClockSkewSeconds: 5,
  }
  path := filepath.Join(dir, "node-bootstrap.json")
  saveTestConfig(t, path, cfg)
  return path, cfg
}

func saveTestConfig(t *testing.T, path string, cfg Config) {
  t.Helper()
  raw, err := json.Marshal(cfg)
  if err != nil { t.Fatal(err) }
  if err := os.WriteFile(path, raw, 0o600); err != nil { t.Fatal(err) }
}

func TestProtectedBootstrapLoadsIndependentTrustAndBoundedPollSettings(t *testing.T) {
  path, expected := setupConfig(t)
  loaded, err := Load(path)
  if err != nil { t.Fatalf("valid owner-only bootstrap must load: %v", err) }
  if loaded.NodeID != expected.NodeID || loaded.ControlPlaneEpoch != expected.ControlPlaneEpoch || loaded.PollSeconds != 30 {
    t.Fatalf("bootstrap scope/poll settings changed: %+v", loaded)
  }
  verifier, err := loaded.Verifier()
  if err != nil { t.Fatal(err) }
  if verifier.NodeID != testNode || verifier.AuthorizedEpoch != testEpoch || verifier.MaxClockSkew != 5*time.Second {
    t.Fatalf("verifier must bind exact locally installed node/epoch: %+v", verifier)
  }
  if !verifier.AllowedCapabilities["singbox-reality-vision"] || verifier.QualifiedBuilds["singbox"].ArtifactDigest != strings.Repeat("a", 64) {
    t.Fatalf("verified runtime trust must come from installed config, not desired-state")
  }
  if len(verifier.TrustedSigners["trusted-owner"]) != ed25519.PublicKeySize {
    t.Fatal("signer key not validated")
  }
}

func TestBootstrapRejectsSymlinksWorldReadableConfigAndUnsafeParent(t *testing.T) {
  path, _ := setupConfig(t)
  link := filepath.Join(filepath.Dir(path), "bootstrap-link.json")
  if err := os.Symlink(path, link); err != nil { t.Fatal(err) }
  if _, err := Load(link); err == nil { t.Fatal("symlinked trust root accepted") }
  if err := os.Chmod(path, 0o644); err != nil { t.Fatal(err) }
  if _, err := Load(path); err == nil { t.Fatal("world-readable trust root accepted") }
  if err := os.Chmod(path, 0o600); err != nil { t.Fatal(err) }
  if err := os.Chmod(filepath.Dir(path), 0o755); err != nil { t.Fatal(err) }
  if _, err := Load(path); err == nil { t.Fatal("unprotected trust root parent accepted") }
}

func TestBootstrapRejectsUnknownTrailingAndOversizedJSON(t *testing.T) {
  path, cfg := setupConfig(t)
  raw, err := json.Marshal(cfg)
  if err != nil { t.Fatal(err) }
  for _, invalid := range [][]byte{
    append(append([]byte{}, raw...), []byte(" true")...),
    append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"privileged":true}`)...),
    bytes.Repeat([]byte(" "), 70000),
  } {
    if err := os.WriteFile(path, invalid, 0o600); err != nil { t.Fatal(err) }
    if _, err := Load(path); err == nil { t.Fatalf("untrusted bootstrap JSON accepted (bytes=%d)", len(invalid)) }
  }
}

func TestBootstrapRejectsMissingOrMismatchedIndependentQualification(t *testing.T) {
  path, cfg := setupConfig(t)
  bad := []Config{}
  copy1 := cfg; copy1.TrustedSigners = map[string]string{"bad": "AA"}; bad = append(bad, copy1)
  copy2 := cfg; copy2.QualifiedBuilds = map[string]manifest.Build{}; bad = append(bad, copy2)
  copy3 := cfg; copy3.QualifiedBuilds = map[string]manifest.Build{"singbox": {Driver:"xray", Version:"1.14.4+omni.2", ArtifactDigest: strings.Repeat("a",64), Capabilities: []string{"singbox-reality-vision"}}}; bad = append(bad, copy3)
  copy4 := cfg; copy4.PollSeconds = 0; bad = append(bad, copy4)
  copy5 := cfg; copy5.MaxClockSkewSeconds = 9999; bad = append(bad, copy5)
  copy6 := cfg; copy6.AllowedCapabilities = []string{"hysteria2"}; bad = append(bad, copy6)
  copy7 := cfg; copy7.NodeID = "wrong"; bad = append(bad, copy7)
  for i, candidate := range bad {
    saveTestConfig(t, path, candidate)
    if _, err := Load(path); err == nil { t.Fatalf("unsafe bootstrap candidate #%d accepted", i) }
  }
}

func TestPrivateCredentialReadRejectsSymlinksAndLoosePermissions(t *testing.T) {
  path, cfg := setupConfig(t)
  _ = path
  original, err := ReadPrivatePEM(cfg.ClientKeyFile)
  if err != nil || !bytes.Equal(original, []byte("private-test-data")) { t.Fatalf("private credential read: %v", err) }
  if err := os.Chmod(cfg.ClientKeyFile, 0o644); err != nil { t.Fatal(err) }
  if _, err := ReadPrivatePEM(cfg.ClientKeyFile); err == nil { t.Fatal("readable TLS private key accepted") }
  if err := os.Chmod(cfg.ClientKeyFile, 0o600); err != nil { t.Fatal(err) }
  link := filepath.Join(filepath.Dir(cfg.ClientKeyFile), "key-link")
  if err := os.Symlink(cfg.ClientKeyFile, link); err != nil { t.Fatal(err) }
  if _, err := ReadPrivatePEM(link); err == nil { t.Fatal("symlinked TLS key accepted") }
}
