package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/supervisorserver"
)

func provisionFixture(t *testing.T) (string, provisioning) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(dir, 0o700); err != nil { t.Fatal(err) }
	p := provisioning{
		SocketPath: filepath.Join(dir, "restore.sock"),
		WatchdogUID: 1001,
		WatchdogGID: 1001,
		AllowedGenerations: []string{"sha256:" + strings.Repeat("b", 64)},
		Native: supervisorserver.NativeConfig{
			GenerationDirectory: filepath.Join(dir, "gens"),
			ActiveConfigPath: filepath.Join(dir, "active", "active.json"),
			SingBoxBinary: "/usr/bin/sing-box",
			SingBoxBinaryDigest: strings.Repeat("a",64),
			SystemctlBinary: "/usr/bin/systemctl",
			SystemctlBinaryDigest: strings.Repeat("c",64),
			HealthAddress: "127.0.0.1:9091",
		},
	}
	path := filepath.Join(dir, "supervisor.json")
	saveProvision(t, path, p)
	return path, p
}

func saveProvision(t *testing.T, path string, p provisioning) {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, data, 0o600); err != nil { t.Fatal(err) }
}

func TestSupervisorRootProvisioningLoadsOwnerPrivatePinnedConfig(t *testing.T) {
	path, expected := provisionFixture(t)
	cfg, err := loadProvisioningForTesting(path, uint32(os.Geteuid()))
	if err != nil { t.Fatalf("valid owner-private config rejected: %v", err) }
	if cfg.SocketPath != expected.SocketPath || cfg.WatchdogUID != expected.WatchdogUID ||
		cfg.AllowedGenerations[0] != expected.AllowedGenerations[0] ||
		cfg.Native.SystemctlBinaryDigest != expected.Native.SystemctlBinaryDigest {
		t.Fatalf("root trust config changed or was not loaded: %+v", cfg)
	}
}

func TestSupervisorRootProvisioningRejectsSymlinksUnsafePermissionsAndParent(t *testing.T) {
	path, _ := provisionFixture(t)
	link := filepath.Join(filepath.Dir(path), "link.json")
	if err := os.Symlink(path, link); err != nil { t.Fatal(err) }
	if _, err := loadProvisioningForTesting(link, uint32(os.Geteuid())); err == nil {
		t.Fatal("symlinked root config accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil { t.Fatal(err) }
	if _, err := loadProvisioningForTesting(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("world-readable root trust config accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil { t.Fatal(err) }
	if err := os.Chmod(filepath.Dir(path), 0o777); err != nil { t.Fatal(err) }
	if _, err := loadProvisioningForTesting(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("world-writable root trust parent accepted")
	}
}

func TestSupervisorRootProvisioningRejectsUnknownDuplicateTrailingAndOversizedJSON(t *testing.T) {
	path, cfg := provisionFixture(t)
	raw, err := json.Marshal(cfg)
	if err != nil { t.Fatal(err) }
	if !bytes.HasSuffix(raw, []byte("}")) { t.Fatal("unexpected fixture json") }
	cases := [][]byte{
		append(append([]byte{}, raw...), []byte(" 123")...),
		append(append([]byte{}, raw[:len(raw)-1]...), []byte(",\"extra\":\"raw shell command\"}")...),
		append(append([]byte{}, raw[:len(raw)-1]...), []byte(",\"socketpath\":\"/tmp/hijack.sock\"}")...),
		bytes.Repeat([]byte(" "), 70000),
	}
	nested := bytes.Replace(raw, []byte("\"HealthAddress\":"), []byte("\"HealthAddress\":\"127.0.0.1:1\",\"HealthAddress\":"), 1)
	if bytes.Equal(nested, raw) { t.Fatal("nested fixture field absent") }
	cases = append(cases, nested)
	for i, content := range cases {
		if err := os.WriteFile(path, content, 0o600); err != nil { t.Fatal(err) }
		if _, err := loadProvisioningForTesting(path, uint32(os.Geteuid())); err == nil {
			t.Fatalf("unsafe JSON document %d was accepted", i)
		}
	}
}

func TestSupervisorRootProvisioningRejectsMissingTrustOrUnauthorizedGeneration(t *testing.T) {
	path, cfg := provisionFixture(t)
	candidates := []provisioning{}
	a := cfg; a.AllowedGenerations = nil; candidates = append(candidates, a)
	b := cfg; b.AllowedGenerations = []string{"../../etc/shadow"}; candidates = append(candidates, b)
	c := cfg; c.WatchdogUID = 0; candidates = append(candidates, c)
	d := cfg; d.WatchdogGID = 0; candidates = append(candidates, d)
	e := cfg; e.Native.HealthAddress = "8.8.8.8:53"; candidates = append(candidates, e)
	for i, candidate := range candidates {
		saveProvision(t, path, candidate)
		if _, err := loadProvisioningForTesting(path, uint32(os.Geteuid())); err == nil {
			t.Fatalf("unsafe root provisioning candidate %d accepted", i)
		}
	}
}

func TestSupervisorExecutableRefusesNonrootBeforeBindingOrRunningHostCommands(t *testing.T) {
	if os.Geteuid() == 0 { t.Skip("non-root CI runner required") }
	_, cfg := provisionFixture(t)
	if err := run(context.Background(), cfg); err == nil {
		t.Fatal("unprivileged process started a root supervisor")
	}
	if _, err := os.Lstat(cfg.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("unprivileged run unexpectedly created root socket: %v", err)
	}
}
