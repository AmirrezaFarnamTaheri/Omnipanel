package supervisorserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const safeRollbackJSON = "{\"log\":{\"level\":\"warn\"},\"inbounds\":[],\"outbounds\":[{\"type\":\"block\",\"tag\":\"block\"}],\"route\":{\"final\":\"block\"}}"

type nativeFixture struct {
	cfg       NativeConfig
	ref       string
	source    string
	singLog   string
	systemLog string
	active    string
	listener  net.Listener
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func makeNativeFixture(t *testing.T, singScript, systemScript string) (nativeFixture, *NativeBackend) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	gens := filepath.Join(dir, "approved")
	if err := os.Mkdir(gens, 0o700); err != nil {
		t.Fatal(err)
	}
	activeDir := filepath.Join(dir, "active")
	if err := os.Mkdir(activeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	singLog := filepath.Join(dir, "sing-log")
	systemLog := filepath.Join(dir, "system-log")
	sing := filepath.Join(dir, "sing-box")
	systemctl := filepath.Join(dir, "systemctl")
	if singScript == "" {
		singScript = fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nif [ \"$1\" = check ] && [ \"$2\" = -c ] && [ -f \"$3\" ]; then exit 0; fi\nexit 21\n", singLog)
	}
	if systemScript == "" {
		systemScript = fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nif [ \"$1\" = restart ] && [ \"$2\" = omnipanel-singbox.service ]; then exit 0; fi\nif [ \"$1\" = is-active ] && [ \"$2\" = --quiet ] && [ \"$3\" = omnipanel-singbox.service ]; then exit 0; fi\nexit 22\n", systemLog)
	}
	for _, script := range []struct {
		path    string
		content string
	}{{sing, singScript}, {systemctl, systemScript}} {
		if err := os.WriteFile(script.path, []byte(script.content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	digest := digestBytes([]byte(safeRollbackJSON))
	ref := "sha256:" + digest
	source := filepath.Join(gens, digest+".json")
	if err := os.WriteFile(source, []byte(safeRollbackJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	cfg := NativeConfig{
		GenerationDirectory:   gens,
		ActiveConfigPath:      filepath.Join(activeDir, "active.json"),
		SingBoxBinary:         sing,
		SingBoxBinaryDigest:   digestBytes([]byte(singScript)),
		SystemctlBinary:       systemctl,
		SystemctlBinaryDigest: digestBytes([]byte(systemScript)),
		HealthAddress:         listener.Addr().String(),
	}
	backend, err := newNativeBackend(cfg, map[string]bool{ref: true}, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	return nativeFixture{cfg: cfg, ref: ref, source: source, singLog: singLog, systemLog: systemLog, active: cfg.ActiveConfigPath, listener: listener}, backend
}

func TestNativeRootRollbackValidatesPinnedBinaryAndRestoresExactlyAllowedGeneration(t *testing.T) {
	fixture, backend := makeNativeFixture(t, "", "")
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err != nil {
		t.Fatalf("approved local rollback refused: %v", err)
	}
	content, err := os.ReadFile(fixture.active)
	if err != nil || !bytes.Equal(content, []byte(safeRollbackJSON)) {
		t.Fatalf("active config mismatch: %v", err)
	}
	info, err := os.Lstat(fixture.active)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored config must be private root-owned regular file: %v %v", info, err)
	}
	singChecks, err := os.ReadFile(fixture.singLog)
	if err != nil || !strings.Contains(string(singChecks), "check -c ") {
		t.Fatalf("pinned native preflight was not invoked: %q %v", singChecks, err)
	}
	systemCalls, err := os.ReadFile(fixture.systemLog)
	if err != nil || strings.TrimSpace(string(systemCalls)) != "restart omnipanel-singbox.service" {
		t.Fatalf("systemd must receive one fixed unit, never a caller command: %q %v", systemCalls, err)
	}
	healthy, err := backend.ObserveKnownGood(context.Background(), fixture.ref)
	if err != nil || !healthy {
		t.Fatalf("restored generation not observed with active service and live local port: %t %v", healthy, err)
	}
	fixture.listener.Close()
	healthy, err = backend.ObserveKnownGood(context.Background(), fixture.ref)
	if err == nil && healthy {
		t.Fatal("closed native health port was incorrectly observed healthy")
	}
}

func TestNativeRootRollbackRefusesUnlistedGenerationAndTamperedProtectedConfig(t *testing.T) {
	fixture, backend := makeNativeFixture(t, "", "")
	for _, ref := range []string{unknownGeneration, "../../etc/shadow", "sha256:wrong"} {
		if err := backend.RestoreKnownGood(context.Background(), ref); err == nil {
			t.Fatalf("untrusted generation accepted: %s", ref)
		}
	}
	if err := os.WriteFile(fixture.source, []byte(safeRollbackJSON+" "), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err == nil {
		t.Fatal("tampered allowlisted generation accepted")
	}
	if err := os.Remove(fixture.source); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(fixture.source), "other.json")
	if err := os.WriteFile(target, []byte(safeRollbackJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, fixture.source); err != nil {
		t.Fatal(err)
	}
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err == nil {
		t.Fatal("symlinked root generation accepted")
	}
	if _, err := os.Stat(fixture.active); !os.IsNotExist(err) {
		t.Fatal("untrusted generation mutated active runtime")
	}
}

func TestNativeRootRollbackDoesNotChangeActiveConfigOnFailedPreflight(t *testing.T) {
	log := filepath.Join(t.TempDir(), "failure.log")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nexit 31\n", log)
	fixture, backend := makeNativeFixture(t, script, "")
	if err := os.WriteFile(fixture.active, []byte("previous-protected-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err == nil {
		t.Fatal("native check failure accepted as restoration")
	}
	raw, err := os.ReadFile(fixture.active)
	if err != nil || string(raw) != "previous-protected-config" {
		t.Fatal("failed native check overwrote previously active configuration")
	}
	if _, err := os.Stat(fixture.systemLog); !os.IsNotExist(err) {
		t.Fatal("failed native check restarted the service")
	}
}

func TestNativeRootRollbackFailsClosedOnServiceRestartOrFailedLocalHealth(t *testing.T) {
	log := filepath.Join(t.TempDir(), "restart.log")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nexit 47\n", log)
	fixture, backend := makeNativeFixture(t, "", script)
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err == nil {
		t.Fatal("service restart failure acknowledged as a successful rollback")
	}
	healthy, err := backend.ObserveKnownGood(context.Background(), fixture.ref)
	if err == nil && healthy {
		t.Fatal("unavailable systemd reported as healthy")
	}
}

func TestNativeRootRollbackRejectsMutatedPinnedExecutablesAndUnsafeProvisioning(t *testing.T) {
	fixture, backend := makeNativeFixture(t, "", "")
	if err := os.WriteFile(fixture.cfg.SingBoxBinary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err == nil {
		t.Fatal("mutated native runtime accepted")
	}
	if _, err := os.Stat(fixture.active); !os.IsNotExist(err) {
		t.Fatal("mutated binary wrote active config")
	}
	cases := []struct {
		name   string
		change func(*NativeConfig)
	}{
		{"remote probe", func(c *NativeConfig) { c.HealthAddress = "8.8.8.8:53" }},
		{"relative active file", func(c *NativeConfig) { c.ActiveConfigPath = "../active.json" }},
		{"relative generation dir", func(c *NativeConfig) { c.GenerationDirectory = "./approved" }},
		{"wrong executable hash", func(c *NativeConfig) { c.SingBoxBinaryDigest = strings.Repeat("a", 64) }},
		{"missing process health", func(c *NativeConfig) { c.HealthAddress = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use an untampered fixture for each invalid-input case so rejection
			// cannot be attributed to the executable mutation tested above.
			fresh, _ := makeNativeFixture(t, "", "")
			cfg := fresh.cfg
			tc.change(&cfg)
			if _, err := newNativeBackend(cfg, map[string]bool{fresh.ref: true}, uint32(os.Geteuid())); err == nil {
				t.Fatal("untrusted root-side local generation/probe configuration accepted")
			}
		})
	}
}
