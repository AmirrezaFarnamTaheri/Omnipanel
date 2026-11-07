package singbox

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
)

const validNativeConfig = "{\"log\":{\"level\":\"error\"},\"inbounds\":[],\"outbounds\":[{\"type\":\"block\",\"tag\":\"block\"}],\"route\":{\"final\":\"block\"},\"secret\":\"staging-private-test-key\"}"

func nativeArtifact(content string) drivers.ConfigArtifact {
    digest := sha256.Sum256([]byte(content))
    return drivers.ConfigArtifact{
        ComponentID: "reality", Format: "singbox/full-config+json",
        Content: []byte(content), SHA256: hex.EncodeToString(digest[:]),
        ContainsSecrets: true,
    }
}

func nativeFixture(t *testing.T, script string) (*NativeStager, string, string, drivers.BuildIdentity) {
    t.Helper()
    root := t.TempDir()
    binary := filepath.Join(root, "sing-box")
    if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
        t.Fatal(err)
    }
    staging := filepath.Join(root, "staged")
    if err := os.Mkdir(staging, 0o700); err != nil {
        t.Fatal(err)
    }
    digest := sha256.Sum256([]byte(script))
    build := drivers.BuildIdentity{
        Runtime: "singbox", Version: "1.14.4+omni.2",
        ArtifactDigest: hex.EncodeToString(digest[:]),
    }
    stager, err := NewNativeStager(binary, staging, build)
    if err != nil {
        t.Fatalf("valid pinned local native runtime rejected: %v", err)
    }
    return stager, binary, staging, build
}

const passingNative = "#!/bin/sh\nif [ \"$1\" != \"check\" ] || [ \"$2\" != \"-c\" ] || [ ! -f \"$3\" ]; then exit 19; fi\nexit 0\n"

func TestNativeStagerRunsPinnedSingBoxCheckBeforePublishingPrivateCandidate(t *testing.T) {
    stager, _, stageDir, _ := nativeFixture(t, passingNative)
    artifact := nativeArtifact(validNativeConfig)
    result, err := stager.Stage(context.Background(), artifact)
    if err != nil {
        t.Fatal(err)
    }
    if result.ComponentID != artifact.ComponentID || result.SHA256 != artifact.SHA256 {
        t.Fatalf("wrong staged receipt: %+v", result)
    }
    if filepath.Dir(result.Path) != stageDir {
        t.Fatalf("candidate escaped private staging directory: %q", result.Path)
    }
    info, err := os.Lstat(result.Path)
    if err != nil {
        t.Fatal(err)
    }
    if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
        t.Fatalf("staged candidate must be a private regular file, got %s", info.Mode())
    }
    read, err := os.ReadFile(result.Path)
    if err != nil || !bytes.Equal(read, artifact.Content) {
        t.Fatal("staged candidate must exactly equal validated bytes")
    }
    repeat, err := stager.Stage(context.Background(), artifact)
    if err != nil || repeat != result {
        t.Fatalf("same digest should be safe and idempotent: %+v, %v", repeat, err)
    }
    files, err := os.ReadDir(stageDir)
    if err != nil || len(files) != 1 {
        t.Fatalf("staging directory must contain only one durable candidate: %d %v", len(files), err)
    }
}

func TestNativeStagerRejectsFailedNativeCheckAndNeverLeaksSecrets(t *testing.T) {
    script := "#!/bin/sh\necho staging-private-test-key >&2\nexit 17\n"
    stager, _, stageDir, _ := nativeFixture(t, script)
    result, err := stager.Stage(context.Background(), nativeArtifact(validNativeConfig))
    if err == nil || result.Path != "" {
        t.Fatalf("failed native validation cannot publish a candidate: %+v", result)
    }
    if strings.Contains(err.Error(), "staging-private-test-key") {
        t.Fatalf("native stderr leaked into error: %v", err)
    }
    files, err := os.ReadDir(stageDir)
    if err != nil || len(files) != 0 {
        t.Fatalf("failure left an eligible staged candidate: %v %v", files, err)
    }
}

func TestNativeStagerRequiresCompleteArtifactWithExactDigestAndUnambiguousJSON(t *testing.T) {
    stager, _, staging, _ := nativeFixture(t, passingNative)
    bad := []struct {
        name string
        mutate func(*drivers.ConfigArtifact)
    }{
        {"inbound fragment", func(a *drivers.ConfigArtifact) { a.Format = "singbox/inbound-fragment+json" }},
        {"wrong digest", func(a *drivers.ConfigArtifact) { a.SHA256 = strings.Repeat("a", 64) }},
        {"path escape component", func(a *drivers.ConfigArtifact) { a.ComponentID = "../escape" }},
        {"missing secret marking", func(a *drivers.ConfigArtifact) { a.ContainsSecrets = false }},
        {"empty configuration", func(a *drivers.ConfigArtifact) { a.Content = nil }},
        {"invalid JSON", func(a *drivers.ConfigArtifact) { a.Content = []byte("{") }},
        {"duplicate key", func(a *drivers.ConfigArtifact) { *a = nativeArtifact("{\"route\":{},\"route\":{\"final\":\"block\"}}") }},
        {"malformed full config", func(a *drivers.ConfigArtifact) { *a = nativeArtifact("[]") }},
    }
    for _, tc := range bad {
        t.Run(tc.name, func(t *testing.T) {
            artifact := nativeArtifact(validNativeConfig)
            tc.mutate(&artifact)
            result, err := stager.Stage(context.Background(), artifact)
            if err == nil || result.Path != "" {
                t.Fatalf("untrusted full config must fail before native validation: %+v, %v", result, err)
            }
        })
    }
    files, err := os.ReadDir(staging)
    if err != nil || len(files) != 0 {
        t.Fatalf("invalid input must never leave staged files: %v %v", files, err)
    }
}

func TestNativeStagerRejectsMutatedExecutableAfterPinnedConstruction(t *testing.T) {
    stager, binary, staging, _ := nativeFixture(t, passingNative)
    if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
        t.Fatal(err)
    }
    result, err := stager.Stage(context.Background(), nativeArtifact(validNativeConfig))
    if err == nil || result.Path != "" {
        t.Fatalf("mutated native runtime must fail checksum guard: %+v %v", result, err)
    }
    files, err := os.ReadDir(staging)
    if err != nil || len(files) != 0 {
        t.Fatal("modified binary must not stage a candidate")
    }
}

func TestNativeStagerRejectsUntrustedNativePathsAndCancelledCalls(t *testing.T) {
    stager, binary, stageDir, build := nativeFixture(t, passingNative)
    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    _, err := stager.Stage(ctx, nativeArtifact(validNativeConfig))
    if !errors.Is(err, context.Canceled) {
        t.Fatalf("cancelled caller must not execute Sing-box: %v", err)
    }
    symlink := filepath.Join(filepath.Dir(binary), "link")
    if err := os.Symlink(binary, symlink); err != nil {
        t.Fatal(err)
    }
    if _, err := NewNativeStager(symlink, stageDir, build); err == nil {
        t.Fatal("symlinked native runtime accepted")
    }
    if err := os.Chmod(stageDir, 0o755); err != nil {
        t.Fatal(err)
    }
    if _, err := NewNativeStager(binary, stageDir, build); err == nil {
        t.Fatal("public staging directory accepted")
    }
}

func TestNativeStagerStopsOnNativeValidationDeadline(t *testing.T) {
    script := "#!/bin/sh\nsleep 2\nexit 0\n"
    stager, _, stageDir, _ := nativeFixture(t, script)
    ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
    defer cancel()
    _, err := stager.Stage(ctx, nativeArtifact(validNativeConfig))
    if err == nil {
        t.Fatal("deadline exceeded must refuse staged success")
    }
    files, err := os.ReadDir(stageDir)
    if err != nil || len(files) != 0 {
        t.Fatal("cancelled check cannot leave a final staging file")
    }
}
