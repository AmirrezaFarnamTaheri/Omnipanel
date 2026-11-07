package singbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
)

// TestPinnedSingBoxBinaryNativePreflight executes only in the signed local
// runtime smoke workflow after Sigstore identity and artifact verification.
// Skipping in unit CI is explicit: synthetic tests are not native evidence.
func TestPinnedSingBoxBinaryNativePreflight(t *testing.T) {
	binary := os.Getenv("OMNI_NATIVE_TEST_SING_BOX_BIN")
	if binary == "" {
		t.Skip("real pinned Sing-box build is only available in signed runtime smoke")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	stageDir := filepath.Join(t.TempDir(), "private-stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	build := drivers.BuildIdentity{
		Runtime: "singbox", Version: "1.14.4+omni.2",
		ArtifactDigest: hex.EncodeToString(hash[:]),
	}
	stager, err := NewNativeStager(binary, stageDir, build)
	if err != nil {
		t.Fatalf("signed binary was refused: %v", err)
	}
	// Deny-all is a deliberately harmless native syntax fixture. It is not
	// a usable Reality production configuration or M0 egress qualification.
	content := "{\"log\":{\"level\":\"warn\"},\"inbounds\":[],\"outbounds\":[{\"type\":\"block\",\"tag\":\"block\"}],\"route\":{\"final\":\"block\"}}"
	result, err := stager.Stage(context.Background(), nativeArtifact(content))
	if err != nil {
		t.Fatalf("native signed-binary check rejected deny-all fixture: %v", err)
	}
	if result.Path == "" || result.ComponentID != "reality" {
		t.Fatalf("native receipt must identify only a private staged candidate: %+v", result)
	}
}
