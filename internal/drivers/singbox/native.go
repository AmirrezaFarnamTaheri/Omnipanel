package singbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
)

const (
	nativeFullConfigFormat = "singbox/full-config+json"
	maxNativeConfigBytes   = 2 << 20
	maxNativeBinaryBytes   = 256 << 20
	maxNativeJSONDepth     = 64
	nativeCheckTimeout     = 12 * time.Second
)

var (
	ErrNativeRejected    = errors.New("Sing-box native preflight input rejected")
	ErrNativeCheckFailed = errors.New("Sing-box native configuration check failed")
)

// NativeStager performs an unprivileged binary-pinned syntax preflight and
// publishes an owner-private candidate file. It does not apply configuration,
// supervise a daemon, confirm policy compliance, or acknowledge deployment.
// In particular, an inbound fragment is never a valid full configuration.
type NativeStager struct {
	binaryPath string
	stageDir   string
	build      drivers.BuildIdentity
}

// StagedConfig proves only that these exact bytes passed a native check and
// were durably staged. A staged path must NEVER be treated as an applied ACK.
type StagedConfig struct {
	ComponentID string
	SHA256      string
	Path        string
}

func NewNativeStager(binaryPath, stagingDirectory string, build drivers.BuildIdentity) (*NativeStager, error) {
	if build.Runtime != "singbox" || !buildVersionPattern.MatchString(build.Version) ||
		!digestPattern.MatchString(build.ArtifactDigest) {
		return nil, ErrNativeRejected
	}
	n := &NativeStager{binaryPath: binaryPath, stageDir: stagingDirectory, build: build}
	if err := n.checkScope(); err != nil {
		return nil, err
	}
	if err := n.checkPinnedBinary(); err != nil {
		return nil, err
	}
	return n, nil
}

func cleanAbsolutePath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && resolved == path
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func (n *NativeStager) checkScope() error {
	if n == nil || !cleanAbsolutePath(n.binaryPath) || !cleanAbsolutePath(n.stageDir) {
		return ErrNativeRejected
	}
	dir, err := os.Lstat(n.stageDir)
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(dir) {
		return ErrNativeRejected
	}
	return nil
}

// checkPinnedBinary requires the installed executable to be a real, non-
// writable-by-others file with the exact digest from local trusted build state.
// It is repeated before each preflight, not only in the constructor.
func (n *NativeStager) checkPinnedBinary() error {
	if !cleanAbsolutePath(n.binaryPath) {
		return ErrNativeRejected
	}
	fd, err := syscall.Open(n.binaryPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrNativeRejected
	}
	file := os.NewFile(uintptr(fd), n.binaryPath)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxNativeBinaryBytes ||
		info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return ErrNativeRejected
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return ErrNativeRejected
	}
	hash := sha256.New()
	copied, err := io.Copy(hash, io.LimitReader(file, maxNativeBinaryBytes+1))
	if err != nil || copied != info.Size() || copied > maxNativeBinaryBytes ||
		hex.EncodeToString(hash.Sum(nil)) != n.build.ArtifactDigest {
		return ErrNativeRejected
	}
	return nil
}

// visitNativeJSON rejects duplicate object keys at any nesting level, including
// ASCII case variants, before Go's JSON decoder can replace a prior field.
func visitNativeJSON(decoder *json.Decoder, depth int) error {
	if depth > maxNativeJSONDepth {
		return ErrNativeRejected
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrNativeRejected
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		keys := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || keys[strings.ToLower(key)] {
				return ErrNativeRejected
			}
			keys[strings.ToLower(key)] = true
			if err := visitNativeJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrNativeRejected
		}
		return nil
	case '[':
		for decoder.More() {
			if err := visitNativeJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrNativeRejected
		}
		return nil
	default:
		return ErrNativeRejected
	}
}

// checkFullCandidate enforces a bounded complete JSON document, not a fragment.
// A separate trusted policy compiler must enforce deny-protected-v1 before any
// future native APPLY operation; a successful native check proves syntax only.
func checkFullCandidate(artifact drivers.ConfigArtifact) error {
	if !principalPattern.MatchString(artifact.ComponentID) || artifact.Format != nativeFullConfigFormat ||
		!artifact.ContainsSecrets || len(artifact.Content) == 0 || len(artifact.Content) > maxNativeConfigBytes ||
		!digestPattern.MatchString(artifact.SHA256) {
		return ErrNativeRejected
	}
	hash := sha256.Sum256(artifact.Content)
	if hex.EncodeToString(hash[:]) != artifact.SHA256 {
		return ErrNativeRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(artifact.Content))
	if err := visitNativeJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrNativeRejected
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(artifact.Content, &root); err != nil || root == nil {
		return ErrNativeRejected
	}
	var inbounds, outbounds []json.RawMessage
	var route map[string]json.RawMessage
	if err := json.Unmarshal(root["inbounds"], &inbounds); err != nil || inbounds == nil {
		return ErrNativeRejected
	}
	if err := json.Unmarshal(root["outbounds"], &outbounds); err != nil || len(outbounds) == 0 {
		return ErrNativeRejected
	}
	if err := json.Unmarshal(root["route"], &route); err != nil || route == nil {
		return ErrNativeRejected
	}
	var final string
	if err := json.Unmarshal(route["final"], &final); err != nil || final == "" {
		return ErrNativeRejected
	}
	return nil
}

func (n *NativeStager) validateExisting(path string, content []byte) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrNativeRejected
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		!ownedByCurrentUser(info) || info.Size() != int64(len(content)) {
		return ErrNativeRejected
	}
	read, err := io.ReadAll(io.LimitReader(file, maxNativeConfigBytes+1))
	if err != nil || !bytes.Equal(read, content) {
		return ErrNativeRejected
	}
	return nil
}

func (n *NativeStager) Stage(ctx context.Context, artifact drivers.ConfigArtifact) (StagedConfig, error) {
	if ctx == nil {
		return StagedConfig{}, ErrNativeRejected
	}
	if err := ctx.Err(); err != nil {
		return StagedConfig{}, err
	}
	if err := n.checkScope(); err != nil {
		return StagedConfig{}, err
	}
	if err := n.checkPinnedBinary(); err != nil {
		return StagedConfig{}, err
	}
	if err := checkFullCandidate(artifact); err != nil {
		return StagedConfig{}, err
	}
	temp, err := os.CreateTemp(n.stageDir, ".native-candidate-")
	if err != nil {
		return StagedConfig{}, ErrNativeRejected
	}
	name := temp.Name()
	defer os.Remove(name)
	defer temp.Close()
	written, err := temp.Write(artifact.Content)
	if err != nil || written != len(artifact.Content) {
		return StagedConfig{}, ErrNativeRejected
	}
	if err := temp.Chmod(0o600); err != nil {
		return StagedConfig{}, ErrNativeRejected
	}
	if err := temp.Sync(); err != nil {
		return StagedConfig{}, ErrNativeRejected
	}
	if err := temp.Close(); err != nil {
		return StagedConfig{}, ErrNativeRejected
	}

	checkCtx, cancel := context.WithTimeout(ctx, nativeCheckTimeout)
	defer cancel()
	command := exec.CommandContext(checkCtx, n.binaryPath, "check", "-c", name)
	command.Dir = n.stageDir
	command.Env = []string{"HOME=/nonexistent", "PATH=/usr/bin:/bin", "LANG=C", "TZ=UTC"}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		if ctxErr := checkCtx.Err(); ctxErr != nil {
			return StagedConfig{}, ctxErr
		}
		return StagedConfig{}, ErrNativeCheckFailed
	}
	if err := ctx.Err(); err != nil {
		return StagedConfig{}, err
	}
	final := filepath.Join(n.stageDir, artifact.ComponentID+"-"+artifact.SHA256+".json")
	if err := os.Link(name, final); err != nil {
		if !errors.Is(err, os.ErrExist) || n.validateExisting(final, artifact.Content) != nil {
			return StagedConfig{}, ErrNativeRejected
		}
	} else {
		dir, err := os.Open(n.stageDir)
		if err != nil {
			return StagedConfig{}, ErrNativeRejected
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil || closeErr != nil {
			return StagedConfig{}, ErrNativeRejected
		}
	}
	return StagedConfig{ComponentID: artifact.ComponentID, SHA256: artifact.SHA256, Path: final}, nil
}
