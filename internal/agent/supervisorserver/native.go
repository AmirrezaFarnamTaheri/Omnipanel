package supervisorserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxGenerationBytes   = 2 << 20
	maxPinnedBinaryBytes = 256 << 20
	nativeCommandTimeout = 8 * time.Second
	activeFilename       = "active.json"
	fixedSingBoxUnit     = "omnipanel-singbox.service"
)

var (
	ErrNativeRejected = errors.New("root native rollback generation or host trust rejected")
	ErrNativeFailed   = errors.New("root native rollback, service restart or observation failed")
)

// NativeConfig is provisioned locally from a separately protected, root-owned
// policy file. Nothing in the Unix client's JSON request can modify it.
type NativeConfig struct {
	GenerationDirectory   string
	ActiveConfigPath      string
	SingBoxBinary         string
	SingBoxBinaryDigest   string
	SystemctlBinary       string
	SystemctlBinaryDigest string
	HealthAddress         string
}

type NativeBackend struct {
	cfg      NativeConfig
	allowed  map[string]bool
	ownerUID uint32
	mu       sync.Mutex
	// Kernel process identity is independently witnessed by systemd and
	// procfs. Unit tests replace only this OS boundary, never the policy.
	unitWitness func(context.Context, string, string, string) error
}

func NewNativeBackend(cfg NativeConfig, generations map[string]bool) (*NativeBackend, error) {
	if os.Geteuid() != 0 {
		return nil, ErrNativeRejected
	}
	return newNativeBackend(cfg, generations, 0)
}

func nativeAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		strings.IndexByte(path, 0) < 0
}

func (b *NativeBackend) protectedDir(path string) error {
	if !nativeAbsolute(path) {
		return ErrNativeRejected
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return ErrNativeRejected
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != b.ownerUID {
		return ErrNativeRejected
	}
	return nil
}

// checkedFile uses O_NOFOLLOW and verifies metadata on the actual open inode,
// preventing a final-component symlink replacement between stat and read.
func (b *NativeBackend) checkedFile(path string, limit int64, executable bool) (*os.File, os.FileInfo, error) {
	if !nativeAbsolute(path) {
		return nil, nil, ErrNativeRejected
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, ErrNativeRejected
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit ||
		info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		file.Close()
		return nil, nil, ErrNativeRejected
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != b.ownerUID ||
		(executable && info.Mode().Perm()&0o111 == 0) ||
		(!executable && info.Mode().Perm()&0o077 != 0) {
		file.Close()
		return nil, nil, ErrNativeRejected
	}
	return file, info, nil
}

func (b *NativeBackend) checkPinnedBinary(path, expectedDigest string) error {
	if !generationPattern.MatchString("sha256:" + expectedDigest) {
		return ErrNativeRejected
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return ErrNativeRejected
	}
	file, info, err := b.checkedFile(path, maxPinnedBinaryBytes, true)
	if err != nil {
		return err
	}
	defer file.Close()
	sum := sha256.New()
	copied, err := io.Copy(sum, io.LimitReader(file, maxPinnedBinaryBytes+1))
	if err != nil || copied != info.Size() || hex.EncodeToString(sum.Sum(nil)) != expectedDigest {
		return ErrNativeRejected
	}
	return nil
}

func newNativeBackend(cfg NativeConfig, generations map[string]bool, trustedUID uint32) (*NativeBackend, error) {
	if os.Geteuid() != int(trustedUID) ||
		!nativeAbsolute(cfg.ActiveConfigPath) ||
		filepath.Base(cfg.ActiveConfigPath) != activeFilename ||
		!nativeAbsolute(cfg.SingBoxBinary) || !nativeAbsolute(cfg.SystemctlBinary) ||
		len(generations) == 0 || len(generations) > maxGenerations {
		return nil, ErrNativeRejected
	}
	host, portText, err := net.SplitHostPort(cfg.HealthAddress)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || host != "127.0.0.1" || port <= 0 || port > 65535 {
		return nil, ErrNativeRejected
	}
	b := &NativeBackend{cfg: cfg, ownerUID: trustedUID, allowed: make(map[string]bool, len(generations)), unitWitness: verifyLinuxUnitListener}
	for ref, allowed := range generations {
		if !allowed || !generationPattern.MatchString(ref) {
			return nil, ErrNativeRejected
		}
		b.allowed[ref] = true
	}
	if err := b.protectedDir(cfg.GenerationDirectory); err != nil {
		return nil, err
	}
	if err := b.protectedDir(filepath.Dir(cfg.ActiveConfigPath)); err != nil {
		return nil, err
	}
	if err := b.checkPinnedBinary(cfg.SingBoxBinary, cfg.SingBoxBinaryDigest); err != nil {
		return nil, err
	}
	if err := b.checkPinnedBinary(cfg.SystemctlBinary, cfg.SystemctlBinaryDigest); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *NativeBackend) generationBytes(ref string) ([]byte, error) {
	if b == nil || !generationPattern.MatchString(ref) || !b.allowed[ref] {
		return nil, ErrNativeRejected
	}
	if err := b.protectedDir(b.cfg.GenerationDirectory); err != nil {
		return nil, err
	}
	filename := filepath.Join(b.cfg.GenerationDirectory, strings.TrimPrefix(ref, "sha256:")+".json")
	file, info, err := b.checkedFile(filename, maxGenerationBytes, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxGenerationBytes+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) != info.Size() || len(raw) > maxGenerationBytes {
		return nil, ErrNativeRejected
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != ref {
		return nil, ErrNativeRejected
	}
	return raw, nil
}

func (b *NativeBackend) runPinned(ctx context.Context, executable string, args ...string) error {
	if ctx == nil {
		return ErrNativeRejected
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, nativeCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, executable, args...)
	cmd.Env = []string{"HOME=/nonexistent", "LANG=C", "PATH=/usr/bin:/bin", "TZ=UTC"}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return ErrNativeFailed
	}
	if err := checkCtx.Err(); err != nil {
		return ErrNativeFailed
	}
	return nil
}

// RestoreKnownGood applies only a separately approved, content-addressed LKG.
// It never accepts a config, path, or service name from the IPC client.
// A native syntax check precedes atomic private active-config replacement;
// the fixed systemd service is restarted afterwards. Restart failure NEVER
// counts as restoration success, and the watchdog keeps the durable guard.
func (b *NativeBackend) RestoreKnownGood(ctx context.Context, ref string) error {
	if b == nil || ctx == nil {
		return ErrNativeRejected
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.protectedDir(filepath.Dir(b.cfg.ActiveConfigPath)); err != nil {
		return err
	}
	raw, err := b.generationBytes(ref)
	if err != nil {
		return err
	}
	if err := b.checkPinnedBinary(b.cfg.SingBoxBinary, b.cfg.SingBoxBinaryDigest); err != nil {
		return err
	}
	if err := b.checkPinnedBinary(b.cfg.SystemctlBinary, b.cfg.SystemctlBinaryDigest); err != nil {
		return err
	}

	dirPath := filepath.Dir(b.cfg.ActiveConfigPath)
	file, err := os.CreateTemp(dirPath, ".rollback-")
	if err != nil {
		return ErrNativeFailed
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return ErrNativeFailed
	}
	n, err := file.Write(raw)
	if err != nil || n != len(raw) {
		return ErrNativeFailed
	}
	if err := file.Sync(); err != nil {
		return ErrNativeFailed
	}
	if err := file.Close(); err != nil {
		return ErrNativeFailed
	}
	if err := b.runPinned(ctx, b.cfg.SingBoxBinary, "check", "-c", tmp); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.cfg.ActiveConfigPath); err != nil {
		return ErrNativeFailed
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return ErrNativeFailed
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return ErrNativeFailed
	}
	return b.runPinned(ctx, b.cfg.SystemctlBinary, "restart", fixedSingBoxUnit)
}

// protectedSOCKSCanaries are fixed test destinations from distinct protected
// categories. They do not originate in the manifest, IPC, DNS, or user input.
// They exercise explicit ruleset refusal, not comprehensive routing proof.
var protectedSOCKSCanaries = [][]byte{
	// Cloud instance metadata
	{5, 1, 0, 1, 169, 254, 169, 254, 0, 80},
	// Loopback IPv4
	{5, 1, 0, 1, 127, 0, 0, 1, 0, 80},
	// RFC1918 /8
	{5, 1, 0, 1, 10, 0, 0, 1, 0, 80},
	// RFC1918 /12
	{5, 1, 0, 1, 172, 16, 0, 1, 0, 80},
	// RFC1918 /16
	{5, 1, 0, 1, 192, 168, 1, 1, 0, 80},
	// Carrier-grade NAT
	{5, 1, 0, 1, 100, 64, 0, 1, 0, 80},
	// Unspecified
	{5, 1, 0, 1, 0, 0, 0, 0, 0, 80},
	// IPv6 loopback
	{5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80},
	// IPv6 ULA
	{5, 1, 0, 4, 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80},
	// IPv6 link-local
	{5, 1, 0, 4, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80},
	// IPv4-mapped metadata
	{5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254, 0, 80},
	// localhost name
	{5, 1, 0, 3, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0, 80},
}

// probeProtectedSOCKSDenial requires an exact SOCKS5 ruleset rejection (REP
// 0x02) and a complete well-formed SOCKS5 response for EVERY fixed canary.
// Connection resets, arbitrary upstream errors, timeouts or truncated frames
// cannot serve as policy-denial evidence. This is a host-local smoke matrix,
// NOT a complete inspection of protected routes or independent client health.
func probeProtectedSOCKSDenial(ctx context.Context, address string) error {
	if ctx == nil {
		return ErrNativeRejected
	}
	for _, request := range protectedSOCKSCanaries {
		if err := probeOneProtectedSOCKSDenial(ctx, address, request); err != nil {
			return err
		}
	}
	return nil
}

func probeOneProtectedSOCKSDenial(ctx context.Context, address string, request []byte) error {
	probeCtx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()
	dialer := net.Dialer{Timeout: 350 * time.Millisecond}
	conn, err := dialer.DialContext(probeCtx, "tcp", address)
	if err != nil {
		return ErrNativeFailed
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(350 * time.Millisecond)); err != nil {
		return ErrNativeFailed
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return ErrNativeFailed
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil || method[0] != 5 || method[1] != 0 {
		return ErrNativeFailed
	}
	if _, err := conn.Write(request); err != nil {
		return ErrNativeFailed
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil ||
		reply[0] != 5 || reply[1] != 2 || reply[2] != 0 {
		return ErrNativeFailed
	}
	var tailBytes int
	switch reply[3] {
	case 1:
		tailBytes = 4 + 2
	case 4:
		tailBytes = 16 + 2
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil || length[0] == 0 {
			return ErrNativeFailed
		}
		tailBytes = int(length[0]) + 2
	default:
		return ErrNativeFailed
	}
	if _, err := io.CopyN(io.Discard, conn, int64(tailBytes)); err != nil {
		return ErrNativeFailed
	}
	if probeCtx.Err() != nil {
		return ErrNativeFailed
	}
	return nil
}

// ObserveKnownGood is a separately executed host-level witness. It verifies
// the approved active config hash, fixed unit state, systemd MainPID, matching
// executable digest and kernel-owned listener before a protected SOCKS5 probe.
// It does not replace independent external generation-bound client evidence.
func (b *NativeBackend) ObserveKnownGood(ctx context.Context, ref string) (bool, error) {
	if b == nil || ctx == nil {
		return false, ErrNativeRejected
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := b.generationBytes(ref); err != nil {
		return false, err
	}
	if err := b.protectedDir(filepath.Dir(b.cfg.ActiveConfigPath)); err != nil {
		return false, err
	}
	file, info, err := b.checkedFile(b.cfg.ActiveConfigPath, maxGenerationBytes, false)
	if err != nil {
		return false, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxGenerationBytes+1))
	file.Close()
	if err != nil || int64(len(raw)) != info.Size() {
		return false, ErrNativeRejected
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != ref {
		return false, ErrNativeRejected
	}
	if err := b.checkPinnedBinary(b.cfg.SystemctlBinary, b.cfg.SystemctlBinaryDigest); err != nil {
		return false, err
	}
	if err := b.runPinned(ctx, b.cfg.SystemctlBinary, "is-active", "--quiet", fixedSingBoxUnit); err != nil {
		return false, err
	}
	// A matching service state and a valid SOCKS5 response cannot prove the
	// listener belongs to the intended native unit. Require a kernel-backed
	// MainPID, pinned executable digest and exact listening socket inode.
	if b.unitWitness == nil || b.unitWitness(ctx, b.cfg.SystemctlBinary, b.cfg.SingBoxBinaryDigest, b.cfg.HealthAddress) != nil {
		return false, ErrNativeRejected
	}
	// A listening port alone can belong to an unrelated or stale process.
	// Require a real SOCKS5 handshake and an explicit ruleset rejection of a
	// protected link-local destination through the restored local proxy.
	// This is still a bounded local data-path probe, NOT proof of external
	// Reality/Vision, all private routes, or a generation-authenticated peer.
	if err := probeProtectedSOCKSDenial(ctx, b.cfg.HealthAddress); err != nil {
		return false, err
	}
	return true, nil
}
