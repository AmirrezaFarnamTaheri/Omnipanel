package supervisorserver

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	maxProcessWitnessBytes = 16 << 20
	maxExecutableBytes     = 256 << 20
	maxObservedDescriptors = 32768
)

// readProcessStartTime is a kernel-backed PID-reuse guard. /proc/PID/stat
// includes a free-form parenthesized process name, so parse after its final
// closing parenthesis rather than splitting the entire raw record.
func readProcessStartTime(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil || len(raw) == 0 || len(raw) > 8192 {
		return "", ErrNativeRejected
	}
	closeParen := strings.LastIndexByte(string(raw), ')')
	if closeParen < 0 || closeParen+2 > len(raw) {
		return "", ErrNativeRejected
	}
	fields := strings.Fields(string(raw[closeParen+1:]))
	// After comm, fields[0] is #3 (state); #22 is the start time.
	if len(fields) <= 19 {
		return "", ErrNativeRejected
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return "", ErrNativeRejected
	}
	return fields[19], nil
}

// listeningInode finds one and only one IPv4 LISTEN socket for the exact
// configured loopback endpoint in the native service's network namespace.
// Multiple SO_REUSEPORT listeners are ambiguous and are refused, even when
// one is owned by the intended process.
func listeningInode(pid, port int) (string, error) {
	path := fmt.Sprintf("/proc/%d/net/tcp", pid)
	file, err := os.Open(path)
	if err != nil {
		return "", ErrNativeRejected
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, maxProcessWitnessBytes))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	local := fmt.Sprintf("0100007F:%04X", port)
	var inode string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || !strings.EqualFold(fields[1], local) || !strings.EqualFold(fields[3], "0A") {
			continue
		}
		value, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || value == 0 || inode != "" {
			return "", ErrNativeRejected
		}
		inode = strconv.FormatUint(value, 10)
	}
	if scanner.Err() != nil || inode == "" {
		return "", ErrNativeRejected
	}
	return inode, nil
}

func processOwnsSocket(pid int, inode string) bool {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil || len(entries) == 0 || len(entries) > maxObservedDescriptors {
		return false
	}
	expected := "socket:[" + inode + "]"
	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err == nil && link == expected {
			return true
		}
	}
	return false
}

func processExecutableMatches(pid int, expectedDigest string) bool {
	file, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxExecutableBytes {
		return false
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxExecutableBytes+1))
	return err == nil && n == info.Size() && hex.EncodeToString(hash.Sum(nil)) == expectedDigest
}

// verifyProcessListener uses the actual Linux kernel process, executable and
// socket descriptor tables. A valid SOCKS5 response from an unrelated process
// is insufficient, even if that process has exactly the same executable hash.
//
// This is a local process-identity witness, NOT cryptographic, independent
// end-to-end network or public VPS attestation.
func verifyProcessListener(pid int, expectedBinaryDigest, healthAddress string) error {
	if pid <= 1 || pid > 1<<22 || !generationPattern.MatchString("sha256:"+expectedBinaryDigest) {
		return ErrNativeRejected
	}
	host, portText, err := net.SplitHostPort(healthAddress)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || host != "127.0.0.1" || port <= 0 || port > 65535 {
		return ErrNativeRejected
	}
	startTime, err := readProcessStartTime(pid)
	if err != nil {
		return ErrNativeRejected
	}
	selfNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return ErrNativeRejected
	}
	unitNamespace, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil || unitNamespace != selfNamespace {
		// This health address is dialed from the supervisor's netns; a
		// listener with the same tuple in a different netns is not proof.
		return ErrNativeRejected
	}
	if !processExecutableMatches(pid, expectedBinaryDigest) {
		return ErrNativeRejected
	}
	inode, err := listeningInode(pid, port)
	if err != nil || !processOwnsSocket(pid, inode) {
		return ErrNativeRejected
	}
	after, err := readProcessStartTime(pid)
	if err != nil || after != startTime {
		return ErrNativeRejected
	}
	return nil
}

// verifyLinuxUnitListener asks systemd for the fixed unit's MainPID through
// the previously verified, locally pinned systemctl binary. It does not
// accept a PID, unit name, executable path or socket from watchdog IPC.
func verifyLinuxUnitListener(ctx context.Context, systemctlBinary, expectedBinaryDigest, healthAddress string) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrNativeRejected
	}
	commandCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, systemctlBinary,
		"show", "--property=MainPID", "--value", fixedSingBoxUnit)
	cmd.Env = []string{"HOME=/nonexistent", "LANG=C", "PATH=/usr/bin:/bin", "TZ=UTC"}
	cmd.Stderr = io.Discard
	output, err := cmd.Output()
	if err != nil || commandCtx.Err() != nil || len(output) == 0 || len(output) > 32 {
		return ErrNativeRejected
	}
	raw := strings.TrimSpace(string(output))
	if raw == "" || strings.Trim(raw, "0123456789") != "" {
		return ErrNativeRejected
	}
	pid, err := strconv.Atoi(raw)
	if err != nil {
		return ErrNativeRejected
	}
	return verifyProcessListener(pid, expectedBinaryDigest, healthAddress)
}
