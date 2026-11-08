package supervisorserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func executableDigest(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func TestProcessListenerWitnessBindsExactKernelSocketToExecutingBinary(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := verifyProcessListener(os.Getpid(), executableDigest(t), listener.Addr().String()); err != nil {
		t.Fatalf("actual process owning kernel TCP listener and pinned binary rejected: %v", err)
	}
}

func TestProcessListenerWitnessRejectsChangedBinaryAndMissingSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	digest := executableDigest(t)
	if err := verifyProcessListener(os.Getpid(), strings.Repeat("a", 64), listener.Addr().String()); err == nil {
		t.Fatal("different native executable digest was falsely attributed to running unit")
	}
	if err := verifyProcessListener(os.Getpid(), digest, "127.0.0.1:1"); err == nil {
		t.Fatal("unowned TCP listener was falsely attributed to running unit")
	}
	if err := verifyProcessListener(0, digest, listener.Addr().String()); err == nil {
		t.Fatal("systemd MainPID=0 was falsely accepted as active")
	}
	if err := verifyProcessListener(os.Getpid(), digest, "8.8.8.8:53"); err == nil {
		t.Fatal("public listener was accepted as local trusted health")
	}
}

// TestKernelListenerHelperProcess is a real child holding its own kernel
// listener. It is launched only from the parent test, with the same hashed
// executable as the parent; no fixture can fake socket ownership.
func TestKernelListenerHelperProcess(t *testing.T) {
	if os.Getenv("OMNI_KERNEL_LISTENER_HELPER") != "1" {
		t.Skip("helper process must be explicitly launched by witness test")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := fmt.Fprintln(os.Stdout, listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestProcessListenerWitnessRejectsOtherProcessWithIdenticalExecutable(t *testing.T) {
	digest := executableDigest(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestKernelListenerHelperProcess$")
	cmd.Env = append(os.Environ(), "OMNI_KERNEL_LISTENER_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	address, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("child native listener did not become ready: %v: %s", err, diagnostics.String())
	}
	address = strings.TrimSpace(address)
	// Both processes have exactly the same executable hash. A health check
	// still must reject the child's port when systemd identifies the parent.
	if err := verifyProcessListener(os.Getpid(), digest, address); err == nil {
		t.Fatal("listener from different PID with identical executable was trusted")
	}
	if err := verifyProcessListener(cmd.Process.Pid, digest, address); err != nil {
		t.Fatalf("actual child listener ownership was not observed: %v", err)
	}
	if err := verifyProcessListener(cmd.Process.Pid, digest, listener.Addr().String()); err == nil {
		t.Fatal("parent listener falsely attributed to child with identical executable")
	}
}

func TestObserveKnownGoodRequiresKernelUnitWitnessBeforeHealth(t *testing.T) {
	fixture, backend := makeNativeFixture(t, "", "")
	acceptHealthSOCKS(t, fixture.listener, false)
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err != nil {
		t.Fatal(err)
	}
	calls := 0
	backend.unitWitness = func(context.Context, string, string, string) error {
		calls++
		return ErrNativeRejected
	}
	healthy, err := backend.ObserveKnownGood(context.Background(), fixture.ref)
	if err == nil || healthy || calls != 1 {
		t.Fatalf("untrusted kernel/process identity must block healthy state: healthy=%t err=%v witnessCalls=%d", healthy, err, calls)
	}
}
