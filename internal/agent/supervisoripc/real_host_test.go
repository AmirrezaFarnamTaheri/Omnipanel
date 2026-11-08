package supervisoripc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// systemctl restart reports the unit-start transaction before the proxy
// listener necessarily accepts connections. Health must be observed, never
// inferred from the restart command's exit status.
func waitForRestoredHostHealth(ctx context.Context, c *Client, ref string) error {
	for i := 0; i < 80; i++ {
		healthy, err := c.ObserveLastKnownGood(ctx, ref)
		if err == nil && healthy {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("native generation failed host-level readiness observation")
}

// This opt-in test exercises the real root-owned supervisor executable,
// systemd unit, and Sigstore-verified Sing-box build on an ephemeral CI host.
// It is never evidence of public VPS connectivity or policy qualification.
func TestSignedRootHostRollbackAfterSIGKILL(t *testing.T) {
	if os.Getenv("OMNI_SIGNED_ROOT_HOST_LAB") != "1" {
		t.Skip("requires explicitly provisioned signed runtime and ephemeral root systemd host")
	}
	if os.Geteuid() == 0 {
		t.Fatal("watchdog client must be unprivileged")
	}
	socket := os.Getenv("OMNI_ROOT_LAB_SOCKET")
	ref := os.Getenv("OMNI_ROOT_LAB_LKG")
	if socket == "" || ref == "" {
		t.Fatal("signed root-host lab lacks socket or pinned generation")
	}
	client, err := New(socket)
	if err != nil {
		t.Fatalf("root supervisor identity rejected: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if healthy, err := client.ObserveLastKnownGood(ctx, ref); healthy && err == nil {
		t.Fatal("a different initial active generation was falsely reported as restored")
	}
	if err := client.RestoreLastKnownGood(ctx, ref); err != nil {
		t.Fatalf("actual Sing-box/systemd rollback failed: %v", err)
	}
	if err := waitForRestoredHostHealth(ctx, client, ref); err != nil {
		t.Fatalf("actual restored Sing-box SOCKS5 deny-route health was not observed: %v", err)
	}
	// The root unit is a fixed CI-only unit installed by the calling lab;
	// no user-supplied unit name or command reaches the root supervisor IPC.
	kill := exec.CommandContext(ctx, "sudo", "/usr/bin/systemctl", "kill", "--kill-who=main", "--signal=SIGKILL", "omnipanel-singbox.service")
	if output, err := kill.CombinedOutput(); err != nil {
		t.Fatalf("ephemeral systemd fault injection failed: %v (%s)", err, output)
	}
	dead := false
	for attempt := 0; attempt < 40; attempt++ {
		healthy, err := client.ObserveLastKnownGood(ctx, ref)
		if err != nil || !healthy {
			dead = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !dead {
		t.Fatal("SIGKILL did not make native runtime health fail closed")
	}
	if err := client.RestoreLastKnownGood(ctx, ref); err != nil {
		t.Fatalf("root recovery following actual SIGKILL failed: %v", err)
	}
	if err := waitForRestoredHostHealth(ctx, client, ref); err != nil {
		t.Fatalf("root supervisor could not recover native runtime after SIGKILL: %v", err)
	}
	// The root allowlist must reject a syntactically valid but unapproved
	// generation even when the caller passes a canonical SHA-256 string.
	unapproved := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if unapproved == ref {
		t.Fatal("test reference unexpectedly equals unapproved fixed value")
	}
	if err := client.RestoreLastKnownGood(ctx, unapproved); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("unapproved generation was not rejected by the root IPC boundary")
	}

	// An independently root-provisioned candidate is a DIFFERENT permission
	// from the known-good recovery allowlist. Exercise the actual pinned binary,
	// fixed systemd unit and protected root ticket on this disposable VM.
	candidate := os.Getenv("OMNI_ROOT_LAB_CANDIDATE")
	if candidate == "" || candidate == ref {
		t.Fatal("root candidate lab requires a distinct pre-approved generation")
	}
	if err := client.RestoreLastKnownGood(ctx, candidate); err == nil {
		t.Fatal("candidate gained rollback recovery privilege")
	}
	if err := client.ApplyApprovedCandidate(ctx, candidate); err != nil {
		t.Fatalf("native root-approved candidate activation failed: %v", err)
	}
	if healthy, err := client.ObserveLastKnownGood(ctx, ref); healthy && err == nil {
		t.Fatal("LKG falsely reported healthy while distinct candidate was active")
	}
	if err := client.ApplyApprovedCandidate(ctx, candidate); err == nil {
		t.Fatal("one-time candidate token replay succeeded after root activation")
	}
	// Fault after candidate activation, then recover the PREVIOUS qualified LKG.
	secondKill := exec.CommandContext(ctx, "sudo", "/usr/bin/systemctl", "kill", "--kill-who=main", "--signal=SIGKILL", "omnipanel-singbox.service")
	if output, err := secondKill.CombinedOutput(); err != nil {
		t.Fatalf("candidate SIGKILL injection failed: %v (%s)", err, output)
	}
	if err := client.RestoreLastKnownGood(ctx, ref); err != nil {
		t.Fatalf("root watchdog could not restore former LKG following candidate death: %v", err)
	}
	if err := waitForRestoredHostHealth(ctx, client, ref); err != nil {
		t.Fatalf("former LKG health was not re-established following candidate failure: %v", err)
	}
	if err := client.ApplyApprovedCandidate(ctx, candidate); err == nil {
		t.Fatal("a restored LKG must not reset consumed root candidate authorization")
	}
}
