package supervisoripc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testRef = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type testRequest struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	Reference string `json:"reference"`
}

func serveLocalSupervisor(t *testing.T, respond func(testRequest) string) (string, <-chan testRequest) {
	t.Helper()
	private := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "supervisor.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	requests := make(chan testRequest, 10)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var req testRequest
				if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
					return
				}
				requests <- req
				_, _ = conn.Write([]byte(respond(req)))
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		wg.Wait()
	})
	return path, requests
}

func TestSupervisorIPCUsesOnlyFixedVerbsAndExactReferencedGeneration(t *testing.T) {
	path, requests := serveLocalSupervisor(t, func(req testRequest) string {
		return `{"version":1,"operation":"` + req.Operation + `","reference":"` + req.Reference + `","ok":true,"healthy":true}`
	})
	client, err := newClient(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RestoreLastKnownGood(context.Background(), testRef); err != nil {
		t.Fatal(err)
	}
	healthy, err := client.ObserveLastKnownGood(context.Background(), testRef)
	if err != nil || !healthy {
		t.Fatalf("verified generation health was not returned: healthy=%t err=%v", healthy, err)
	}
	first, second := <-requests, <-requests
	if first.Version != 1 || first.Operation != "restore-known-good" || first.Reference != testRef ||
		second.Version != 1 || second.Operation != "observe-known-good" || second.Reference != testRef {
		t.Fatalf("client transmitted unexpected privileged operation: %+v %+v", first, second)
	}
}

func TestSupervisorIPCRejectsUnsafeSocketPathsAndUntrustedPeers(t *testing.T) {
	path, _ := serveLocalSupervisor(t, func(req testRequest) string { return "{}" })
	if _, err := newClient("../run/supervisor.sock", uint32(os.Geteuid())); err == nil {
		t.Fatal("relative Unix path accepted")
	}
	link := filepath.Join(filepath.Dir(path), "symlink.sock")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := newClient(link, uint32(os.Geteuid())); err == nil {
		t.Fatal("symlinked supervisor accepted")
	}
	if _, err := newClient(path, uint32(os.Geteuid())+1); err == nil {
		t.Fatal("unexpected socket owner accepted")
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := newClient(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("world-writable supervisor socket accepted")
	}
}

func TestSupervisorIPCRejectsMalformedRepliesAndWrongEcho(t *testing.T) {
	cases := map[string]string{
		"wrong digest":    `{"version":1,"operation":"restore-known-good","reference":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ok":true,"healthy":true}`,
		"wrong operation": `{"version":1,"operation":"observe-known-good","reference":"` + testRef + `","ok":true,"healthy":true}`,
		"trailing data":   `{"version":1,"operation":"restore-known-good","reference":"` + testRef + `","ok":true,"healthy":true} 123`,
		"oversized":       strings.Repeat("X", 5000),
		"unacknowledged":  `{"version":1,"operation":"restore-known-good","reference":"` + testRef + `","ok":false,"healthy":true}`,
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			path, _ := serveLocalSupervisor(t, func(req testRequest) string { return reply })
			c, err := newClient(path, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.RestoreLastKnownGood(context.Background(), testRef); err == nil {
				t.Fatal("invalid supervisor acknowledgment was accepted")
			}
		})
	}
}

func TestSupervisorIPCRejectsArbitraryReferencesBeforeDial(t *testing.T) {
	path, requests := serveLocalSupervisor(t, func(req testRequest) string {
		return "{}"
	})
	client, err := newClient(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"", "../etc/shadow", "sha256:wrong", testRef + "/etc/passwd"} {
		if err := client.RestoreLastKnownGood(context.Background(), ref); err == nil {
			t.Fatalf("malformed digest sent to privileged supervisor: %q", ref)
		}
	}
	select {
	case req := <-requests:
		t.Fatalf("invalid reference reached privileged socket: %+v", req)
	default:
	}
}

func TestSupervisorIPCRefusesUnresponsiveRootService(t *testing.T) {
	path, _ := serveLocalSupervisor(t, func(req testRequest) string {
		time.Sleep(180 * time.Millisecond)
		return "{}"
	})
	client, err := newClient(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = client.ObserveLastKnownGood(ctx, testRef)
	if err == nil || time.Since(start) > 170*time.Millisecond {
		t.Fatalf("supervisor socket did not fail closed before client deadline: %v", err)
	}
}

func TestSupervisorIPCRootConstructorRequiresRootOwnedPeer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test exercises the nonroot runner")
	}
	path, _ := serveLocalSupervisor(t, func(req testRequest) string { return "{}" })
	if _, err := New(path); err == nil {
		t.Fatal("production constructor accepted non-root-owned supervisor")
	}
}

func TestSupervisorIPCUnhealthyObservationIsNotSuccessfulRecovery(t *testing.T) {
	path, _ := serveLocalSupervisor(t, func(req testRequest) string {
		return `{"version":1,"operation":"` + req.Operation + `","reference":"` + req.Reference + `","ok":true,"healthy":false}`
	})
	client, err := newClient(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := client.ObserveLastKnownGood(context.Background(), testRef)
	if err != nil || healthy {
		t.Fatalf("unhealthy LKG must not be reported healthy: %t %v", healthy, err)
	}
}

var _ = errors.Is
