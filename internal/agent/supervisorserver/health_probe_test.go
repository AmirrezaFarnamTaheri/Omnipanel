package supervisorserver

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// Previously ObserveKnownGood accepted any open TCP port, even when an
// unrelated process was listening. That could clear an activation guard
// without a working Sing-box listener.
func TestNativeHealthRefusesUnrelatedTCPListener(t *testing.T) {
	fixture, backend := makeNativeFixture(t, "", "")
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err != nil {
		t.Fatal(err)
	}
	// The fixture's listener intentionally accepts no SOCKS protocol.
	// TCP connect succeeds and the fake systemctl reports active.
	healthy, err := backend.ObserveKnownGood(context.Background(), fixture.ref)
	if err == nil && healthy {
		t.Fatal("unrelated open TCP port was accepted as healthy Sing-box")
	}
}

func acceptHealthSOCKS(t *testing.T, listener net.Listener, connectSuccess bool) {
	t.Helper()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(conn, greeting); err != nil {
					return
				}
				if greeting[0] != 5 || greeting[1] != 1 || greeting[2] != 0 {
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				request := make([]byte, 10)
				if _, err := io.ReadFull(conn, request); err != nil {
					return
				}
				if request[0] != 5 || request[1] != 1 || request[3] != 1 ||
					request[4] != 169 || request[5] != 254 || request[6] != 169 ||
					request[7] != 254 || request[8] != 0 || request[9] != 80 {
					return
				}
				reply := byte(2) // Connection not allowed by ruleset.
				if connectSuccess {
					reply = 0
				}
				_, _ = conn.Write([]byte{5, reply, 0, 1, 0, 0, 0, 0, 0, 0})
			}()
		}
	}()
}

func TestNativeHealthRequiresDeniedProtectedSOCKSProbe(t *testing.T) {
	fixture, backend := makeNativeFixture(t, "", "")
	acceptHealthSOCKS(t, fixture.listener, true)
	if err := backend.RestoreKnownGood(context.Background(), fixture.ref); err != nil {
		t.Fatal(err)
	}
	healthy, err := backend.ObserveKnownGood(context.Background(), fixture.ref)
	if err == nil && healthy {
		t.Fatal("a proxy that permits the protected test destination was accepted")
	}
}
