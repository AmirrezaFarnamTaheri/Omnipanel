package supervisorserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// readProbeRequest reads one complete SOCKS5 CONNECT request, including its
// variable-length address and port. This is deliberately test-only protocol
// parsing, so a fake server cannot make a partial response look successful.
func readProbeRequest(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 1 || header[2] != 0 {
		return nil, errors.New("unexpected SOCKS5 request header")
	}
	size := 0
	switch header[3] {
	case 1:
		size = 4 + 2
	case 4:
		size = 16 + 2
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(r, length); err != nil {
			return nil, err
		}
		if length[0] == 0 {
			return nil, errors.New("empty domain name")
		}
		header = append(header, length[0])
		size = int(length[0]) + 2
	default:
		return nil, errors.New("unsupported SOCKS5 address type")
	}
	tail := make([]byte, size)
	if _, err := io.ReadFull(r, tail); err != nil {
		return nil, err
	}
	return append(header, tail...), nil
}

func testProbeServer(t *testing.T, answer func([]byte) []byte) (string, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := new(atomic.Int64)
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
				if _, err := io.ReadFull(conn, greeting); err != nil ||
					!bytes.Equal(greeting, []byte{5, 1, 0}) {
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				req, err := readProbeRequest(conn)
				if err != nil {
					return
				}
				received.Add(1)
				response := answer(req)
				if len(response) != 0 {
					_, _ = conn.Write(response)
				}
			}()
		}
	}()
	return listener.Addr().String(), received
}

var completePolicyDenial = []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}
var completeSuccess = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
var metadataSOCKSRequest = []byte{5, 1, 0, 1, 169, 254, 169, 254, 0, 80}

func TestProtectedSOCKSHealthRejectsGenericErrorsAndTruncatedReplies(t *testing.T) {
	cases := []struct {
		name  string
		reply []byte
	}{
		{"network unreachable is not a ruleset denial", []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"header without bound address or port", []byte{5, 2, 0, 1}},
		{"truncated IPv6 response", []byte{5, 2, 0, 4, 0, 0, 0}},
		{"truncated domain response", []byte{5, 2, 0, 3, 4, 't', 'e'}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			address, _ := testProbeServer(t, func([]byte) []byte { return tc.reply })
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := probeProtectedSOCKSDenial(ctx, address); err == nil {
				t.Fatal("malformed or non-policy SOCKS5 result was accepted as safe egress")
			}
		})
	}
}

func TestProtectedSOCKSHealthRejectsProxyAllowingOtherProtectedDestinations(t *testing.T) {
	address, requests := testProbeServer(t, func(req []byte) []byte {
		if bytes.Equal(req, metadataSOCKSRequest) {
			return completePolicyDenial
		}
		return completeSuccess // Maliciously permit every other protected target.
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeProtectedSOCKSDenial(ctx, address); err == nil {
		t.Fatal("metadata-only denial was accepted despite other protected destinations being permitted")
	}
	if requests.Load() < 2 {
		t.Fatal("health check did not test beyond the metadata destination")
	}
}

func TestProtectedSOCKSHealthRequiresCompletePolicyDenialsForAllCanaries(t *testing.T) {
	address, requests := testProbeServer(t, func([]byte) []byte { return completePolicyDenial })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeProtectedSOCKSDenial(ctx, address); err != nil {
		t.Fatalf("proxy that explicitly denies protected canaries should pass local observation: %v", err)
	}
	if got := requests.Load(); got < 12 {
		t.Fatalf("only %d canaries were tested: require IPv4, IPv6 and protected hostname coverage", got)
	}
}
