// Package supervisoripc connects an unprivileged watchdog to a separately
// installed, root-owned rollback supervisor over a local Unix-domain socket.
// It cannot execute arbitrary commands, accept paths or dial network hosts.
package supervisoripc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	protocolVersion = 1
	maxReplyBytes   = 4096
	requestTimeout  = 3 * time.Second
)

var (
	ErrUntrustedSupervisor = errors.New("root supervisor IPC identity or response refused")
	ErrSupervisorUnavailable = errors.New("root supervisor IPC unavailable")
	refPattern = regexp.MustCompile("^sha256:[a-f0-9]{64}$")
)

// Client trusts only the peer UID assigned locally at construction. Production
// always requires UID 0; tests exercise the same Unix transport using the
// test runner's UID without weakening New's production trust requirement.
type Client struct {
	socketPath string
	expectedUID uint32
}

// New permits only a root-owned socket in a root-owned non-writable directory.
// It never permits operator-supplied credentials or a non-root UID override.
func New(socketPath string) (*Client, error) {
	return newClient(socketPath, 0)
}

func newClient(socketPath string, expectedUID uint32) (*Client, error) {
	c := &Client{socketPath: socketPath, expectedUID: expectedUID}
	if err := c.verifySocket(); err != nil {
		return nil, err
	}
	return c, nil
}

func ownedBy(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid
}

func (c *Client) verifySocket() error {
	if c == nil || c.socketPath == "" ||
		!filepath.IsAbs(c.socketPath) || filepath.Clean(c.socketPath) != c.socketPath ||
		strings.IndexByte(c.socketPath, 0) >= 0 || len(c.socketPath) >= 100 {
		return ErrUntrustedSupervisor
	}
	parent, err := os.Lstat(filepath.Dir(c.socketPath))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 ||
		!ownedBy(parent, c.expectedUID) {
		return ErrUntrustedSupervisor
	}
	sock, err := os.Lstat(c.socketPath)
	if err != nil || sock.Mode()&os.ModeSocket == 0 || sock.Mode().Perm()&0o007 != 0 ||
		!ownedBy(sock, c.expectedUID) {
		return ErrUntrustedSupervisor
	}
	return nil
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	var uid uint32
	var credentialErr error
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, ErrUntrustedSupervisor
	}
	err = raw.Control(func(fd uintptr) {
		var creds *syscall.Ucred
		creds, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if credentialErr == nil && creds != nil && creds.Pid > 0 {
			uid = creds.Uid
		} else {
			credentialErr = ErrUntrustedSupervisor
		}
	})
	if err != nil || credentialErr != nil {
		return 0, ErrUntrustedSupervisor
	}
	return uid, nil
}

type request struct {
	Version int `json:"version"`
	Operation string `json:"operation"`
	Reference string `json:"reference"`
}

type response struct {
	Version int `json:"version"`
	Operation string `json:"operation"`
	Reference string `json:"reference"`
	OK bool `json:"ok"`
	Healthy bool `json:"healthy"`
}

// exchange sends one bounded, fixed-schema request on one Unix connection.
// The root peer must echo the exact verb and SHA-256 generation reference.
// No caller-controlled path, script, or shell command can cross this boundary.
func (c *Client) exchange(ctx context.Context, operation, reference string) (response, error) {
	if ctx == nil || ctx.Err() != nil || !refPattern.MatchString(reference) ||
		(operation != "restore-known-good" && operation != "observe-known-good") {
		return response{}, ErrUntrustedSupervisor
	}
	if err := c.verifySocket(); err != nil {
		return response{}, err
	}
	dialer := &net.Dialer{Timeout: requestTimeout}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return response{}, ErrSupervisorUnavailable
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return response{}, ErrUntrustedSupervisor
	}
	uid, err := peerUID(unixConn)
	if err != nil || uid != c.expectedUID {
		return response{}, ErrUntrustedSupervisor
	}
	deadline := time.Now().Add(requestTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return response{}, ErrSupervisorUnavailable
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopCancel()
	if err := json.NewEncoder(conn).Encode(request{
		Version: protocolVersion, Operation: operation, Reference: reference,
	}); err != nil {
		return response{}, ErrSupervisorUnavailable
	}
	// This protocol is one request/response per connection. A server that
	// never closes the response times out rather than leaving a hanging guard.
	raw, err := io.ReadAll(io.LimitReader(conn, maxReplyBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxReplyBytes {
		return response{}, ErrSupervisorUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var reply response
	if err := decoder.Decode(&reply); err != nil {
		return response{}, ErrUntrustedSupervisor
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return response{}, ErrUntrustedSupervisor
	}
	if reply.Version != protocolVersion || reply.Operation != operation ||
		reply.Reference != reference || !reply.OK {
		return response{}, ErrUntrustedSupervisor
	}
	return reply, nil
}

func (c *Client) RestoreLastKnownGood(ctx context.Context, reference string) error {
	_, err := c.exchange(ctx, "restore-known-good", reference)
	return err
}

// ObserveLastKnownGood returns true ONLY when the root peer explicitly reports
// that the exact rollback generation is independently observed healthy.
func (c *Client) ObserveLastKnownGood(ctx context.Context, reference string) (bool, error) {
	reply, err := c.exchange(ctx, "observe-known-good", reference)
	if err != nil {
		return false, err
	}
	return reply.Healthy, nil
}
