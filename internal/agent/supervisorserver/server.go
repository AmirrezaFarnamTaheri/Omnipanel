// Package supervisorserver implements a root-side, fixed-verb local rollback
// protocol. A caller can select only a locally allowlisted SHA-256 generation;
// no command, filesystem path, service unit or raw config comes from the wire.
package supervisorserver

import (
	"bufio"
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
	maxRequestBytes = 2048
	serverDeadline  = 3 * time.Second
	maxGenerations  = 32
)

var (
	ErrUntrustedServer   = errors.New("root supervisor socket, credentials or generation policy rejected")
	ErrServerUnavailable = errors.New("root supervisor server unavailable")
	generationPattern    = regexp.MustCompile("^sha256:[a-f0-9]{64}$")
)

// Config is root-provisioned; the request must never contain or influence it.
// Only one exact non-root UID/GID may issue rollback and health requests.
type Config struct {
	SocketPath         string
	WatchdogUID        uint32
	WatchdogGID        uint32
	AllowedGenerations map[string]bool
}

// Backend must independently enforce generation pinning, native validation
// and health. An injected test backend is NOT a production runtime supervisor.
type Backend interface {
	RestoreKnownGood(context.Context, string) error
	ObserveKnownGood(context.Context, string) (bool, error)
}

type Server struct {
	cfg     Config
	backend Backend
	rootUID uint32
	allowed map[string]bool
}

// New only authorizes an actual root process and requires a non-root watchdog.
func New(cfg Config, backend Backend) (*Server, error) {
	if os.Geteuid() != 0 || cfg.WatchdogUID == 0 || cfg.WatchdogGID == 0 {
		return nil, ErrUntrustedServer
	}
	return newServer(cfg, backend, 0)
}

// newServer is package-private test injection of the expected local server
// owner, not a production API that disables SO_PEERCRED authentication.
func newServer(cfg Config, backend Backend, trustedServerUID uint32) (*Server, error) {
	if os.Geteuid() != int(trustedServerUID) || backend == nil ||
		cfg.SocketPath == "" || !filepath.IsAbs(cfg.SocketPath) ||
		filepath.Clean(cfg.SocketPath) != cfg.SocketPath ||
		strings.IndexByte(cfg.SocketPath, 0) >= 0 ||
		len(cfg.SocketPath) >= 108 || len(cfg.AllowedGenerations) == 0 ||
		len(cfg.AllowedGenerations) > maxGenerations {
		return nil, ErrUntrustedServer
	}
	allowed := make(map[string]bool, len(cfg.AllowedGenerations))
	for generation, approved := range cfg.AllowedGenerations {
		if !approved || !generationPattern.MatchString(generation) {
			return nil, ErrUntrustedServer
		}
		allowed[generation] = true
	}
	s := &Server{cfg: cfg, rootUID: trustedServerUID, backend: backend, allowed: allowed}
	if err := s.verifyDirectory(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) verifyDirectory() error {
	if s == nil || s.cfg.SocketPath == "" {
		return ErrUntrustedServer
	}
	d, err := os.Lstat(filepath.Dir(s.cfg.SocketPath))
	if err != nil || !d.IsDir() || d.Mode().Perm()&0o027 != 0 {
		return ErrUntrustedServer
	}
	stat, ok := d.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != s.rootUID {
		return ErrUntrustedServer
	}
	// The watchdog's group must own a group-traversable parent. No other
	// group can be used to grant access to a root socket.
	if d.Mode().Perm()&0o070 != 0 && stat.Gid != s.cfg.WatchdogGID {
		return ErrUntrustedServer
	}
	return nil
}

func peerCredentials(conn *net.UnixConn) (uint32, uint32, error) {
	var uid, gid uint32
	var credentialErr error
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, ErrUntrustedServer
	}
	if err := raw.Control(func(fd uintptr) {
		creds, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e != nil || creds == nil || creds.Pid <= 0 {
			credentialErr = ErrUntrustedServer
			return
		}
		uid, gid = creds.Uid, creds.Gid
	}); err != nil || credentialErr != nil {
		return 0, 0, ErrUntrustedServer
	}
	return uid, gid, nil
}

type request struct {
	version   int
	operation string
	reference string
}

// decodeRequest accepts exactly three case-sensitive fields, once each, with
// one bounded newline-terminated JSON object. No arbitrary nested or trailing
// values and no duplicate fields are accepted by the privileged process.
func decodeRequest(raw []byte) (request, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return request{}, ErrUntrustedServer
	}
	seen := make(map[string]bool, 3)
	var r request
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return request{}, ErrUntrustedServer
		}
		seen[key] = true
		switch key {
		case "version":
			err = decoder.Decode(&r.version)
		case "operation":
			err = decoder.Decode(&r.operation)
		case "reference":
			err = decoder.Decode(&r.reference)
		default:
			return request{}, ErrUntrustedServer
		}
		if err != nil {
			return request{}, ErrUntrustedServer
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 3 {
		return request{}, ErrUntrustedServer
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return request{}, ErrUntrustedServer
	}
	if r.version != protocolVersion ||
		(r.operation != "restore-known-good" && r.operation != "observe-known-good") ||
		!generationPattern.MatchString(r.reference) {
		return request{}, ErrUntrustedServer
	}
	return r, nil
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(serverDeadline)); err != nil {
		return
	}
	uid, gid, err := peerCredentials(conn)
	if err != nil || uid != s.cfg.WatchdogUID || gid != s.cfg.WatchdogGID {
		return
	}
	// Read only through the first newline. A client cannot wait for an
	// arbitrarily long payload or keep the root server blocked indefinitely.
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequestBytes+1)).ReadBytes('\n')
	if err != nil || len(line) == 0 || len(line) > maxRequestBytes {
		return
	}
	req, err := decodeRequest(line)
	if err != nil || !s.allowed[req.reference] {
		return
	}
	operationCtx, cancel := context.WithTimeout(ctx, serverDeadline)
	defer cancel()
	ok := false
	healthy := false
	switch req.operation {
	case "restore-known-good":
		ok = s.backend.RestoreKnownGood(operationCtx, req.reference) == nil
	case "observe-known-good":
		var backendErr error
		healthy, backendErr = s.backend.ObserveKnownGood(operationCtx, req.reference)
		ok = backendErr == nil
		if !ok {
			healthy = false
		}
	}
	// No backend error text, runtime logs, private config, or OS path is ever
	// transmitted to a lower-trust watchdog.
	_ = json.NewEncoder(conn).Encode(map[string]any{
		"version":   protocolVersion,
		"operation": req.operation,
		"reference": req.reference,
		"ok":        ok,
		"healthy":   healthy && ok && req.operation == "observe-known-good",
	})
}

// Serve owns one Unix-domain socket path. It never unlinks or replaces a
// preexisting file; root-owned parent prevents untrusted socket substitution.
// Each authenticated request is processed serially with a bounded deadline.
func (s *Server) Serve(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrUntrustedServer
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	if err := s.verifyDirectory(); err != nil {
		return err
	}
	if _, err := os.Lstat(s.cfg.SocketPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return ErrUntrustedServer
	}
	addr := &net.UnixAddr{Name: s.cfg.SocketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return ErrServerUnavailable
	}
	defer listener.Close()
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(s.cfg.SocketPath, 0o660); err != nil {
		return ErrUntrustedServer
	}
	if os.Getegid() != int(s.cfg.WatchdogGID) {
		if err := os.Chown(s.cfg.SocketPath, -1, int(s.cfg.WatchdogGID)); err != nil {
			return ErrUntrustedServer
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrServerUnavailable
		}
		s.handle(ctx, conn)
	}
}
