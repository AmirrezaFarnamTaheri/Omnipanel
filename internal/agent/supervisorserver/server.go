// Package supervisorserver implements the root-side fixed-verb rollback
// transport. No arbitrary shell, config, path or runtime mutation is accepted.
package supervisorserver

import (
	"context"
	"errors"
)

var ErrUnavailable = errors.New("root supervisor server is not implemented")

type Config struct {
	SocketPath string
	WatchdogUID uint32
	WatchdogGID uint32
	AllowedGenerations map[string]bool
}

type Backend interface {
	RestoreKnownGood(context.Context, string) error
	ObserveKnownGood(context.Context, string) (bool, error)
}

type Server struct{}

func New(cfg Config, backend Backend) (*Server, error) {
	return nil, ErrUnavailable
}

// newServer is the test seam: it exercises exactly the production code with
// an explicitly configured trusted server UID, not a skip-auth mode.
func newServer(cfg Config, backend Backend, trustedServerUID uint32) (*Server, error) {
	return nil, ErrUnavailable
}

func (s *Server) Serve(ctx context.Context) error {
	return ErrUnavailable
}
