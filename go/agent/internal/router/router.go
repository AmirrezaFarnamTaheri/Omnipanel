package router

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"omnipanel/agent/config"
	"omnipanel/agent/internal/state"
)

// New builds the agent HTTP router with middleware and routes.
func New(cfg *config.Config, st *state.Store) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Agent control-plane client routes (outbound, called by the agent loop,
	// not exposed as HTTP endpoints here). Kept as package-level functions
	// used by the agent background poller.

	_ = cfg
	_ = st

	return r
}

// placeholder to avoid unused import warnings during partial builds.
var _ = time.Second
