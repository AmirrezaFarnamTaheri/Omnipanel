package router

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"omnipanel/control-plane/config"
	"omnipanel/control-plane/internal/handlers"
	"omnipanel/control-plane/internal/store"
)

// New builds the chi router with middleware and all registered routes.
// The store and config are injected into each request's context.
func New(cfg *config.Config, s *store.Store) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Inject store and config into request context
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, storeKey{}, s)
			ctx = context.WithValue(ctx, cfgKey{}, cfg)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Health
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Mount API routes
	r.Mount("/v1", handlers.Routes(cfg, s))

	return r
}

type storeKey struct{}
type cfgKey struct{}
