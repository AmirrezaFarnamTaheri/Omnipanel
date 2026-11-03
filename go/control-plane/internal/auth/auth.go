package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"omnipanel/control-plane/internal/store"
)

// Session represents an authenticated admin session.
type Session struct {
	AdminID   int32
	Email     string
	Role      string
	TokenHash string
	ExpiresAt time.Time
}

// Authenticator validates admin sessions and enforces role-based access.
type Authenticator struct {
	store *store.Store
}

func NewAuthenticator(s *store.Store) *Authenticator {
	return &Authenticator{store: s}
}

// SessionFromRequest extracts and validates the omni_session cookie.
func (a *Authenticator) SessionFromRequest(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie("omni_session")
	if err != nil {
		return nil, errors.New("missing session cookie")
	}
	token := cookie.Value
	if token == "" {
		return nil, errors.New("empty session token")
	}

	ctx := r.Context()
	row := a.store.Pool().QueryRow(ctx, `
		SELECT s.admin_id, a.email, a.role, s.expires_at
		FROM admin_sessions s
		JOIN admins a ON a.id = s.admin_id
		WHERE s.token_hash = $1 AND s.expires_at > now()
	`, token)

	var adminID int32
	var email, role string
	var expiresAt time.Time
	if err := row.Scan(&adminID, &email, &role, &expiresAt); err != nil {
		log.Warn().Err(err).Msg("session lookup failed")
		return nil, errors.New("invalid or expired session")
	}

	return &Session{
		AdminID:   adminID,
		Email:     email,
		Role:      role,
		TokenHash: token,
		ExpiresAt: expiresAt,
	}, nil
}

// RequireRole returns middleware that requires the user to have at least the given role.
// Role order: viewer < operator < owner.
func RequireRole(minRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := r.Context().Value(sessionKey{}).(*Session)
			if !ok || sess == nil {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}
			if roleRank(sess.Role) < roleRank(minRole) {
				http.Error(w, `{"error":"insufficient role"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func roleRank(role string) int {
	switch role {
	case "viewer":
		return 1
	case "operator":
		return 2
	case "owner":
		return 3
	default:
		return 0
	}
}

// CSRF checks Origin == Host for non-safe methods.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			origin := r.Header.Get("Origin")
			host := r.Host
			if origin != "" && origin != "https://"+host && origin != "http://"+host {
				http.Error(w, `{"error":"csrf origin mismatch"}`, http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type sessionKey struct{}

func WithSession(sess *Session) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(contextWithSession(r.Context(), sess)))
		})
	}
}

func contextWithSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, sess)
}

func SessionFromContext(ctx context.Context) (*Session, bool) {
	sess, ok := ctx.Value(sessionKey{}).(*Session)
	return sess, ok
}

// ConstantTimeCompare compares two strings in constant time.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// StripBearer extracts the Bearer token from an Authorization header.
func StripBearer(authHeader string) (string, bool) {
	if authHeader == "" {
		return "", false
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}
