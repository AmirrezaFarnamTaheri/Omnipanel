// Package sessions tracks runtime-owned authenticated sessions independently
// from endpoint-principal entitlement state.
package sessions

import (
	"errors"
	"io"
	"sort"
	"sync"
	"time"
)

var (
	ErrInvalidSession         = errors.New("session ID, principal ID and credential generation are required")
	ErrInvalidEntitlement     = errors.New("entitlements require non-empty principal IDs and positive credential generations")
	ErrPrincipalNotAuthorized = errors.New("endpoint principal is not authorized for this credential generation")
	ErrSessionExists          = errors.New("session ID is already registered")
	ErrInvalidIdleTimeout     = errors.New("idle timeout must be positive")
	ErrInvalidPrincipal       = errors.New("principal ID is required")
)

// CloseFailure records a runtime session that could not be closed. Callers
// should redact the underlying error before writing it to operator-visible logs.
type CloseFailure struct {
	SessionID string
	Err       error
}

// RevocationReport distinguishes closed sessions from sessions that were only
// blocked from opening additional routed flows.
type RevocationReport struct {
	Blocked       int
	Closed        int
	Unclosable    int
	CloseFailures []CloseFailure
}

// CleanupReport describes sessions removed after they exceeded the configured idle window.
type CleanupReport struct {
	Expired       int
	Closed        int
	Unclosable    int
	CloseFailures []CloseFailure
}

type trackedSession struct {
	id                   string
	principalID          string
	credentialGeneration uint64
	createdAt            time.Time
	lastSeenAt           time.Time
	blocked              bool
	closer               io.Closer
}

type closeTarget struct {
	session *trackedSession
}

// SessionSnapshot contains bounded operational state without exposing
// credentials, remote addresses or runtime-specific connection metadata.
type SessionSnapshot struct {
	ID                   string
	PrincipalID          string
	CredentialGeneration uint64
	CreatedAt            time.Time
	LastSeenAt           time.Time
	Blocked              bool
	HasCloser            bool
}

// Registry is owned by one runtime instance on one node. Session IDs must be
// opaque, runtime-generated identifiers, not client IP addresses: NAT rebinding
// and shared source addresses must not merge different authenticated sessions.
type Registry struct {
	mu           sync.Mutex
	sessions     map[string]*trackedSession
	entitlements map[string]uint64
	now          func() time.Time
}

func NewRegistry() *Registry {
	return NewRegistryWithClock(time.Now)
}

// NewRegistryWithClock allows the agent and tests to use a consistent clock.
func NewRegistryWithClock(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{
		sessions:     make(map[string]*trackedSession),
		entitlements: make(map[string]uint64),
		now:          now,
	}
}

// ReconcileEntitlements atomically replaces the authorized endpoint-principal
// snapshot. Sessions for removed principals or older credential generations
// become permanently blocked. A later re-enable requires a new runtime session.
func (r *Registry) ReconcileEntitlements(entitlements map[string]uint64) (RevocationReport, error) {
	authorized := make(map[string]uint64, len(entitlements))
	for principalID, generation := range entitlements {
		if principalID == "" || generation == 0 {
			return RevocationReport{}, ErrInvalidEntitlement
		}
		authorized[principalID] = generation
	}

	r.mu.Lock()
	r.entitlements = authorized
	report, targets := r.blockLocked(func(session *trackedSession) bool {
		generation, allowed := authorized[session.principalID]
		return !allowed || generation != session.credentialGeneration
	})
	r.mu.Unlock()

	r.closeTargets(&report, targets)
	return report, nil
}

// Register associates a new authenticated runtime session with an active
// endpoint principal and its current credential generation.
func (r *Registry) Register(sessionID, principalID string, credentialGeneration uint64, closer io.Closer) error {
	if sessionID == "" || principalID == "" || credentialGeneration == 0 {
		return ErrInvalidSession
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	generation, allowed := r.entitlements[principalID]
	if !allowed || generation != credentialGeneration {
		return ErrPrincipalNotAuthorized
	}
	if _, exists := r.sessions[sessionID]; exists {
		return ErrSessionExists
	}

	now := r.now()
	r.sessions[sessionID] = &trackedSession{
		id:                   sessionID,
		principalID:          principalID,
		credentialGeneration: credentialGeneration,
		createdAt:            now,
		lastSeenAt:           now,
		closer:               closer,
	}
	return nil
}

// CanRoute must be checked before routing each new flow opened on a tracked
// session. A blocked session cannot create additional routed connections.
func (r *Registry) CanRoute(sessionID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, exists := r.sessions[sessionID]
	if !exists || session.blocked {
		return false
	}
	generation, allowed := r.entitlements[session.principalID]
	if !allowed || generation != session.credentialGeneration {
		session.blocked = true
		return false
	}
	return true
}

// Touch updates liveness only while the session remains authorized.
func (r *Registry) Touch(sessionID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, exists := r.sessions[sessionID]
	if !exists || session.blocked {
		return false
	}
	generation, allowed := r.entitlements[session.principalID]
	if !allowed || generation != session.credentialGeneration {
		session.blocked = true
		return false
	}
	session.lastSeenAt = r.now()
	return true
}

// DisconnectPrincipal terminates or mutes the principal's current sessions
// without changing its entitlement. New sessions may still authenticate.
func (r *Registry) DisconnectPrincipal(principalID string) (RevocationReport, error) {
	if principalID == "" {
		return RevocationReport{}, ErrInvalidPrincipal
	}

	r.mu.Lock()
	report, targets := r.blockLocked(func(session *trackedSession) bool {
		return session.principalID == principalID
	})
	r.mu.Unlock()

	r.closeTargets(&report, targets)
	return report, nil
}

// PruneIdle blocks and forgets sessions that have not refreshed liveness
// within maxIdle. Runtime closers are retried outside the registry lock; a
// session without a closer is forgotten but remains unroutable because its ID
// is no longer registered.
func (r *Registry) PruneIdle(maxIdle time.Duration) (CleanupReport, error) {
	if maxIdle <= 0 {
		return CleanupReport{}, ErrInvalidIdleTimeout
	}

	now := r.now()
	r.mu.Lock()
	var report CleanupReport
	var targets []closeTarget
	for sessionID, session := range r.sessions {
		if now.Sub(session.lastSeenAt) <= maxIdle {
			continue
		}
		report.Expired++
		session.blocked = true
		if session.closer == nil {
			report.Unclosable++
			delete(r.sessions, sessionID)
			continue
		}
		targets = append(targets, closeTarget{session: session})
	}
	r.mu.Unlock()

	for _, target := range targets {
		session := target.session
		if err := session.closer.Close(); err != nil {
			report.CloseFailures = append(report.CloseFailures, CloseFailure{
				SessionID: session.id,
				Err:       err,
			})
			continue
		}
		report.Closed++
		r.mu.Lock()
		if r.sessions[session.id] == session {
			delete(r.sessions, session.id)
		}
		r.mu.Unlock()
	}
	return report, nil
}

// Unregister removes a session after its runtime reports that it has ended.
func (r *Registry) Unregister(sessionID string) {
	if sessionID == "" {
		return
	}
	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()
}

// Snapshot returns a stable, sorted view suitable for bounded diagnostics.
func (r *Registry) Snapshot() []SessionSnapshot {
	r.mu.Lock()
	snapshot := make([]SessionSnapshot, 0, len(r.sessions))
	for _, session := range r.sessions {
		snapshot = append(snapshot, SessionSnapshot{
			ID:                   session.id,
			PrincipalID:          session.principalID,
			CredentialGeneration: session.credentialGeneration,
			CreatedAt:            session.createdAt,
			LastSeenAt:           session.lastSeenAt,
			Blocked:              session.blocked,
			HasCloser:            session.closer != nil,
		})
	}
	r.mu.Unlock()

	sort.Slice(snapshot, func(i, j int) bool {
		return snapshot[i].ID < snapshot[j].ID
	})
	return snapshot
}

func (r *Registry) blockLocked(matches func(*trackedSession) bool) (RevocationReport, []closeTarget) {
	var report RevocationReport
	var targets []closeTarget

	for _, session := range r.sessions {
		if session.blocked || !matches(session) {
			continue
		}
		session.blocked = true
		report.Blocked++
		if session.closer == nil {
			report.Unclosable++
			continue
		}
		targets = append(targets, closeTarget{session: session})
	}
	return report, targets
}

// closeTargets deliberately runs runtime callbacks outside the registry lock.
// Closing a session commonly calls back into Unregister; holding the lock here
// would deadlock the runtime's own close handler.
func (r *Registry) closeTargets(report *RevocationReport, targets []closeTarget) {
	for _, target := range targets {
		session := target.session
		if err := session.closer.Close(); err != nil {
			report.CloseFailures = append(report.CloseFailures, CloseFailure{
				SessionID: session.id,
				Err:       err,
			})
			continue
		}

		report.Closed++
		r.mu.Lock()
		if r.sessions[session.id] == session {
			delete(r.sessions, session.id)
		}
		r.mu.Unlock()
	}
}
