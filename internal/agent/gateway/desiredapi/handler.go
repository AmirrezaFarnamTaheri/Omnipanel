// Package desiredapi is a read-only, node-certificate-authorized HTTP
// boundary for a signed desired-state snapshot. It cannot sign, enroll, apply,
// or report runtime state. It is not a deployable control-plane service.
package desiredapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/pki/enrollment"
)

var (
	ErrInvalidConfig = errors.New("invalid node desired-state gateway configuration")
	identityPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	trustDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

const (
	desiredPath = "/v2/nodes/self/desired"
	maxSequence = 9007199254740991
)

// Snapshot must come from a server-side, authenticated node-scoped store.
// Epoch is its independently authorized control-plane history, not a query
// parameter. Envelope holds a previously signed manifest, never raw secrets.
type Snapshot struct {
	Epoch string
	Envelope []byte
}

// Source returns only the current immutable snapshot for the authenticated
// node. A production adapter must bind the record and epoch in one read.
type Source interface {
	Latest(context.Context, string) (Snapshot, error)
}

// Handler never trusts forwarded certificate headers, request-supplied node
// IDs or an unverified signed envelope. TLS termination must use Go's TLS stack
// (TLS 1.3, RequireAndVerifyClientCert); the live PKI ledger is consulted on
// every request, including before a no-change response.
type Handler struct {
	ledger enrollment.TokenStore
	source Source
	trustDomain string
	verifier manifest.Verifier
	now func() time.Time
}

func NewHandler(ledger enrollment.TokenStore, source Source, trustDomain string, verifier manifest.Verifier, now func() time.Time) (*Handler, error) {
	if ledger == nil || source == nil || now == nil ||
		!trustDomainPattern.MatchString(trustDomain) ||
		len(verifier.TrustedSigners) == 0 ||
		len(verifier.AllowedCapabilities) == 0 ||
		len(verifier.QualifiedBuilds) == 0 ||
		verifier.MaxClockSkew < 0 {
		return nil, ErrInvalidConfig
	}
	return &Handler{ledger: ledger, source: source, trustDomain: trustDomain, verifier: verifier, now: now}, nil
}

func readCursor(raw string) (uint64, bool) {
	if raw == "" || len(raw) > 16 {
		return 0, false
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	return value, err == nil && value <= maxSequence && strconv.FormatUint(value, 10) == raw
}

func parseRequestQuery(raw string) (string, uint64, uint64, bool) {
	query, err := url.ParseQuery(raw)
	if err != nil || len(query) != 3 {
		return "", 0, 0, false
	}
	keys := []string{"controlPlaneEpoch", "structuralSequence", "membershipSequence"}
	for _, key := range keys {
		if len(query[key]) != 1 {
			return "", 0, 0, false
		}
	}
	epoch := query.Get("controlPlaneEpoch")
	if !identityPattern.MatchString(epoch) {
		return "", 0, 0, false
	}
	structure, validStructure := readCursor(query.Get("structuralSequence"))
	membership, validMembership := readCursor(query.Get("membershipSequence"))
	return epoch, structure, membership, validStructure && validMembership
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path != desiredPath {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h == nil || h.ledger == nil || h.source == nil || h.now == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.TLS == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	at := h.now().UTC()
	node, err := enrollment.AuthenticatePeer(r.Context(), *r.TLS, h.ledger, h.trustDomain, at)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.ContentLength > 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	epoch, structure, membership, ok := parseRequestQuery(r.URL.RawQuery)
	if !ok {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return
	}
	snapshot, err := h.source.Latest(r.Context(), node)
	if err != nil || !identityPattern.MatchString(snapshot.Epoch) || len(snapshot.Envelope) == 0 {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if snapshot.Epoch != epoch {
		http.Error(w, "recovery approval required", http.StatusConflict)
		return
	}

	// Verify the stored snapshot before returning even a 204: an unsigned,
	// corrupted or unqualified record cannot masquerade as 'no change'.
	verifier := h.verifier
	verifier.NodeID = node
	verifier.AuthorizedEpoch = snapshot.Epoch
	verifier.Current = manifest.Cursor{}
	verifier.Now = func() time.Time { return at }
	verified, err := verifier.Verify(snapshot.Envelope)
	if err != nil || verified.Decision != manifest.ApplyRevision {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if structure > verified.Manifest.StructuralSequence || membership > verified.Manifest.MembershipSequence {
		http.Error(w, "recovery approval required", http.StatusConflict)
		return
	}
	if structure == verified.Manifest.StructuralSequence && membership == verified.Manifest.MembershipSequence {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(snapshot.Envelope)
}
