package certificates

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidCertificateEntry = errors.New("certificates: invalid certificate inventory entry")
	ErrInsecureFallbackRefused = errors.New("certificates: silent insecure or self-signed TLS fallback is forbidden")
	ErrBoundaryViolation       = errors.New("certificates: TLS trust boundary violation")
)

type TrustBoundary string

const (
	BoundaryNodeMTLS      TrustBoundary = "node_mtls"
	BoundaryACMEPublicTLS TrustBoundary = "acme_public_tls"
	BoundaryRealityDecoy  TrustBoundary = "reality_decoy"
	BoundaryCDNOrigin     TrustBoundary = "cdn_origin"
)

type LifecycleState string

const (
	StateHealthy            LifecycleState = "healthy"
	StateRenewalDue         LifecycleState = "renewal_due"
	StateRateLimitedBackoff LifecycleState = "rate_limited_backoff"
	StateExpired            LifecycleState = "expired"
	StateRevoked            LifecycleState = "revoked"
)

type Entry struct {
	CertID                string
	DomainOrSAN           string
	Boundary              TrustBoundary
	SHA256Fingerprint     string
	NotBefore             time.Time
	NotAfter              time.Time
	AutoRenewEnabled      bool
	FailedRenewalAttempts int
	Revoked               bool
	AllowInsecureFallback bool
}

type Evaluation struct {
	CertID                    string
	Boundary                  TrustBoundary
	State                     LifecycleState
	DaysRemaining             int
	RecommendedBackoffSeconds int
}

func EvaluateEntry(e Entry, now time.Time) (Evaluation, error) {
	if strings.TrimSpace(e.CertID) == "" || strings.TrimSpace(e.DomainOrSAN) == "" {
		return Evaluation{}, ErrInvalidCertificateEntry
	}
	if e.AllowInsecureFallback {
		return Evaluation{}, ErrInsecureFallbackRefused
	}
	if len(e.SHA256Fingerprint) != 64 {
		return Evaluation{}, fmt.Errorf("%w: fingerprint must be 64 hex chars", ErrInvalidCertificateEntry)
	}
	if !e.NotAfter.After(e.NotBefore) || e.FailedRenewalAttempts < 0 {
		return Evaluation{}, ErrInvalidCertificateEntry
	}
	switch e.Boundary {
	case BoundaryNodeMTLS:
		if !strings.HasPrefix(e.DomainOrSAN, "spiffe://omnipanel/node/") {
			return Evaluation{}, fmt.Errorf("%w: node_mtls requires spiffe:// URI SAN", ErrBoundaryViolation)
		}
	case BoundaryRealityDecoy:
		if e.AutoRenewEnabled {
			return Evaluation{}, fmt.Errorf("%w: reality_decoy must not enable ACME auto-renewal", ErrBoundaryViolation)
		}
	case BoundaryACMEPublicTLS, BoundaryCDNOrigin:
	default:
		return Evaluation{}, ErrBoundaryViolation
	}

	daysRemaining := int(e.NotAfter.Sub(now).Hours() / 24)
	backoff := 0
	if e.FailedRenewalAttempts > 0 {
		shift := e.FailedRenewalAttempts - 1
		if shift > 10 {
			shift = 10
		}
		backoff = 60 * (1 << shift)
		if backoff > 86400 {
			backoff = 86400
		}
	}

	state := StateHealthy
	switch {
	case e.Revoked:
		state = StateRevoked
	case !now.Before(e.NotAfter):
		state = StateExpired
	case e.FailedRenewalAttempts > 0:
		state = StateRateLimitedBackoff
	case daysRemaining <= 30 && e.Boundary != BoundaryRealityDecoy:
		state = StateRenewalDue
	}

	return Evaluation{
		CertID:                    e.CertID,
		Boundary:                  e.Boundary,
		State:                     state,
		DaysRemaining:             daysRemaining,
		RecommendedBackoffSeconds: backoff,
	}, nil
}
