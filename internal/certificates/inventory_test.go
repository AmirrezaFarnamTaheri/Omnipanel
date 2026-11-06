package certificates

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEvaluateEntryEnforcesBoundariesAndRefusesInsecureFallback(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	fp := strings.Repeat("a", 64)

	ev, err := EvaluateEntry(Entry{
		CertID:            "cert-mtls-1",
		DomainOrSAN:       "spiffe://omnipanel/node/11111111-1111-4111-8111-111111111111",
		Boundary:          BoundaryNodeMTLS,
		SHA256Fingerprint: fp,
		NotBefore:         now.Add(-time.Hour),
		NotAfter:          now.Add(20 * time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.State != StateRenewalDue {
		t.Fatalf("expected renewal_due, got %s", ev.State)
	}

	if _, err := EvaluateEntry(Entry{
		CertID:                "cert-bad",
		DomainOrSAN:           "edge.example.com",
		Boundary:              BoundaryACMEPublicTLS,
		SHA256Fingerprint:     fp,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		AllowInsecureFallback: true,
	}, now); !errors.Is(err, ErrInsecureFallbackRefused) {
		t.Fatalf("expected ErrInsecureFallbackRefused, got %v", err)
	}
}
