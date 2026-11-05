package desiredapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

const (
	desiredNode            = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	desiredEpoch           = "ea2429da-7540-4e40-ae70-38fd3f19794b"
	desiredDomain          = "agents.omnipanel.test"
	fixtureSignatureDomain = "omnipanel:desired-state:ed25519-jcs-v1\n"
)

type fixtureLedger struct {
	mu     sync.Mutex
	active bool
	err    error
	calls  int
}

func (l *fixtureLedger) Active(_ context.Context, node, serial string, _ [32]byte, _ time.Time) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if node != desiredNode || serial != "2" {
		return false, errors.New("incorrect certificate identity")
	}
	return l.active, l.err
}

func (l *fixtureLedger) SetActive(active bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active = active
}

type fixtureSource struct {
	snapshot Snapshot
	err      error
	calls    int
	lastNode string
}

func (s *fixtureSource) Latest(_ context.Context, node string) (Snapshot, error) {
	s.calls++
	s.lastNode = node
	return s.snapshot, s.err
}

func fixtureVerifiedPeer(t *testing.T, now time.Time) tls.ConnectionState {
	t.Helper()
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only gateway root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := &url.URL{Scheme: "spiffe", Host: desiredDomain, Path: "/node/" + desiredNode}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{identity},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, root}},
	}
}

func fixtureSignedDesired(t *testing.T, now time.Time) ([]byte, manifest.Verifier) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6b}, ed25519.SeedSize))
	artifactDigest := strings.Repeat("a", 64)
	m := manifest.Manifest{
		SchemaVersion: "2.0", ControlPlaneEpoch: desiredEpoch, NodeID: desiredNode,
		StructuralSequence: 2, MembershipSequence: 3,
		IssuedAt:             now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:            now.Add(10 * time.Minute).Format(time.RFC3339),
		RequiredCapabilities: []string{"singbox-reality-vision"},
		Components: []manifest.Component{{
			ID: "reality", Driver: "singbox", RuntimeVersion: "1.14.4+omni.2",
			ArtifactDigest: artifactDigest, ConfigurationDigest: strings.Repeat("b", 64),
			ConfigurationRef: "reality-config", DependsOn: []string{},
			Listeners:  []manifest.Listener{{Address: "0.0.0.0", Port: 443, Transport: "tcp"}},
			Disruption: "listener_restart",
		}},
		BaseEgressPolicy: "deny-protected-v1",
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var canonicalObject any
	if err := json.Unmarshal(raw, &canonicalObject); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(canonicalObject)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(key, append([]byte(fixtureSignatureDomain), canonical...))
	wire, err := json.Marshal(manifest.Envelope{
		SignatureVersion: "ed25519-jcs-v1", SignerID: "test-signer",
		ContentDigest: hex.EncodeToString(digest[:]),
		Signature:     base64.RawURLEncoding.EncodeToString(sig), Manifest: m,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := manifest.Verifier{
		AuthorizedEpoch:     desiredEpoch,
		TrustedSigners:      map[string]ed25519.PublicKey{"test-signer": key.Public().(ed25519.PublicKey)},
		AllowedCapabilities: map[string]bool{"singbox-reality-vision": true},
		QualifiedBuilds: map[string]manifest.Build{"singbox": {
			Driver: "singbox", Version: "1.14.4+omni.2", ArtifactDigest: artifactDigest,
			Capabilities: []string{"singbox-reality-vision"},
		}},
		MaxClockSkew: time.Second,
	}
	return wire, verifier
}

func fixtureHandler(t *testing.T) (*Handler, *fixtureLedger, *fixtureSource, tls.ConnectionState) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	wire, verifier := fixtureSignedDesired(t, now)
	ledger := &fixtureLedger{active: true}
	source := &fixtureSource{snapshot: Snapshot{Epoch: desiredEpoch, StructuralSequence: 2, MembershipSequence: 3, Envelope: wire}}
	handler, err := NewHandler(ledger, source, desiredDomain, verifier, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return handler, ledger, source, fixtureVerifiedPeer(t, now)
}

func desiredRequest(query string, peer *tls.ConnectionState) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://gateway.test/v2/nodes/self/desired?"+query, nil)
	req.TLS = peer
	return req
}
func requestQuery(structural, membership string) string {
	return "controlPlaneEpoch=" + desiredEpoch + "&structuralSequence=" + structural + "&membershipSequence=" + membership
}

func TestDesiredHandlerAuthenticatesCertificateAndVerifiesEnvelopeBefore200Or204(t *testing.T) {
	h, ledger, src, peer := fixtureHandler(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, desiredRequest(requestQuery("0", "0"), &peer))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), src.snapshot.Envelope) ||
		w.Header().Get("Content-Type") != "application/json" ||
		w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("authorized desired state missing: status=%d headers=%v body=%q", w.Code, w.Header(), w.Body.String())
	}
	if ledger.calls != 1 || src.calls != 1 || src.lastNode != desiredNode {
		t.Fatalf("did not scope access to authenticated node: ledger=%d source=%d node=%q", ledger.calls, src.calls, src.lastNode)
	}
	// A structural manifest is not a membership update feed. An applied
	// structural revision with a lagging membership cursor must not cause
	// the node to re-verify an equal structural revision as a new change.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, desiredRequest(requestQuery("2", "0"), &peer))
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("equal structural cursor with lagging membership must be 204: status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, desiredRequest(requestQuery("2", "3"), &peer))
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("same signed cursor is not a 204 no-change response: status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestDesiredHandlerRejectsRevokedOrUnverifiedPeersBeforeReadingState(t *testing.T) {
	h, ledger, src, peer := fixtureHandler(t)
	ledger.SetActive(false)
	for _, tc := range []struct {
		name string
		peer *tls.ConnectionState
	}{
		{"revoked", &peer},
		{"unverified chain", &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: peer.PeerCertificates}},
		{"no TLS", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := desiredRequest(requestQuery("0", "0"), tc.peer)
			req.Header.Set("X-Forwarded-Client-Cert", "spiffe://"+desiredDomain+"/node/"+desiredNode)
			h.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized || w.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatalf("invalid or revoked peer admitted: status=%d", w.Code)
			}
		})
	}
	if src.calls != 0 {
		t.Fatal("unverified peer reached source")
	}
}

func TestDesiredHandlerRejectsIncorrectEpochCursorOrQuery(t *testing.T) {
	h, _, _, peer := fixtureHandler(t)
	for _, tc := range []struct {
		query  string
		status int
	}{
		{requestQuery("3", "3"), http.StatusConflict},
		{requestQuery("2", "4"), http.StatusConflict},
		{strings.Replace(requestQuery("0", "0"), desiredEpoch, "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc", 1), http.StatusConflict},
		{requestQuery("01", "0"), http.StatusBadRequest},
		{requestQuery("0", "0") + "&membershipSequence=0", http.StatusBadRequest},
		{requestQuery("0", "0") + "&nodeId=" + desiredNode, http.StatusBadRequest},
		{"controlPlaneEpoch=" + desiredEpoch + "&structuralSequence=-1&membershipSequence=0", http.StatusBadRequest},
		{"controlPlaneEpoch=" + desiredEpoch + "&structuralSequence=9007199254740992&membershipSequence=0", http.StatusBadRequest},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, desiredRequest(tc.query, &peer))
		if w.Code != tc.status {
			t.Errorf("query %q: got %d, want %d", tc.query, w.Code, tc.status)
		}
	}
}

func TestDesiredHandlerFailsClosedForTamperedOrUnavailableSignedState(t *testing.T) {
	h, _, src, peer := fixtureHandler(t)
	src.snapshot.Envelope = bytes.Replace(src.snapshot.Envelope, []byte("\"structuralSequence\":2"), []byte("\"structuralSequence\":8"), 1)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, desiredRequest(requestQuery("0", "0"), &peer))
	if w.Code != http.StatusServiceUnavailable || w.Body.Len() == 0 {
		t.Fatalf("unsigned state served: %d", w.Code)
	}
	src.err = errors.New("sensitive database failure")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, desiredRequest(requestQuery("0", "0"), &peer))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "sensitive") {
		t.Fatalf("storage failure was disclosed or admitted: %d %q", w.Code, w.Body.String())
	}
}

func TestDesiredHandlerRejectsUnsafeConstructionAndNonGET(t *testing.T) {
	_, verifier := fixtureSignedDesired(t, time.Now().UTC())
	if _, err := NewHandler(nil, nil, "", verifier, time.Now); err == nil {
		t.Fatal("unauthenticated gateway constructor was allowed")
	}
	h, _, _, peer := fixtureHandler(t)
	req := desiredRequest(requestQuery("0", "0"), &peer)
	req.Method = http.MethodPost
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected method status %d", w.Code)
	}
	req = desiredRequest(requestQuery("0", "0"), &peer)
	req.URL.Path = "/v2/nodes/other/desired"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unscoped path status %d", w.Code)
	}
}
