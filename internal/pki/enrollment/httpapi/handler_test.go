package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/pki/enrollment"
)

const nodeA = "62c478bb-47c3-4dc6-a363-a2fbde813810"
const nodeB = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc"

type fixtureLedger struct {
	sync.Mutex
	consumed bool
	digest   [32]byte
	node     string
	expires  time.Time
}

func (s *fixtureLedger) Lookup(_ context.Context, hash [32]byte, at time.Time) (string, error) {
	s.Lock()
	defer s.Unlock()
	if hash != s.digest || s.consumed || !s.expires.After(at) {
		return "", enrollment.ErrInvalidToken
	}
	return s.node, nil
}
func (s *fixtureLedger) Commit(_ context.Context, hash [32]byte, node, _ string, _ [32]byte, _, _, at time.Time) error {
	s.Lock()
	defer s.Unlock()
	if hash != s.digest || s.consumed || node != s.node || !s.expires.After(at) {
		return enrollment.ErrInvalidToken
	}
	s.consumed = true
	return nil
}
func (*fixtureLedger) Active(context.Context, string, string, [32]byte, time.Time) (bool, error) {
	return false, nil
}

type fakeLimiter struct {
	allowed bool
	err     error
	calls   int
	key     string
}

func (l *fakeLimiter) Allow(_ context.Context, key string) (bool, error) {
	l.calls++
	l.key = key
	return l.allowed, l.err
}

type stubIssuer struct {
	calls  int
	token  string
	csr    []byte
	issued enrollment.Issued
	err    error
}

func (s *stubIssuer) Enroll(_ context.Context, token string, csr []byte) (enrollment.Issued, error) {
	s.calls++
	s.token = token
	s.csr = bytes.Clone(csr)
	return s.issued, s.err
}

func tlsRequest(method, path, token, payload, remote string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(payload))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.RemoteAddr = remote
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}
func validCSR(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node:" + nodeB}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
func validJSON(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"csrPem": validCSR(t)})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func fixtureAuthority(t *testing.T) (*enrollment.Authority, string) {
	t.Helper()
	at := time.Now().UTC()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Only Enrollment CA"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	token, digest, err := enrollment.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	ledger := &fixtureLedger{digest: digest, node: nodeA, expires: at.Add(5 * time.Minute)}
	authority, err := enrollment.NewAuthority(ca, key, "agents.omnipanel.test", ledger, func() time.Time { return at }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return authority, token
}

func TestEnrollIssuerReceivesOnlyBearerAndCSRAndReturnsTokenBoundCertificate(t *testing.T) {
	issuer, token := fixtureAuthority(t)
	limiter := &fakeLimiter{allowed: true}
	handler, err := New(issuer, limiter)
	if err != nil {
		t.Fatal(err)
	}
	req := tlsRequest("POST", Path, token, validJSON(t), "198.51.100.40:56530")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Forwarded-Client-Cert", "By=attacker;URI=spiffe://agents.omnipanel.test/node/"+nodeB)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected successful issuance: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		NodeID         string `json:"nodeId"`
		CertificatePEM string `json:"certificatePem"`
		Serial         string `json:"serial"`
		ExpiresAt      string `json:"expiresAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.NodeID != nodeA || response.Serial == "" {
		t.Fatalf("body identity not token-scoped: %+v", response)
	}
	block, _ := pem.Decode([]byte(response.CertificatePEM))
	if block == nil {
		t.Fatal("missing PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://agents.omnipanel.test/node/"+nodeA {
		t.Fatalf("CSR and headers forged node identity: %+v", cert.URIs)
	}
	if limiter.key != "198.51.100.40" {
		t.Fatalf("forwarded identity influenced rate-limit key: %q", limiter.key)
	}
	if strings.Contains(rec.Body.String(), token) || rec.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("token exposure or cached credentials")
	}
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, tlsRequest("POST", Path, token, validJSON(t), "198.51.100.40:56531"))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("reused bearer was redeemed twice: %d", rec2.Code)
	}
}
func TestEnrollRejectsUnsafeRequestsWithoutCallingIssuer(t *testing.T) {
	issuer := &stubIssuer{}
	limiter := &fakeLimiter{allowed: true}
	handler, err := New(issuer, limiter)
	if err != nil {
		t.Fatal(err)
	}
	valid := validJSON(t)
	tests := []struct {
		name   string
		modify func(*http.Request)
	}{
		{"plaintext", func(r *http.Request) { r.TLS = nil }},
		{"TLS12", func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 }},
		{"nonPOST", func(r *http.Request) { r.Method = "GET" }},
		{"wrongPath", func(r *http.Request) { r.URL.Path = "/v2/other" }},
		{"queryToken", func(r *http.Request) { r.URL.RawQuery = "access_token=secret" }},
		{"missingBearer", func(r *http.Request) { r.Header.Del("Authorization") }},
		{"twoBearerHeaders", func(r *http.Request) { r.Header.Add("Authorization", "Bearer another") }},
		{"badContentType", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{"compressed", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"invalidJSON", func(r *http.Request) { r.Body = http.NoBody }},
		{"unknownJSON", func(r *http.Request) { r.Body = ioBody(`{"csrPem":"x","nodeId":"` + nodeB + `"}`) }},
		{"duplicateCSR", func(r *http.Request) { r.Body = ioBody(`{"csrPem":"a","csrPem":"b"}`) }},
		{"multipleJSON", func(r *http.Request) { r.Body = ioBody(`{"csrPem":"x"}{"csrPem":"y"}`) }},
		{"hugeBody", func(r *http.Request) { r.Body = ioBody(strings.Repeat("x", 30000)); r.ContentLength = 30000 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := tlsRequest("POST", Path, strings.Repeat("A", 43), valid, "203.0.113.10:4500")
			tc.modify(r)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)
			if rec.Code < 400 || rec.Code == http.StatusInternalServerError {
				t.Fatalf("unsafe request accepted: %d %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), nodeB) || strings.Contains(rec.Body.String(), strings.Repeat("A", 43)) || strings.Contains(rec.Body.String(), "secret") {
				t.Fatal("request secrets reflected")
			}
			if rec.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatal("response is cacheable")
			}
		})
	}
	if issuer.calls != 0 {
		t.Fatalf("malformed requests reached signing authority %d times", issuer.calls)
	}
}
func ioBody(body string) *readerCloser { return &readerCloser{Reader: strings.NewReader(body)} }

type readerCloser struct{ *strings.Reader }

func (*readerCloser) Close() error { return nil }

func TestEnrollLimiterFailuresAndSigningFailuresAreFailClosed(t *testing.T) {
	issuer := &stubIssuer{issued: enrollment.Issued{NodeID: nodeA, CertificatePEM: []byte("data")}}
	limiter := &fakeLimiter{allowed: false}
	handler, err := New(issuer, limiter)
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		return tlsRequest("POST", Path, strings.Repeat("B", 43), validJSON(t), "192.0.2.25:2222")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, request())
	if rec.Code != http.StatusTooManyRequests || issuer.calls != 0 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limit did not stop issuer: %d", rec.Code)
	}
	limiter.allowed = true
	limiter.err = errors.New("backend secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, request())
	if rec.Code != http.StatusServiceUnavailable || issuer.calls != 0 || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("limiter outage bypassed: %d", rec.Code)
	}
	limiter.err = nil
	issuer.err = fmt.Errorf("signer secret unavailable")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, request())
	if rec.Code != http.StatusServiceUnavailable || issuer.calls != 1 || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("signer error leaked or incorrectly classified: %d", rec.Code)
	}
}
func TestEnrollConstructorRejectsMissingSecurityDependencies(t *testing.T) {
	if _, err := New(nil, &fakeLimiter{allowed: true}); err == nil {
		t.Fatal("missing issuer accepted")
	}
	if _, err := New(&stubIssuer{}, nil); err == nil {
		t.Fatal("no limiter accepted")
	}
}

// Exercise a real TLS 1.3 handshake rather than a synthetic request state.
func TestEnrollRealTLS13Bootstrap(t *testing.T) {
	issuer := &stubIssuer{issued: enrollment.Issued{NodeID: nodeA, CertificatePEM: []byte("signed-cert"), Serial: "1", NotAfter: time.Now().Add(time.Hour)}}
	guard := &fakeLimiter{allowed: true}
	handler, err := New(issuer, guard)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+Path, strings.NewReader(validJSON(t)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43))
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 || resp.StatusCode != http.StatusCreated || issuer.calls != 1 {
		t.Fatalf("real TLS13 issuance failed: status=%d calls=%d tls=%+v", resp.StatusCode, issuer.calls, resp.TLS)
	}
}
