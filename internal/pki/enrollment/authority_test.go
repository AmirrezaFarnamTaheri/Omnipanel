package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"
)

const (
	testNodeA       = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	testNodeB       = "a2f5a88e-3cc3-4a4c-81f6-45719fb131bc"
	testTrustDomain = "agents.omnipanel.test"
)

type grant struct {
	node     string
	expires  time.Time
	consumed bool
}
type enrollmentRecord struct {
	node                string
	key                 [32]byte
	notBefore, notAfter time.Time
	revoked             bool
}
type mockLedger struct {
	mu         sync.Mutex
	grants     map[[32]byte]*grant
	certs      map[string]enrollmentRecord
	failCommit bool
}

func newMockLedger() *mockLedger {
	return &mockLedger{grants: make(map[[32]byte]*grant), certs: make(map[string]enrollmentRecord)}
}
func (s *mockLedger) seed(h [32]byte, node string, exp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[h] = &grant{node: node, expires: exp}
}
func (s *mockLedger) Lookup(_ context.Context, h [32]byte, at time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[h]
	if g == nil || g.consumed || !g.expires.After(at) {
		return "", ErrInvalidToken
	}
	return g.node, nil
}
func (s *mockLedger) Commit(_ context.Context, h [32]byte, node, serial string, key [32]byte, nb, na, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[h]
	if g == nil || g.consumed || !g.expires.After(at) || g.node != node {
		return ErrInvalidToken
	}
	if s.failCommit {
		return errors.New("simulated durable write failure")
	}
	if _, exists := s.certs[serial]; exists {
		return errors.New("serial conflict")
	}
	g.consumed = true
	s.certs[serial] = enrollmentRecord{node: node, key: key, notBefore: nb, notAfter: na}
	return nil
}
func (s *mockLedger) Active(_ context.Context, node, serial string, key [32]byte, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, found := s.certs[serial]
	return found && rec.node == node && rec.key == key && !rec.revoked && !at.Before(rec.notBefore) && at.Before(rec.notAfter), nil
}
func (s *mockLedger) revoke(serial string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.certs[serial]
	r.revoked = true
	s.certs[serial] = r
}
func (s *mockLedger) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.certs) }

func issuerFixture(t *testing.T) (*x509.Certificate, crypto.Signer, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OmniPanel test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, key, now
}
func csrFixture(t *testing.T, spoofNode string) ([]byte, crypto.Signer) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claimed, _ := url.Parse("spiffe://" + testTrustDomain + "/node/" + spoofNode)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "node:" + spoofNode}, URIs: []*url.URL{claimed}, DNSNames: []string{"spoof.example"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}
func authorized(t *testing.T) (*Authority, *mockLedger, string, time.Time, *x509.Certificate) {
	t.Helper()
	ca, key, at := issuerFixture(t)
	store := newMockLedger()
	token, digest, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	store.seed(digest, testNodeA, at.Add(5*time.Minute))
	auth, err := NewAuthority(ca, key, testTrustDomain, store, func() time.Time { return at }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return auth, store, token, at, ca
}

func TestAuthorizedTokenOverridesSpoofedCSRIdentityAndRevocation(t *testing.T) {
	auth, store, token, now, ca := authorized(t)
	csr, key := csrFixture(t, testNodeB)
	issued, err := auth.Enroll(context.Background(), token, csr)
	if err != nil || issued.NodeID != testNodeA || issued.Serial == "" {
		t.Fatalf("token-derived node identity failed: %+v %v", issued, err)
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	if block == nil {
		t.Fatal("missing certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "" || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 1 ||
		cert.URIs[0].String() != "spiffe://"+testTrustDomain+"/node/"+testNodeA {
		t.Fatalf("untrusted CSR identity leaked into certificate: %+v", cert)
	}
	expected, _ := x509.MarshalPKIXPublicKey(key.Public())
	actual, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if !bytes.Equal(expected, actual) || cert.NotAfter.After(now.Add(time.Hour)) {
		t.Fatal("CSR proof key or TTL incorrect")
	}
	peer := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: chains}
	node, err := AuthenticatePeer(context.Background(), peer, store, testTrustDomain, now)
	if err != nil || node != testNodeA {
		t.Fatalf("authorized peer rejected: %s %v", node, err)
	}
	if _, err := auth.Enroll(context.Background(), token, csr); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("token replay accepted: %v", err)
	}
	if _, err := AuthenticatePeer(context.Background(), tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}}, store, testTrustDomain, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("unverified TLS chain accepted")
	}
	store.revoke(issued.Serial)
	if _, err := AuthenticatePeer(context.Background(), peer, store, testTrustDomain, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked peer accepted: %v", err)
	}
}

func TestTokenRedemptionIsAtomicUnderConcurrency(t *testing.T) {
	auth, store, token, _, _ := authorized(t)
	csr, _ := csrFixture(t, testNodeA)
	var wg sync.WaitGroup
	result := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := auth.Enroll(context.Background(), token, csr); result <- err == nil }()
	}
	wg.Wait()
	close(result)
	wins := 0
	for success := range result {
		if success {
			wins++
		}
	}
	if wins != 1 || store.count() != 1 {
		t.Fatalf("replayed enrollment created %d credentials and %d records", wins, store.count())
	}
}
func TestBadCSRCannotConsumeTokenOrReturnUnrecordedCredential(t *testing.T) {
	auth, store, token, now, _ := authorized(t)
	csr, _ := csrFixture(t, testNodeA)
	block, _ := pem.Decode(csr)
	block.Bytes[len(block.Bytes)-1] ^= 0x01
	tampered := pem.EncodeToMemory(block)
	for _, bad := range [][]byte{[]byte("garbage"), tampered, append(append([]byte{}, csr...), []byte("trailing")...)} {
		if _, err := auth.Enroll(context.Background(), token, bad); !errors.Is(err, ErrInvalidCSR) {
			t.Fatalf("bad CSR accepted: %v", err)
		}
	}
	store.failCommit = true
	if out, err := auth.Enroll(context.Background(), token, csr); err == nil || len(out.CertificatePEM) != 0 {
		t.Fatal("failed record commit returned a credential")
	}
	store.failCommit = false
	if _, err := auth.Enroll(context.Background(), token, csr); err != nil {
		t.Fatalf("failure incorrectly consumed token: %v", err)
	}
	expired, hash, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	store.seed(hash, testNodeA, now.Add(-time.Second))
	if _, err := auth.Enroll(context.Background(), expired, csr); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("expired grant accepted")
	}
}
func TestAuthorityRefusesUnboundedTTLAndWrongSigner(t *testing.T) {
	ca, key, now := issuerFixture(t)
	if _, err := NewAuthority(ca, key, "", newMockLedger(), func() time.Time { return now }, time.Hour); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("empty trust domain accepted")
	}
	if _, err := NewAuthority(ca, key, testTrustDomain, newMockLedger(), func() time.Time { return now }, 48*time.Hour); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("unbounded TTL accepted")
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthority(ca, other, testTrustDomain, newMockLedger(), func() time.Time { return now }, time.Hour); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal("mismatched CA private key accepted")
	}
}
func TestGeneratedTokenEntropyAndDigestSeparation(t *testing.T) {
	token1, h1, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	token2, h2, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if token1 == token2 || h1 == h2 || len(token1) != 43 || sha256.Sum256([]byte(token1)) == h1 {
		t.Fatal("unsafe enrollment token generation")
	}
}


func TestTokenExpiresDuringIssuance(t *testing.T) {
	ca, signer, start := issuerFixture(t)
	store := newMockLedger()
	token, digest, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	store.seed(digest, testNodeA, start.Add(5*time.Minute))
	calls := 0
	now := func() time.Time {
		calls++
		if calls >= 3 {
			return start.Add(6*time.Minute)
		}
		return start
	}
	authority, err := NewAuthority(ca, signer, testTrustDomain, store, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFixture(t, testNodeA)
	issued, err := authority.Enroll(context.Background(), token, csr)
	if !errors.Is(err, ErrInvalidToken) || len(issued.CertificatePEM) != 0 {
		t.Fatalf("expired token redeemed at commit: certificate_returned=%t err=%v", len(issued.CertificatePEM) > 0, err)
	}
	if store.count() != 0 {
		t.Fatal("expiry race created a durable certificate")
	}
}


// TLS peers may supply intermediate certificates after the leaf. A verified
// chain remains acceptable if the leaf has a registered, unrevoked node identity.
func TestAuthenticatePeerAcceptsVerifiedIssuerChain(t *testing.T) {
	auth, store, token, at, ca := authorized(t)
	csr, _ := csrFixture(t, testNodeA)
	issued, err := auth.Enroll(context.Background(), token, csr)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := tls.ConnectionState{
		Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{leaf, ca},
		VerifiedChains: chains,
	}
	node, err := AuthenticatePeer(context.Background(), peer, store, testTrustDomain, at)
	if err != nil || node != testNodeA {
		t.Fatalf("a valid issuer chain must not be rejected: node=%q err=%v", node, err)
	}
}
