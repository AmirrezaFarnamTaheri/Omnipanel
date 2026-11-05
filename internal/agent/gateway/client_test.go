package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testNode = "62c478bb-47c3-4dc6-a363-a2fbde813810"
const testEpoch = "ea2429da-7540-4e40-ae70-38fd3f19794b"

// Generate independent, short-lived CA / server / client identities in-memory.
// The test server enforces mutual TLS, so no insecure testing shortcuts apply.
func testCertificates(t *testing.T) (caPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM []byte) {
	t.Helper()
	now := time.Now()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OmniPanel test issuing CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	newLeaf := func(serial int64, name string, isServer bool) ([]byte, []byte) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		eku := x509.ExtKeyUsageClientAuth
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if isServer {
			eku = x509.ExtKeyUsageServerAuth
			cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{eku}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, public, caKey)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	}
	serverCertPEM, serverKeyPEM = newLeaf(2, "OmniPanel test gateway", true)
	clientCertPEM, clientKeyPEM = newLeaf(3, "node-"+testNode, false)
	return
}

func testServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, Config) {
	t.Helper()
	caPEM, serverPEM, serverKey, clientPEM, clientKey := testCertificates(t)
	cert, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("invalid CA fixture")
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, Config{Origin: srv.URL, NodeID: testNode, RootCAPEM: caPEM, ClientCertificatePEM: clientPEM, ClientPrivateKeyPEM: clientKey}
}

func testRequest() Request {
	return Request{NodeID: testNode, ControlPlaneEpoch: testEpoch, StructuralSequence: 7, MembershipSequence: 11}
}

func TestMTLSFetchUsesSelfEndpointAndExactCursors(t *testing.T) {
	count := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.Method != "GET" || r.URL.Path != "/v2/nodes/self/desired" || r.Host == "" {
			t.Errorf("unexpected path/method %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("controlPlaneEpoch") != testEpoch || r.URL.Query().Get("structuralSequence") != "7" || r.URL.Query().Get("membershipSequence") != "11" || len(r.URL.Query()) != 3 {
			t.Errorf("unsafe/missing cursor query: %s", r.URL.RawQuery)
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1 || r.TLS.Version != tls.VersionTLS13 {
			t.Errorf("no validated TLS client identity: %+v", r.TLS)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("wrong media type")
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"manifest":"signed"}`))
	}
	_, cfg := testServer(t, handler)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1") // ambient proxies must be ignored
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := client.FetchNodeDesired(context.Background(), testRequest())
	if err != nil || string(body) != `{"manifest":"signed"}` || count != 1 {
		t.Fatalf("real mTLS GET failed: body=%q count=%d err=%v", body, count, err)
	}
}

func TestNoChangeAndRedirectFailClosed(t *testing.T) {
	// HTTP 204 is an explicit no-change, not a successful runtime apply.
	_, cfg := testServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	goodClient, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = goodClient.FetchNodeDesired(context.Background(), testRequest())
	if !errors.Is(err, ErrNoChange) {
		t.Fatalf("204 must have typed no-change result: %v", err)
	}

	targetHits := 0
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHits++ }))
	t.Cleanup(redirectTarget.Close)
	_, redirectCfg := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	})
	redirectClient, err := New(redirectCfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = redirectClient.FetchNodeDesired(context.Background(), testRequest())
	if err == nil || targetHits != 0 {
		t.Fatalf("redirect escaped pinned TLS origin: hits=%d err=%v", targetHits, err)
	}
}

func TestInvalidOriginAndClientCredentialsRejected(t *testing.T) {
	_, base := testServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cases := []struct {
		name   string
		modify func(*Config)
	}{
		{"plaintext", func(c *Config) { c.Origin = "http://127.0.0.1:8443" }},
		{"user info", func(c *Config) { c.Origin = "https://user:password@localhost:8443" }},
		{"query", func(c *Config) { c.Origin += "?token=secret" }},
		{"fragment", func(c *Config) { c.Origin += "#fragment" }},
		{"non-root path", func(c *Config) { c.Origin += "/arbitrary/path" }},
		{"invalid node", func(c *Config) { c.NodeID = "not-a-node" }},
		{"invalid max", func(c *Config) { c.MaxResponseBytes = maximumResponseLimit + 1 }},
		{"negative max", func(c *Config) { c.MaxResponseBytes = -1 }},
		{"invalid port", func(c *Config) { c.Origin = "https://localhost:65536" }},
		{"untrusted root", func(c *Config) { c.RootCAPEM = []byte("bad") }},
		{"missing client cert", func(c *Config) { c.ClientCertificatePEM = nil }},
		{"missing client key", func(c *Config) { c.ClientPrivateKeyPEM = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.modify(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("invalid client settings accepted")
			}
		})
	}
	client, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []Request{
		{NodeID: "mismatched", ControlPlaneEpoch: testEpoch},
		{NodeID: testNode, ControlPlaneEpoch: "not-uuid"},
		{NodeID: testNode, ControlPlaneEpoch: testEpoch, StructuralSequence: 1 << 53},
	} {
		if _, err := client.FetchNodeDesired(context.Background(), req); err == nil {
			t.Fatalf("invalid request permitted: %+v", req)
		}
	}
}

func TestOversizeNonJSONErrorAndEmptyBodiesFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		code  int
		ct    string
		body  []byte
		cache string
	}{
		{"too large", 200, "application/json", bytes.Repeat([]byte("x"), 1025), "private, no-store"},
		{"bad mime", 200, "text/plain", []byte(`{"bad":true}`), "private, no-store"},
		{"cacheable", 200, "application/json", []byte(`{"bad":true}`), "public, max-age=100"},
		{"empty 200", 200, "application/json", nil, "private, no-store"},
		{"unauthorized", 401, "application/problem+json", []byte(`{"detail":"sensitive"}`), "no-store"},
		{"server fail", 503, "application/problem+json", []byte(`{"detail":"sensitive"}`), "no-store"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			_, cfg := testServer(t, func(w http.ResponseWriter, r *http.Request) {
				hits++
				w.Header().Set("Content-Type", tc.ct)
				w.Header().Set("Cache-Control", tc.cache)
				w.WriteHeader(tc.code)
				_, _ = w.Write(tc.body)
			})
			cfg.MaxResponseBytes = 1024
			client, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.FetchNodeDesired(context.Background(), testRequest())
			if err == nil {
				t.Fatal("invalid result accepted")
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("server response content leaked in error")
			}
			if hits != 1 {
				t.Errorf("request should never be retried: %d", hits)
			}
		})
	}
}

func TestUnknownCARootFailsServerVerification(t *testing.T) {
	_, cfg := testServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"signed":true}`)) })
	otherCA, _, _, _, _ := testCertificates(t)
	cfg.RootCAPEM = otherCA
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.FetchNodeDesired(context.Background(), testRequest())
	if err == nil {
		t.Fatal("untrusted gateway TLS certificate accepted")
	}
}

func TestContextCancellation(t *testing.T) {
	_, cfg := testServer(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("cancelled request reached gateway") })
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.FetchNodeDesired(ctx, testRequest())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not propagated: %v", err)
	}
}
