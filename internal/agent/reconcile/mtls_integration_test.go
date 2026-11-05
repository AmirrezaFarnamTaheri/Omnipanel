package reconcile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/gateway"
)

// This is an in-process mTLS gateway simulator, not a control-plane service.
// It proves transport composition with the signed-envelope verifier and WAL.
func TestMutualTLSDesiredStateReachesVerifiedJournalWithoutApply(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated integration CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, rootPub, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leaf := func(serial int64, server bool) ([]byte, []byte) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		eku := x509.ExtKeyUsageClientAuth
		subject := "node-" + fixtureNode
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subject}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			eku = x509.ExtKeyUsageServerAuth
			cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{eku}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, rootPriv)
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	}
	serverPEM, serverKey := leaf(2, true)
	clientPEM, clientKey := leaf(3, false)
	serverCert, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("invalid local CA")
	}

	m, verifier, signingKey := signerFixture(t)
	signed := signFixture(t, m, signingKey)
	count := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.Method != http.MethodGet || r.URL.Path != "/v2/nodes/self/desired" ||
			r.URL.Query().Get("controlPlaneEpoch") != fixtureEpoch ||
			r.URL.Query().Get("structuralSequence") != "0" ||
			r.URL.Query().Get("membershipSequence") != "0" ||
			r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1 {
			t.Errorf("gateway saw unexpected unauthenticated or non-scoped request")
		}
		if count == 2 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		_, _ = w.Write(signed)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := gateway.New(gateway.Config{Origin: server.URL, NodeID: fixtureNode, RootCAPEM: rootPEM, ClientCertificatePEM: clientPEM, ClientPrivateKeyPEM: clientKey})
	if err != nil {
		t.Fatal(err)
	}
	_, store := openTestJournal(t)
	defer store.Close()
	processor, err := New(store, verifier)
	if err != nil {
		t.Fatal(err)
	}

	first, err := processor.PollOnce(context.Background(), client)
	if err != nil || first.Outcome != PendingApplication || !first.NewlyRecorded || first.StructuralSequence != 2 {
		t.Fatalf("signed mTLS payload failed to enter verified journal: %+v %v", first, err)
	}
	second, err := processor.PollOnce(context.Background(), client)
	if err != nil || second.Outcome != NoChange || second.NewlyRecorded {
		t.Fatalf("mTLS 204 must not report a deployment: %+v %v", second, err)
	}
	entries, err := store.Pending(context.Background())
	if err != nil || len(entries) != 1 || entries[0].Stage != "VERIFIED" {
		t.Fatalf("signed intent missing from journal: %+v %v", entries, err)
	}
	cursor, err := store.Cursor(context.Background())
	if err != nil || cursor.StructuralSequence != 0 || cursor.MembershipSequence != 0 || cursor.Digest != "" {
		t.Fatalf("transport success must never promote applied cursors: %+v %v", cursor, err)
	}
	if count != 2 {
		t.Fatalf("unexpected gateway call count: %d", count)
	}
}
