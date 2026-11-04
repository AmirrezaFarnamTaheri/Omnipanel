package desiredapi

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
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/gateway"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

// End-to-end local boundary: a real TLS 1.3 client presents a node certificate,
// the gateway checks the live revocation ledger, verifies the signed manifest,
// and the existing outbound client accepts only a bounded private response.
// No host runtime is installed or applied in this test.
func TestActualMTLSClientAndSignedDesiredHandlerRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	wire, verifier := fixtureSignedDesired(t, now)
	ledger := &fixtureLedger{active: true}
	source := &fixtureSource{snapshot: Snapshot{Epoch: desiredEpoch, Envelope: wire}}
	h, err := NewHandler(ledger, source, desiredDomain, verifier, func() time.Time { return now })
	if err != nil { t.Fatal(err) }

	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(50), Subject: pkix.Name{CommonName: "local test mTLS root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil { t.Fatal(err) }
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil { t.Fatal(err) }
	rootPEM := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:caDER})
	makeLeaf := func(serial int64, server bool) ([]byte, []byte) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil { t.Fatal(err) }
		eku := x509.ExtKeyUsageClientAuth
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30*time.Minute),
			KeyUsage:x509.KeyUsageDigitalSignature,
		}
		if server {
			eku = x509.ExtKeyUsageServerAuth
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			template.URIs = []*url.URL{{Scheme:"spiffe", Host:desiredDomain, Path:"/node/"+desiredNode}}
		}
		template.ExtKeyUsage = []x509.ExtKeyUsage{eku}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, public, caPrivate)
		if err != nil { t.Fatal(err) }
		pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil { t.Fatal(err) }
		return pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:der}),
			pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY", Bytes:pkcs8})
	}
	serverPEM,serverKey := makeLeaf(51,true)
	clientPEM,clientKey := makeLeaf(2,false)
	serverIdentity,err := tls.X509KeyPair(serverPEM,serverKey)
	if err != nil { t.Fatal(err) }
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		MinVersion:tls.VersionTLS13,
		Certificates:[]tls.Certificate{serverIdentity},
		ClientAuth:tls.RequireAndVerifyClientCert, ClientCAs:roots,
	}
	srv.StartTLS()
	defer srv.Close()

	client,err := gateway.New(gateway.Config{
		Origin:srv.URL,NodeID:desiredNode,
		RootCAPEM:rootPEM,ClientCertificatePEM:clientPEM,ClientPrivateKeyPEM:clientKey,
	})
	if err != nil { t.Fatal(err) }
	poll := gateway.Request{NodeID:desiredNode,ControlPlaneEpoch:desiredEpoch}
	got,err := client.FetchNodeDesired(context.Background(),poll)
	if err != nil || !bytes.Equal(got,wire) {
		t.Fatalf("real mTLS desired-state handshake failed: wire=%d err=%v",len(got),err)
	}
	verifier.NodeID,verifier.AuthorizedEpoch = desiredNode,desiredEpoch
	verifier.Now = func()time.Time{return now}
	if verified,err := verifier.Verify(got); err != nil || verified.Decision != manifest.ApplyRevision {
		t.Fatalf("client rejected gateway-signed manifest: %+v err=%v",verified,err)
	}
	poll.StructuralSequence,poll.MembershipSequence = 2,3
	if got,err := client.FetchNodeDesired(context.Background(),poll); !errors.Is(err,gateway.ErrNoChange) || len(got)!=0 {
		t.Fatalf("equal applied cursor did not produce verified no-change: bytes=%d err=%v",len(got),err)
	}
	ledger.SetActive(false)
	if _,err := client.FetchNodeDesired(context.Background(),poll); err == nil || errors.Is(err,gateway.ErrNoChange) {
		t.Fatalf("revoked certificate still authorized a desired-state response: %v",err)
	}
}
