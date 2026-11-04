// Package enrollment defines node enrollment and certificate admission without
// exposing a public enrollment endpoint or any privileged node operation.
package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"time"
)

var (
	ErrInvalidAuthority = errors.New("invalid enrollment authority")
	ErrInvalidToken     = errors.New("invalid or expired enrollment token")
	ErrInvalidCSR       = errors.New("invalid enrollment certificate request")
	ErrUnauthorized     = errors.New("node certificate not authorized")
	nodePattern         = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
	domainPattern       = regexp.MustCompile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
)

const (
	tokenBytes         = 32
	maxCSRBytes        = 16 * 1024
	maxCertificateLife = 24 * time.Hour
)

// TokenStore must atomically consume a previously authorized token AND record
// the issued certificate. Implementations must be durable and transactional;
// one-time tokens must not be reissued after a process restart.
type TokenStore interface {
	Lookup(ctx context.Context, tokenDigest [32]byte, at time.Time) (nodeID string, err error)
	Commit(ctx context.Context, tokenDigest [32]byte, nodeID, serial string, keyDigest [32]byte, notBefore, notAfter, at time.Time) error
	Active(ctx context.Context, nodeID, serial string, keyDigest [32]byte, at time.Time) (bool, error)
}

type Authority struct {
	ca          *x509.Certificate
	signer      crypto.Signer
	trustDomain string
	store       TokenStore
	now         func() time.Time
	ttl         time.Duration
}

type Issued struct {
	CertificatePEM []byte
	NodeID         string
	Serial         string
	NotAfter       time.Time
}

// NewAuthority enforces a CA key match and short-lived client-only certificates.
// The signing key must be managed outside the public gateway process.
func NewAuthority(ca *x509.Certificate, key crypto.Signer, trustDomain string, store TokenStore, now func() time.Time, lifetime time.Duration) (*Authority, error) {
	if ca == nil || key == nil || store == nil || now == nil || !domainPattern.MatchString(trustDomain) ||
		lifetime < time.Minute || lifetime > maxCertificateLife || !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrInvalidAuthority
	}
	certKey, err := x509.MarshalPKIXPublicKey(ca.PublicKey)
	if err != nil {
		return nil, ErrInvalidAuthority
	}
	signingKey, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(certKey, signingKey) {
		return nil, ErrInvalidAuthority
	}
	at := now().UTC()
	if at.Before(ca.NotBefore) || !at.Before(ca.NotAfter) || !at.Add(lifetime).Before(ca.NotAfter) {
		return nil, ErrInvalidAuthority
	}
	return &Authority{ca: ca, signer: key, trustDomain: trustDomain, store: store, now: now, ttl: lifetime}, nil
}

// GenerateToken creates 256-bit unpredictable bearer credentials. Only its
// SHA-256 digest may be persisted in the enrollment token table.
func GenerateToken() (string, [32]byte, error) {
	var secret [tokenBytes]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", [32]byte{}, err
	}
	return base64.RawURLEncoding.EncodeToString(secret[:]), sha256.Sum256(secret[:]), nil
}

func parseToken(value string) ([32]byte, error) {
	if len(value) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		return [32]byte{}, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != tokenBytes || base64.RawURLEncoding.EncodeToString(raw) != value {
		return [32]byte{}, ErrInvalidToken
	}
	return sha256.Sum256(raw), nil
}

func parseCSR(payload []byte) (*x509.CertificateRequest, error) {
	if len(payload) == 0 || len(payload) > maxCSRBytes {
		return nil, ErrInvalidCSR
	}
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidCSR
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, ErrInvalidCSR
	}
	switch key := csr.PublicKey.(type) {
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalidCSR
		}
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return nil, ErrInvalidCSR
		}
	default:
		return nil, ErrInvalidCSR
	}
	return csr, nil
}

// Enroll verifies CSR proof of key possession, then derives the authenticated
// node exclusively from its authorized, unspent token. CSR CN and SAN are never
// copied into the certificate. Commit must transactionally redeem+record.
func (a *Authority) Enroll(ctx context.Context, bearer string, csrPEM []byte) (Issued, error) {
	if err := ctx.Err(); err != nil {
		return Issued{}, err
	}
	hash, err := parseToken(bearer)
	if err != nil {
		return Issued{}, err
	}
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return Issued{}, err
	}
	at := a.now().UTC()
	if at.Before(a.ca.NotBefore) || !at.Add(a.ttl).Before(a.ca.NotAfter) {
		return Issued{}, ErrInvalidAuthority
	}
	node, err := a.store.Lookup(ctx, hash, at)
	if err != nil {
		return Issued{}, err
	}
	if !nodePattern.MatchString(node) {
		return Issued{}, ErrInvalidToken
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Issued{}, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	notBefore := at.Add(-time.Minute)
	if notBefore.Before(a.ca.NotBefore) {
		notBefore = a.ca.NotBefore
	}
	notAfter := at.Add(a.ttl)
	uri := &url.URL{Scheme: "spiffe", Host: a.trustDomain, Path: "/node/" + node}
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    notBefore, NotAfter: notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.ca, csr.PublicKey, a.signer)
	if err != nil {
		return Issued{}, fmt.Errorf("issue node certificate: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return Issued{}, ErrInvalidCSR
	}
	if err := ctx.Err(); err != nil {
		return Issued{}, err
	}
	// Signing and database load may cross the token expiration deadline.
	// Recheck time at redemption, not just before creating the certificate.
	commitAt := a.now().UTC()
	if commitAt.Before(a.ca.NotBefore) || !commitAt.Before(notAfter) {
		return Issued{}, ErrInvalidToken
	}
	if err := a.store.Commit(ctx, hash, node, serial.String(), sha256.Sum256(spki), notBefore, notAfter, commitAt); err != nil {
		return Issued{}, err
	}
	return Issued{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), NodeID: node, Serial: serial.String(), NotAfter: notAfter}, nil
}

// AuthenticatePeer must be called only with a tls.ConnectionState created by
// Go's TLS stack after chain validation. A forwarded certificate HTTP header
// is never an authentication source. The registry provides revocation checks.
func AuthenticatePeer(ctx context.Context, peer tls.ConnectionState, store TokenStore, trustDomain string, at time.Time) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if store == nil || !domainPattern.MatchString(trustDomain) || peer.Version != tls.VersionTLS13 ||
		len(peer.PeerCertificates) == 0 || len(peer.VerifiedChains) == 0 {
		return "", ErrUnauthorized
	}
	cert := peer.PeerCertificates[0]
	trusted := false
	for _, chain := range peer.VerifiedChains {
		if len(chain) >= 2 && bytes.Equal(chain[0].Raw, cert.Raw) {
			trusted = true
			break
		}
	}
	if !trusted || at.Before(cert.NotBefore) || !at.Before(cert.NotAfter) || cert.IsCA ||
		cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(cert.URIs) != 1 || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		return "", ErrUnauthorized
	}
	uri := cert.URIs[0]
	if uri.Scheme != "spiffe" || uri.Host != trustDomain || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || uri.Port() != "" || uri.Opaque != "" {
		return "", ErrUnauthorized
	}
	const prefix = "/node/"
	if len(uri.Path) != len(prefix)+36 || uri.Path[:len(prefix)] != prefix {
		return "", ErrUnauthorized
	}
	node := uri.Path[len(prefix):]
	if !nodePattern.MatchString(node) {
		return "", ErrUnauthorized
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", ErrUnauthorized
	}
	active, err := store.Active(ctx, node, cert.SerialNumber.String(), sha256.Sum256(spki), at.UTC())
	if err != nil || !active {
		return "", ErrUnauthorized
	}
	return node, nil
}
