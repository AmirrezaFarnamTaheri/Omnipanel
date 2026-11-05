// Package gateway provides a narrowly scoped, outbound-only HTTPS/mTLS desired
// state fetcher. It does not implement enrollment, certificate revocation,
// signed-manifest validation, or any privileged node operation.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultResponseLimit    = 1 << 20
	maximumResponseLimit    = 4 << 20
	maximumRevisionSequence = 9007199254740991
)

var (
	ErrNoChange       = errors.New("gateway reports no structural change")
	ErrInvalidConfig  = errors.New("invalid authenticated gateway configuration")
	ErrInvalidRequest = errors.New("invalid node desired-state poll request")
	nodeIDPattern     = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
)

// Request binds a desired-state GET to the caller's authorized node and the
// *applied* cursors. Peer identity is authenticated by mTLS at the gateway;
// NodeID is not transmitted in a caller-controlled route or forwarded header.
type Request struct {
	NodeID             string
	ControlPlaneEpoch  string
	StructuralSequence uint64
	MembershipSequence uint64
}

// Config contains provisioning-time trust material, never values from a
// downloaded desired-state manifest. Origin must be a bare HTTPS origin.
type Config struct {
	Origin               string
	NodeID               string
	RootCAPEM            []byte
	ClientCertificatePEM []byte
	ClientPrivateKeyPEM  []byte
	MaxResponseBytes     int64
}

type Client struct {
	origin     url.URL
	nodeID     string
	httpClient *http.Client
	limit      int64
}

// New constructs an mTLS client with explicit CA trust, client authentication,
// hostname verification, TLS 1.3, no ambient proxy, and no cross-origin redirects.
func New(cfg Config) (*Client, error) {
	if !nodeIDPattern.MatchString(cfg.NodeID) {
		return nil, fmt.Errorf("%w: node identity", ErrInvalidConfig)
	}
	u, err := url.Parse(cfg.Origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, fmt.Errorf("%w: HTTPS origin must have no credentials, path, query or fragment", ErrInvalidConfig)
	}
	if port := u.Port(); port != "" {
		value, e := strconv.Atoi(port)
		if e != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("%w: invalid gateway port", ErrInvalidConfig)
		}
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM(cfg.RootCAPEM) {
		return nil, fmt.Errorf("%w: explicit root CA required", ErrInvalidConfig)
	}
	identity, err := tls.X509KeyPair(cfg.ClientCertificatePEM, cfg.ClientPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: client certificate and key", ErrInvalidConfig)
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("%w: client certificate parse", ErrInvalidConfig)
	}
	hasClientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		return nil, fmt.Errorf("%w: client-auth certificate required", ErrInvalidConfig)
	}
	identity.Leaf = leaf
	max := cfg.MaxResponseBytes
	if max == 0 {
		max = defaultResponseLimit
	}
	if max < 1 || max > maximumResponseLimit {
		return nil, fmt.Errorf("%w: response size bound", ErrInvalidConfig)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      trust,
			Certificates: []tls.Certificate{identity},
		},
		Proxy:                 nil,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		MaxConnsPerHost:       1,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	return &Client{
		origin:     *u,
		nodeID:     cfg.NodeID,
		httpClient: &http.Client{Transport: tr, Timeout: 12 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("gateway redirects forbidden") }},
		limit:      max,
	}, nil
}

// FetchNodeDesired issues exactly one bounded GET to the fixed gateway path.
// A 204 response returns ErrNoChange; a 200 body is still UNTRUSTED until a
// separate manifest.Verifier verifies its signature, scope, epoch and replay.
func (c *Client) FetchNodeDesired(ctx context.Context, poll Request) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil || c.httpClient == nil || poll.NodeID != c.nodeID || !nodeIDPattern.MatchString(poll.ControlPlaneEpoch) ||
		poll.StructuralSequence > maximumRevisionSequence || poll.MembershipSequence > maximumRevisionSequence {
		return nil, ErrInvalidRequest
	}
	target := c.origin
	target.Path = "/v2/nodes/self/desired"
	target.RawPath = ""
	query := url.Values{
		"controlPlaneEpoch":  {poll.ControlPlaneEpoch},
		"structuralSequence": {strconv.FormatUint(poll.StructuralSequence, 10)},
		"membershipSequence": {strconv.FormatUint(poll.MembershipSequence, 10)},
	}
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authenticated desired-state fetch failed: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, ErrNoChange
	case http.StatusOK:
		// Only exact successful responses may deliver a signed envelope.
	default:
		// Never read or log server-controlled problem bodies or secrets.
		return nil, fmt.Errorf("gateway rejected desired-state fetch (HTTP %d)", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("gateway returned unexpected content type")
	}
	if resp.Header.Get("Content-Encoding") != "" && !strings.EqualFold(resp.Header.Get("Content-Encoding"), "identity") {
		return nil, errors.New("gateway returned compressed desired-state body")
	}
	hasPrivate, hasNoStore := false, false
	for _, item := range strings.Split(resp.Header.Get("Cache-Control"), ",") {
		if strings.EqualFold(strings.TrimSpace(item), "private") {
			hasPrivate = true
		}
		if strings.EqualFold(strings.TrimSpace(item), "no-store") {
			hasNoStore = true
		}
	}
	if !hasPrivate || !hasNoStore {
		return nil, errors.New("gateway omitted private no-store response directive")
	}
	if resp.ContentLength > c.limit {
		return nil, errors.New("gateway signed desired-state body exceeds size limit")
	}
	wire, err := io.ReadAll(io.LimitReader(resp.Body, c.limit+1))
	if err != nil {
		return nil, fmt.Errorf("read bounded desired-state body: %w", err)
	}
	if int64(len(wire)) > c.limit || len(wire) == 0 {
		return nil, errors.New("gateway signed desired-state body is empty or oversized")
	}
	return wire, nil
}
