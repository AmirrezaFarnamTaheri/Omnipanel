// Package httpapi exposes only a bounded TLS bootstrap exchange; it does not
// expose administrator grant issuance, certificate renewal, or privileged work.
package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/pki/enrollment"
)

const (
	Path               = "/v2/nodes/enroll"
	maxBodyBytes int64 = 24 << 10
)

// Issuer must run behind a separately protected signing key and an atomic,
// durable grant/certificate registry. It MUST NOT be driven by untrusted
// identity claims from a request's headers or CSR.
type Issuer interface {
	Enroll(context.Context, string, []byte) (enrollment.Issued, error)
}

// Limiter is a required, fail-closed admission control. Production deployment
// must inject a bounded, shared implementation and edge-layer protections.
// The client key is the transport peer IP, not forwarded/proxy headers.
type Limiter interface {
	Allow(context.Context, string) (bool, error)
}

type handler struct {
	issuer  Issuer
	limiter Limiter
}

// New returns a handler only if all trust boundaries are explicitly provided.
func New(issuer Issuer, limiter Limiter) (http.Handler, error) {
	if issuer == nil || limiter == nil {
		return nil, errors.New("enrollment issuer and admission limiter required")
	}
	return &handler{issuer: issuer, limiter: limiter}, nil
}

// Reject all errors without reflecting token, CSR, database or signer details.
func problem(w http.ResponseWriter, status int) {
	title := http.StatusText(status)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}{Type: "about:blank", Title: title, Status: status})
}

func peerIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func badJSON(w http.ResponseWriter, err error) {
	var oversized *http.MaxBytesError
	if errors.As(err, &oversized) {
		problem(w, http.StatusRequestEntityTooLarge)
	} else {
		problem(w, http.StatusBadRequest)
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path != Path {
		problem(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		problem(w, http.StatusMethodNotAllowed)
		return
	}
	// Bootstrap cannot use client mTLS because this operation issues the
	// client certificate. Direct TLS 1.3 is nevertheless mandatory.
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
		problem(w, http.StatusForbidden)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		problem(w, http.StatusBadRequest)
		return
	}
	ip := peerIP(r.RemoteAddr)
	if ip == "" {
		problem(w, http.StatusForbidden)
		return
	}
	allowed, err := h.limiter.Allow(r.Context(), ip)
	if err != nil {
		problem(w, http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", "60")
		problem(w, http.StatusTooManyRequests)
		return
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || len(values[0]) != 7+43 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="node-enrollment"`)
		problem(w, http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	for _, ch := range token {
		if ch != '-' && ch != '_' && !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') {
			problem(w, http.StatusUnauthorized)
			return
		}
	}
	contentType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || len(params) > 1 ||
		(len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) ||
		r.Header.Get("Content-Encoding") != "" {
		problem(w, http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > maxBodyBytes {
		problem(w, http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	// Reject duplicate keys instead of silently accepting the last one.
	// Every request has exactly one string-valued csrPem field.
	var csr string
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		badJSON(w, err)
		return
	}
	seen := false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil || key != "csrPem" || seen {
			badJSON(w, err)
			return
		}
		if err := decoder.Decode(&csr); err != nil {
			badJSON(w, err)
			return
		}
		seen = true
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || !seen || len(csr) == 0 || len(csr) > 16*1024 {
		badJSON(w, err)
		return
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		badJSON(w, err)
		return
	}
	issued, err := h.issuer.Enroll(r.Context(), token, []byte(csr))
	if err != nil {
		switch {
		case errors.Is(err, enrollment.ErrInvalidToken):
			w.Header().Set("WWW-Authenticate", `Bearer realm="node-enrollment"`)
			problem(w, http.StatusUnauthorized)
		case errors.Is(err, enrollment.ErrInvalidCSR):
			problem(w, http.StatusBadRequest)
		default:
			problem(w, http.StatusServiceUnavailable)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		NodeID         string `json:"nodeId"`
		CertificatePEM string `json:"certificatePem"`
		Serial         string `json:"serial"`
		ExpiresAt      string `json:"expiresAt"`
	}{NodeID: issued.NodeID, CertificatePEM: string(issued.CertificatePEM), Serial: issued.Serial, ExpiresAt: issued.NotAfter.UTC().Format(time.RFC3339)})
}
