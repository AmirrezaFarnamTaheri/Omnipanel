// Package httpapi exposes a bounded administrator adapter for the independently
// authenticated signed-state proposal and approval service. It does not issue
// signers, sessions, TOTP attestations, or node enrollment credentials.
package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/control/desiredapproval"
)

const (
	CSRFPath              = "/v2/admin/desired/csrf"
	ProposalPath          = "/v2/admin/desired/proposals"
	maxRequestBytes int64 = 1<<20 + 8192
	csrfLifeMinutes int64 = 5
)

type ApprovalService interface {
	Propose(context.Context, desiredapproval.ProposalRequest) (desiredapproval.ProposalReceipt, error)
	Review(context.Context, desiredapproval.ReviewRequest) (desiredapproval.Reviewable, error)
	Approve(context.Context, desiredapproval.ApprovalRequest) (desiredapproval.ApprovalReceipt, error)
}

// SessionChecker is a separate, online authenticated-session verifier. Its
// implementation must consult durable server-side sessions, never JWT claims
// or headers such as X-Forwarded-User. The approval service also rechecks
// administrator identity, permissions and independently verified TOTP.
type SessionChecker interface {
	Active(context.Context, string) (bool, error)
}

type handler struct {
	service  ApprovalService
	sessions SessionChecker
	origin   string
	host     string
	key      []byte
	now      func() time.Time
}

// New fails closed without explicit same-origin HTTPS configuration, an
// independent session verifier and a separately provisioned >=256-bit CSRF key.
func New(service ApprovalService, sessions SessionChecker, origin string, key []byte, now func() time.Time) (http.Handler, error) {
	u, err := url.Parse(origin)
	if nilInterface(service) || nilInterface(sessions) || now == nil || len(key) < 32 || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.Contains(u.Host, "@") || u.Hostname() == "" || u.String() != origin {
		return nil, errors.New("invalid administrator HTTP boundary configuration")
	}
	return &handler{service: service, sessions: sessions, origin: origin, host: u.Host, key: bytes.Clone(key), now: now}, nil
}

func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	kind := reflect.ValueOf(v).Kind()
	switch kind {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(v).IsNil()
	}
	return false
}

func problem(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}{"about:blank", http.StatusText(status), status})
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func bearer(r *http.Request) (string, bool) {
	v := r.Header.Values("Authorization")
	if len(v) != 1 || !strings.HasPrefix(v[0], "Bearer ") {
		return "", false
	}
	return bearerToken(strings.TrimPrefix(v[0], "Bearer "))
}
func bearerToken(s string) (string, bool) {
	if len(s) != 43 || strings.Contains(s, ",") {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != s {
		return "", false
	}
	return s, true
}

func (h *handler) csrfMAC(token string, slot int64) string {
	mac := hmac.New(sha256.New, h.key)
	_, _ = mac.Write([]byte("omnipanel-admin-csrf-v1\x00"))
	_, _ = mac.Write([]byte(token))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(h.origin))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strconv.FormatInt(slot, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (h *handler) mintCSRF(token string) string {
	slot := h.now().UTC().Unix() / 60
	return "v1." + strconv.FormatInt(slot, 10) + "." + h.csrfMAC(token, slot)
}
func (h *handler) validCSRF(token, csrf string) bool {
	parts := strings.Split(csrf, ".")
	if len(parts) != 3 || parts[0] != "v1" || len(parts[2]) != 43 {
		return false
	}
	slot, err := strconv.ParseInt(parts[1], 10, 64)
	nowSlot := h.now().UTC().Unix() / 60
	if err != nil || slot > nowSlot || nowSlot-slot >= csrfLifeMinutes || parts[1] != strconv.FormatInt(slot, 10) {
		return false
	}
	expect := h.csrfMAC(token, slot)
	return subtle.ConstantTimeCompare([]byte(expect), []byte(parts[2])) == 1
}
func uuid() (string, error) {
	var a [16]byte
	if _, err := rand.Read(a[:]); err != nil {
		return "", err
	}
	a[6] = a[6]&0x0f | 0x40
	a[8] = a[8]&0x3f | 0x80
	s := hex.EncodeToString(a[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[:8], s[8:12], s[12:16], s[16:20], s[20:]), nil
}
func validID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// uniqueJSON rejects duplicate fields, unknown fields, trailing JSON,
// unsupported encodings and excessive lengths before reaching approval logic.
func uniqueJSON(w http.ResponseWriter, r *http.Request, allowed map[string]bool) (map[string]json.RawMessage, bool) {
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || len(r.Header.Values("Content-Type")) != 1 || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") || len(r.Header.Values("Content-Encoding")) != 0 {
		problem(w, http.StatusUnsupportedMediaType)
		return nil, false
	}
	if r.ContentLength > maxRequestBytes {
		problem(w, http.StatusRequestEntityTooLarge)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	begin, e := d.Token()
	if e != nil || begin != json.Delim('{') {
		problem(w, http.StatusBadRequest)
		return nil, false
	}
	result := map[string]json.RawMessage{}
	for d.More() {
		field, e := d.Token()
		name, ok := field.(string)
		if e != nil || !ok || !allowed[name] {
			problem(w, http.StatusBadRequest)
			return nil, false
		}
		if _, present := result[name]; present {
			problem(w, http.StatusBadRequest)
			return nil, false
		}
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil {
			problem(w, http.StatusBadRequest)
			return nil, false
		}
		result[name] = raw
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') {
		problem(w, http.StatusBadRequest)
		return nil, false
	}
	if e = d.Decode(new(any)); !errors.Is(e, io.EOF) {
		problem(w, http.StatusBadRequest)
		return nil, false
	}
	return result, true
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.Host != h.host || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != h.origin || len(r.Header.Values("Cookie")) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
		problem(w, http.StatusForbidden)
		return
	}
	if v := r.Header.Get("Sec-Fetch-Site"); len(r.Header.Values("Sec-Fetch-Site")) > 1 || (v != "" && v != "same-origin") {
		problem(w, http.StatusForbidden)
		return
	}
	token, ok := bearer(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="admin-desired"`)
		problem(w, http.StatusUnauthorized)
		return
	}
	live, err := h.sessions.Active(r.Context(), token)
	if err != nil {
		problem(w, http.StatusServiceUnavailable)
		return
	}
	if !live {
		problem(w, http.StatusUnauthorized)
		return
	}
	if r.URL.Path == CSRFPath {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			problem(w, http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > 0 {
			problem(w, http.StatusBadRequest)
			return
		}
		respond(w, http.StatusOK, struct {
			Token string `json:"token"`
		}{h.mintCSRF(token)})
		return
	}
	if r.URL.Path == ProposalPath {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			problem(w, http.StatusMethodNotAllowed)
			return
		}
		if len(r.Header.Values("X-Omni-CSRF")) != 1 || !h.validCSRF(token, r.Header.Get("X-Omni-CSRF")) {
			problem(w, http.StatusForbidden)
			return
		}
		h.propose(w, r, token)
		return
	}
	tail, found := strings.CutPrefix(r.URL.Path, ProposalPath+"/")
	if !found {
		problem(w, http.StatusNotFound)
		return
	}
	if strings.HasSuffix(tail, "/approval") {
		id := strings.TrimSuffix(tail, "/approval")
		if !validID(id) {
			problem(w, http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			problem(w, http.StatusMethodNotAllowed)
			return
		}
		if len(r.Header.Values("X-Omni-CSRF")) != 1 || !h.validCSRF(token, r.Header.Get("X-Omni-CSRF")) {
			problem(w, http.StatusForbidden)
			return
		}
		h.approve(w, r, token, id)
		return
	}
	if !validID(tail) {
		problem(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		problem(w, http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength > 0 {
		problem(w, http.StatusBadRequest)
		return
	}
	reviewed, err := h.service.Review(r.Context(), desiredapproval.ReviewRequest{SessionToken: token, ProposalID: tail})
	if err != nil {
		serviceProblem(w, err)
		return
	}
	respond(w, http.StatusOK, reviewed)
}
func serviceProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, desiredapproval.ErrInvalidInput):
		problem(w, http.StatusBadRequest)
	case errors.Is(err, desiredapproval.ErrUnauthorized):
		problem(w, http.StatusForbidden)
	case errors.Is(err, desiredapproval.ErrConflict):
		problem(w, http.StatusConflict)
	default:
		problem(w, http.StatusServiceUnavailable)
	}
}
func (h *handler) propose(w http.ResponseWriter, r *http.Request, token string) {
	fields, ok := uniqueJSON(w, r, map[string]bool{"organizationId": true, "nodeId": true, "lifetimeSeconds": true, "envelope": true})
	if !ok {
		return
	}
	if len(fields) != 4 {
		problem(w, http.StatusBadRequest)
		return
	}
	var org, node string
	var seconds int64
	if json.Unmarshal(fields["organizationId"], &org) != nil || json.Unmarshal(fields["nodeId"], &node) != nil || json.Unmarshal(fields["lifetimeSeconds"], &seconds) != nil || !validID(org) || !validID(node) || seconds < 60 || seconds > 600 || len(fields["envelope"]) == 0 || fields["envelope"][0] != '{' {
		problem(w, http.StatusBadRequest)
		return
	}
	proposalID, err := uuid()
	if err != nil {
		problem(w, http.StatusServiceUnavailable)
		return
	}
	receipt, err := h.service.Propose(r.Context(), desiredapproval.ProposalRequest{SessionToken: token, ProposalID: proposalID, OrganizationID: org, NodeID: node, Envelope: bytes.Clone(fields["envelope"]), Lifetime: time.Duration(seconds) * time.Second})
	if err != nil {
		serviceProblem(w, err)
		return
	}
	respond(w, http.StatusCreated, receipt)
}
func (h *handler) approve(w http.ResponseWriter, r *http.Request, token, id string) {
	fields, ok := uniqueJSON(w, r, map[string]bool{"expectedSha256": true})
	if !ok {
		return
	}
	if len(fields) != 1 {
		problem(w, http.StatusBadRequest)
		return
	}
	var digest string
	if json.Unmarshal(fields["expectedSha256"], &digest) != nil || len(digest) != 64 {
		problem(w, http.StatusBadRequest)
		return
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			problem(w, http.StatusBadRequest)
			return
		}
	}
	receipt, err := h.service.Approve(r.Context(), desiredapproval.ApprovalRequest{SessionToken: token, ProposalID: id, ExpectedSHA256: digest})
	if err != nil {
		serviceProblem(w, err)
		return
	}
	respond(w, http.StatusCreated, receipt)
}
