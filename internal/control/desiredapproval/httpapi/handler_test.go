package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/control/desiredapproval"
)

const origin = "https://admin.omnipanel.test"
const sessionToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const proposalID = "7a514a8c-422a-4d0a-bc41-ea144c52911e"
const nodeID = "62c478bb-47c3-4dc6-a363-a2fbde813810"
const orgID = "4b0895aa-1701-4c6d-8b31-91d642c23e1c"

var clock = time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC)

type fakeService struct {
	proposals, reviews, approvals int
	gotProposal                   desiredapproval.ProposalRequest
	gotApproval                   desiredapproval.ApprovalRequest
	err                           error
}

func (f *fakeService) Propose(_ context.Context, p desiredapproval.ProposalRequest) (desiredapproval.ProposalReceipt, error) {
	f.proposals++
	f.gotProposal = p
	return desiredapproval.ProposalReceipt{ProposalID: p.ProposalID, NodeID: p.NodeID, EnvelopeSHA256: strings.Repeat("a", 64), ExpiresAt: clock.Add(5 * time.Minute)}, f.err
}
func (f *fakeService) Review(_ context.Context, r desiredapproval.ReviewRequest) (desiredapproval.Reviewable, error) {
	f.reviews++
	return desiredapproval.Reviewable{ProposalID: r.ProposalID, OrganizationID: orgID, NodeID: nodeID, Epoch: "ea2429da-7540-4e40-ae70-38fd3f19794b", StructuralSequence: 1, EnvelopeSHA256: strings.Repeat("a", 64), Envelope: []byte(`{"manifest":{"secret":"private"}}`), ExpiresAt: clock.Add(5 * time.Minute)}, f.err
}
func (f *fakeService) Approve(_ context.Context, r desiredapproval.ApprovalRequest) (desiredapproval.ApprovalReceipt, error) {
	f.approvals++
	f.gotApproval = r
	return desiredapproval.ApprovalReceipt{ProposalID: r.ProposalID, ApprovalID: proposalID, EnvelopeSHA256: r.ExpectedSHA256, NodeID: nodeID, ExpiresAt: clock.Add(3 * time.Minute)}, f.err
}

type fakeSessions struct {
	ok    bool
	err   error
	calls int
}

func (f *fakeSessions) Active(context.Context, string) (bool, error) { f.calls++; return f.ok, f.err }
func makeHandler(t *testing.T) (http.Handler, *fakeService, *fakeSessions) {
	t.Helper()
	f := &fakeService{}
	s := &fakeSessions{ok: true}
	h, err := New(f, s, origin, []byte(strings.Repeat("K", 32)), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	return h, f, s
}
func request(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "https://admin.omnipanel.test"+path, strings.NewReader(body))
	r.Host = "admin.omnipanel.test"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.Header.Set("Origin", origin)
	r.Header.Set("Authorization", "Bearer "+sessionToken)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	return r
}
func token(t *testing.T, h http.Handler) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("GET", CSRFPath, ""))
	if w.Code != 200 {
		t.Fatalf("csrf HTTP %d %s", w.Code, w.Body.String())
	}
	var obj struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &obj); err != nil {
		t.Fatal(err)
	}
	if obj.Token == "" {
		t.Fatal("empty token")
	}
	return obj.Token
}
func TestConstructorFailsClosed(t *testing.T) {
	f := &fakeService{}
	s := &fakeSessions{ok: true}
	cases := []struct {
		svc      ApprovalService
		sessions SessionChecker
		origin   string
		key      []byte
		clock    func() time.Time
	}{{nil, s, origin, []byte(strings.Repeat("X", 32)), time.Now}, {f, nil, origin, []byte(strings.Repeat("X", 32)), time.Now}, {f, s, "http://admin.omnipanel.test", []byte(strings.Repeat("X", 32)), time.Now}, {f, s, "https://admin.omnipanel.test/x", []byte(strings.Repeat("X", 32)), time.Now}, {f, s, origin, []byte("short"), time.Now}, {f, s, origin, []byte(strings.Repeat("X", 32)), nil}}
	for i, x := range cases {
		if h, e := New(x.svc, x.sessions, x.origin, x.key, x.clock); e == nil || h != nil {
			t.Errorf("unsafe configuration %d accepted", i)
		}
	}
}
func TestHTTPBoundaryMustRejectUnsafeRequestsBeforeSideEffects(t *testing.T) {
	h, f, _ := makeHandler(t)
	csrf := token(t, h)
	body := `{"organizationId":"` + orgID + `","nodeId":"` + nodeID + `","lifetimeSeconds":300,"envelope":{"manifest":{"nodeId":"` + nodeID + `"}}}`
	tests := []struct {
		name   string
		modify func(*http.Request)
	}{
		{"without TLS", func(r *http.Request) { r.TLS = nil }},
		{"TLS12", func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 }},
		{"wrong host", func(r *http.Request) { r.Host = "evil.example" }},
		{"wrong origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
		{"duplicate origin", func(r *http.Request) { r.Header.Add("Origin", origin) }},
		{"duplicate csrf", func(r *http.Request) { r.Header.Add("X-Omni-CSRF", csrf) }},
		{"duplicate content type", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }},
		{"missing origin", func(r *http.Request) { r.Header.Del("Origin") }},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"cookie credentials", func(r *http.Request) { r.Header.Set("Cookie", "session=ambient") }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "token=oops" }},
		{"no bearer", func(r *http.Request) { r.Header.Del("Authorization") }},
		{"two bearers", func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+sessionToken) }},
		{"missing csrf", func(r *http.Request) { r.Header.Del("X-Omni-CSRF") }},
		{"forged csrf", func(r *http.Request) { r.Header.Set("X-Omni-CSRF", strings.Repeat("A", 64)) }},
		{"duplicate content key", func(r *http.Request) {
			r.Body = http.NoBody
			r.Body = ioBody(`{"nodeId":"` + nodeID + `","nodeId":"` + nodeID + `"}`)
		}},
		{"unknown content key", func(r *http.Request) {
			r.Body = ioBody(`{"organizationId":"` + orgID + `","nodeId":"` + nodeID + `","lifetimeSeconds":300,"envelope":{},"role":"owner"}`)
		}},
		{"compressed", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"GET mutate", func(r *http.Request) { r.Method = "GET" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := request("POST", ProposalPath, body)
			q.Header.Set("X-Omni-CSRF", csrf)
			tc.modify(q)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, q)
			if w.Code < 400 {
				t.Fatalf("unsafe input admitted: %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), sessionToken) || strings.Contains(w.Body.String(), "ambient") {
				t.Fatal("credential reflected")
			}
			if w.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatal("cacheable response")
			}
		})
	}
	if f.proposals != 0 {
		t.Fatalf("unsafe requests reached approval service %d times", f.proposals)
	}
	// A token issued to one live owner cannot authorize a second owner's
	// session, even when both are admitted by the online session checker.
	other := request("POST", ProposalPath, body)
	other.Header.Set("Authorization", "Bearer "+strings.Repeat("B", 42)+"A")
	other.Header.Set("X-Omni-CSRF", csrf)
	otherResult := httptest.NewRecorder()
	h.ServeHTTP(otherResult, other)
	if otherResult.Code != http.StatusForbidden || f.proposals != 0 {
		t.Fatalf("csrf token crossed authenticated sessions: status=%d calls=%d", otherResult.Code, f.proposals)
	}
	good := request("POST", ProposalPath, body)
	good.Header.Set("X-Omni-CSRF", csrf)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, good)
	if w.Code != http.StatusCreated || f.proposals != 1 || f.gotProposal.SessionToken != sessionToken || f.gotProposal.NodeID != nodeID || f.gotProposal.Lifetime != 5*time.Minute {
		t.Fatalf("safe request failed: status=%d calls=%d %+v", w.Code, f.proposals, f.gotProposal)
	}
	if !strings.Contains(string(f.gotProposal.Envelope), `"manifest"`) {
		t.Fatal("signed bytes not propagated")
	}
}
func TestReviewAndApproveUseIndependentDigestConfirmation(t *testing.T) {
	h, f, _ := makeHandler(t)
	csrf := token(t, h)
	path := ProposalPath + "/" + proposalID
	q := request("GET", path, "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, q)
	var preview desiredapproval.Reviewable
	if json.Unmarshal(w.Body.Bytes(), &preview) != nil || w.Code != http.StatusOK || f.reviews != 1 || string(preview.Envelope) != `{"manifest":{"secret":"private"}}` {
		t.Fatalf("review failed: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("review cacheable")
	}
	approve := request("POST", path+"/approval", `{"expectedSha256":"`+strings.Repeat("a", 64)+`"}`)
	approve.Header.Set("X-Omni-CSRF", csrf)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, approve)
	if w.Code != http.StatusCreated || f.approvals != 1 || f.gotApproval.ExpectedSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("approval failed: %d %v", w.Code, f.gotApproval)
	}
	for _, bad := range []string{`{"expectedSha256":"` + strings.Repeat("A", 64) + `"}`, `{"expectedSha256":"` + strings.Repeat("a", 64) + `","expectedSha256":"` + strings.Repeat("a", 64) + `"}`} {
		q = request("POST", path+"/approval", bad)
		q.Header.Set("X-Omni-CSRF", csrf)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, q)
		if w.Code != 400 {
			t.Fatalf("bad digest allowed: %d", w.Code)
		}
	}
	if f.approvals != 1 {
		t.Fatal("malformed approval called service")
	}
}
func TestSessionOutagesAndExpiredCSRFDoNotAuthorize(t *testing.T) {
	h, f, s := makeHandler(t)
	csrf := token(t, h)
	s.ok = false
	q := request("GET", ProposalPath+"/"+proposalID, "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, q)
	if w.Code != 401 || f.reviews != 0 {
		t.Fatalf("missing session was admitted: %d", w.Code)
	}
	s.ok = true
	s.err = errors.New("db down")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, q)
	if w.Code != 503 {
		t.Fatalf("session store failure did not fail closed: %d", w.Code)
	}
	s.err = nil
	// Construct a second handler with a future clock and the same key to simulate expiry.
	future, _ := New(f, s, origin, []byte(strings.Repeat("K", 32)), func() time.Time { return clock.Add(6 * time.Minute) })
	post := request("POST", ProposalPath, `{"organizationId":"`+orgID+`","nodeId":"`+nodeID+`","lifetimeSeconds":300,"envelope":{}}`)
	post.Header.Set("X-Omni-CSRF", csrf)
	w = httptest.NewRecorder()
	future.ServeHTTP(w, post)
	if w.Code != 403 || f.proposals != 0 {
		t.Fatalf("expired csrf token admitted: %d", w.Code)
	}
}

func TestReviewAndCSRFEndpointsRejectUnboundedGETBodies(t *testing.T) {
	for _, endpoint := range []string{CSRFPath, ProposalPath + "/" + proposalID} {
		for _, tc := range []struct {
			name string
			set  func(*http.Request)
		}{
			{"known nonempty", func(r *http.Request) {}},
			{"chunked unknown length", func(r *http.Request) {
				r.ContentLength = -1
				r.TransferEncoding = []string{"chunked"}
			}},
			{"unknown length", func(r *http.Request) { r.ContentLength = -1 }},
		} {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				h, f, _ := makeHandler(t)
				q := request(http.MethodGet, endpoint, "unexpected request content")
				tc.set(q)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, q)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("GET with unexpected body was accepted: status=%d", w.Code)
				}
				if f.reviews != 0 || f.proposals != 0 || f.approvals != 0 {
					t.Fatal("unexpected GET body reached protected administrator service")
				}
			})
		}
	}
}

func ioBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
