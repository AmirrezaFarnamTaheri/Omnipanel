package grants

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

const (
	nodeID         = "62c478bb-47c3-4dc6-a363-a2fbde813810"
	organizationID = "161e69df-38db-4476-a3dd-b9adb0f822a1"
	correlationID  = "c090a8e3-12fd-48d5-8dc4-0ab999a3da03"
)

func validInput() Request {
	return Request{
		AdminSessionToken: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xA3}, 32)),
		OrganizationID:    organizationID, NodeID: nodeID, CorrelationID: correlationID,
		Lifetime: 5 * time.Minute,
	}
}

func TestNewRejectsMissingStorage(t *testing.T) {
	svc, err := New(nil)
	if svc != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing database accepted: %v %v", svc, err)
	}
}

func TestIssueRejectsInvalidSessionScopeAndDurationWithoutDBWrites(t *testing.T) {
	svc, err := New(new(sql.DB))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*Request)
	}{
		{"missing token", func(r *Request) { r.AdminSessionToken = "" }},
		{"short token", func(r *Request) { r.AdminSessionToken = "abc" }},
		{"noncanonical token", func(r *Request) { r.AdminSessionToken += "=" }},
		{"invalid node uuid", func(r *Request) { r.NodeID = "not-a-uuid" }},
		{"wrong-case node", func(r *Request) { r.NodeID = "62C478BB-47c3-4dc6-a363-a2fbde813810" }},
		{"bad org id", func(r *Request) { r.OrganizationID = "" }},
		{"bad correlation", func(r *Request) { r.CorrelationID = "not-uuid" }},
		{"zero lifetime", func(r *Request) { r.Lifetime = 0 }},
		{"short lifetime", func(r *Request) { r.Lifetime = 59 * time.Second }},
		{"long lifetime", func(r *Request) { r.Lifetime = 16 * time.Minute }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validInput()
			tc.change(&r)
			got, err := svc.Issue(context.Background(), r)
			if !errors.Is(err, ErrInvalidInput) || got.Token != "" {
				t.Fatalf("invalid request accepted or wrote token: token_returned=%t err=%v", got.Token != "", err)
			}
		})
	}
}

func TestCanceledContextRefusesIssuance(t *testing.T) {
	svc, _ := New(new(sql.DB))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.Issue(ctx, validInput())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request not rejected: %v", err)
	}
}
