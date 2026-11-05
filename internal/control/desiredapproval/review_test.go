package desiredapproval

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestReviewerPreviewRefusesMissingOrUnverifiedSession(t *testing.T) {
	svc, err := NewService(new(sql.DB), testVerifier())
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []ReviewRequest{
		{},
		{SessionToken: "invalid", ProposalID: testProposal},
		{SessionToken: testToken(), ProposalID: "bad"},
	} {
		if _, err := svc.Review(context.Background(), req); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("unverified review request escaped input validation: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.Review(ctx, ReviewRequest{SessionToken: testToken(), ProposalID: testProposal}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled review request continued: %v", err)
	}
}
