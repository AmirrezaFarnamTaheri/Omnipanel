package desiredapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const recoveredEpoch = "32486a70-22d9-4ec4-97bd-21881762f6d0"

// Database state, including its stored epoch, can be rolled back by PITR.
// Possession of a valid old signature must never replace a separately
// authorized control-plane epoch from protected gateway configuration.
func TestDesiredHandlerRejectsOldSignedDatabaseEpochAfterRecovery(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	previouslySigned, verifier := fixtureSignedDesired(t, now)
	verifier.AuthorizedEpoch = recoveredEpoch
	source := &fixtureSource{snapshot: Snapshot{
		Epoch: desiredEpoch, StructuralSequence: 2,
		MembershipSequence: 3, Envelope: previouslySigned,
	}}
	handler, err := NewHandler(&fixtureLedger{active: true}, source, desiredDomain, verifier, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	peer := fixtureVerifiedPeer(t, now)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, desiredRequest(requestQuery("0", "0"), &peer))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("signed old epoch bypassed independently trusted recovery epoch: %d", w.Code)
	}
}

func TestDesiredHandlerRequiresSeparatelyProvisionedAuthorizedEpoch(t *testing.T) {
	now := time.Now().UTC()
	_, verifier := fixtureSignedDesired(t, now)
	verifier.AuthorizedEpoch = ""
	if _, err := NewHandler(&fixtureLedger{active: true}, &fixtureSource{}, desiredDomain, verifier, func() time.Time { return now }); err == nil {
		t.Fatal("desired gateway constructed without a trusted control-plane epoch")
	}
}
