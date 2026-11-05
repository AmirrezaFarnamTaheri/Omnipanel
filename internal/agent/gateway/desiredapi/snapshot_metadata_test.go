package desiredapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A database head is not itself signed. Even if its stored envelope is valid,
// its epoch and revision metadata must describe the exact signed manifest.
// Otherwise a corrupt or unauthorized head can misrepresent the revision.
func TestDesiredHandlerRejectsSnapshotMetadataNotBoundToSignedManifest(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"zero sequence", func(s *Snapshot) { s.StructuralSequence = 0 }},
		{"wrong structural sequence", func(s *Snapshot) { s.StructuralSequence = 3 }},
		{"wrong membership sequence", func(s *Snapshot) { s.MembershipSequence = 4 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, source, peer := fixtureHandler(t)
			tc.mutate(&source.snapshot)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, desiredRequest(requestQuery("0", "0"), &peer))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("unbound stored metadata served signed state: status=%d", w.Code)
			}
		})
	}
}
