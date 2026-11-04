package enrollment

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestApprovedSQLStoreCannotBeConstructedWithoutDatabase(t *testing.T) {
	store, err := NewApprovedSQLStore(nil)
	if store != nil || err == nil {
		t.Fatalf("missing PostgreSQL accepted: store=%v err=%v", store, err)
	}
}

func TestApprovedSQLStoreRejectsInvalidIdentityBeforeDBAccess(t *testing.T) {
	store := &ApprovedSQLStore{}
	allowed, err := store.Active(context.Background(), "invalid-node-id", "123",
		sha256.Sum256([]byte("test-key")), time.Now())
	if allowed || !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invalid node certificate admitted: allowed=%t err=%v", allowed, err)
	}
}
