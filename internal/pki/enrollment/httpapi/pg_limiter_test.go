package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestRateLimiterRefusesInvalidConfiguration(t *testing.T) {
	validSecret := bytes.Repeat([]byte{0x4a}, 32)
	for _, tc := range []struct {
		name        string
		db          *sql.DB
		key         []byte
		peerLimit   int
		globalLimit int
	}{
		{"nil database", nil, validSecret, 3, 100},
		{"missing HMAC key", new(sql.DB), nil, 3, 100},
		{"short HMAC key", new(sql.DB), validSecret[:16], 3, 100},
		{"invalid peer budget", new(sql.DB), validSecret, 0, 100},
		{"invalid global budget", new(sql.DB), validSecret, 3, 0},
		{"out-of-range budget", new(sql.DB), validSecret, 3, 1000001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limiter, err := NewPostgresLimiter(tc.db, tc.key, tc.peerLimit, tc.globalLimit)
			if limiter != nil || !errors.Is(err, ErrInvalidRateConfig) {
				t.Fatalf("invalid limiter accepted: %#v, %v", limiter, err)
			}
		})
	}
}

func TestRateLimiterRejectsPeerSpoofingBeforeDatabaseAccess(t *testing.T) {
	limiter, err := NewPostgresLimiter(new(sql.DB), bytes.Repeat([]byte{0x7a}, 32), 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "not-an-ip", "10.0.0.5:53000", " 203.0.113.1 ", "203.0.113.999", "user@127.0.0.1"} {
		allowed, err := limiter.Allow(context.Background(), input)
		if allowed || !errors.Is(err, ErrInvalidPeer) {
			t.Fatalf("invalid peer admitted: %q allowed=%t err=%v", input, allowed, err)
		}
	}
}

func TestRateLimiterUsesKeyedDigestAndCanonicalIP(t *testing.T) {
	limiter, err := NewPostgresLimiter(new(sql.DB), bytes.Repeat([]byte{0x7a}, 32), 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := limiter.peerDigest("203.0.113.44")
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := limiter.peerDigest("::ffff:203.0.113.44")
	if err != nil || ordinary != mapped {
		t.Fatalf("mapped IPv4 evaded same per-peer budget: %v", err)
	}
	other, err := limiter.peerDigest("203.0.113.45")
	if err != nil || other == ordinary || ordinary == [32]byte{} {
		t.Fatal("two distinct peers share rate-limit digest")
	}
	differentKey, err := NewPostgresLimiter(new(sql.DB), bytes.Repeat([]byte{0x6a}, 32), 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	different, _ := differentKey.peerDigest("203.0.113.44")
	if different == ordinary {
		t.Fatal("rate-limit digest ignores secret key")
	}
}
