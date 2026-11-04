package grants

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestTOTPMatchesPublishedRFC6238SHA1Vector(t *testing.T) {
	// RFC 6238 SHA-1 vector at T=59 yields 94287082 (8 digits), i.e. 287082 (6 digits).
	secret := []byte("12345678901234567890")
	if got := totpCode(secret, 1); got != "287082" {
		t.Fatalf("TOTP SHA-1 RFC vector: got %s, want 287082", got)
	}
}

func TestTOTPCountersAreSingleUseAcrossAdjacentWindows(t *testing.T) {
	secret := []byte("12345678901234567890")
	code := "287082"
	if step, valid := matchTOTP(secret, code, 1, -1); !valid || step != 1 {
		t.Fatalf("valid counter rejected: step=%d valid=%v", step, valid)
	}
	if _, valid := matchTOTP(secret, code, 1, 1); valid {
		t.Fatal("replayed TOTP counter was accepted")
	}
	if _, valid := matchTOTP(secret, code, 2, -1); !valid {
		t.Fatal("previous adjacent TOTP step rejected")
	}
	for _, bad := range []string{"", "1", "28708", "2870820", "28 082", "aaaaaa", "999999"} {
		if _, valid := matchTOTP(secret, bad, 1, -1); valid {
			t.Fatalf("invalid code %q accepted", bad)
		}
	}
	if _, valid := matchTOTP(secret, code, 3, -1); valid {
		t.Fatal("stale TOTP outside +/- one step accepted")
	}
}

// An accidental nil key custodian would otherwise permit unverified MFA.
type rejectOpener struct{}

func (rejectOpener) OpenTOTP(_ context.Context, _ int64, _ string) ([]byte, error) {
	return nil, errors.New("not available")
}
func TestStepUpRefusesUntrustedConstructorAndMalformedFactors(t *testing.T) {
	if _, err := NewStepUpService(nil, rejectOpener{}); !errors.Is(err, ErrStepUpConfig) {
		t.Fatal("nil DB accepted")
	}
	if _, err := NewStepUpService(new(sql.DB), nil); !errors.Is(err, ErrStepUpConfig) {
		t.Fatal("nil key opener accepted")
	}
	svc, err := NewStepUpService(new(sql.DB), rejectOpener{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "12345", "1234567", "12ab56"} {
		if err := svc.Verify(context.Background(), "token", bad); !errors.Is(err, ErrStepUpCode) {
			t.Fatalf("malformed code %q was not rejected before DB: %v", bad, err)
		}
	}
}
