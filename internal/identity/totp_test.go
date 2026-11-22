// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"testing"
	"time"
)

func TestTOTPRFC6238Vectors(t *testing.T) {
	// RFC 6238 Appendix B uses the ASCII secret "12345678901234567890" for
	// SHA-1; the reference outputs are 8 digits, so the 6-digit code is the
	// last six digits.
	secret := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		if got := TOTPCode(secret, TOTPStep(time.Unix(c.unix, 0))); got != c.want {
			t.Errorf("TOTP at %d = %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	now := time.Unix(1111111111, 0).UTC()
	secret := make([]byte, TOTPSecretLen)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	step := TOTPStep(now)
	code := TOTPCode(secret, step)

	got, ok := VerifyTOTP(secret, code, now, 0)
	if !ok || got != step {
		t.Fatalf("current code rejected: step=%d ok=%v", got, ok)
	}
	// The same code is rejected once its step has been consumed.
	if _, ok := VerifyTOTP(secret, code, now, got); ok {
		t.Fatal("replayed code accepted")
	}
	// One step in the future is accepted (clock skew).
	next := TOTPCode(secret, step+1)
	if _, ok := VerifyTOTP(secret, next, now, step); !ok {
		t.Fatal("next-step code rejected")
	}
	// Two steps away is outside the ±1 window.
	far := TOTPCode(secret, step+3)
	if _, ok := VerifyTOTP(secret, far, now, 0); ok {
		t.Fatal("code outside the window accepted")
	}
	// Non-digits and wrong lengths are rejected without panicking.
	for _, bad := range []string{"", "12345", "abcdef", "1234567"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("bad code %q accepted", bad)
		}
	}
}

func TestTOTPURL(t *testing.T) {
	secret := []byte("12345678901234567890")
	got := TOTPURL("qwq", "alice", secret)
	want := "otpauth://totp/qwq:alice?algorithm=SHA1&digits=6&issuer=qwq&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got != want {
		t.Fatalf("TOTPURL = %s, want %s", got, want)
	}
}
