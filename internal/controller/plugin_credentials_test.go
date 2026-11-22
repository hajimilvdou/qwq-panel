// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func TestPluginTokensRoundTrip(t *testing.T) {
	tokens := PluginTokens{DB: testDB(t)}
	if _, err := tokens.Digest(t.Context(), "alpha"); !errors.Is(err, ErrNoPluginToken) {
		t.Fatalf("Digest before Put = %v, want ErrNoPluginToken", err)
	}
	for _, token := range []string{"first-token", "rotated-token"} {
		if err := tokens.Put(t.Context(), "alpha", []byte(token)); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := tokens.Digest(t.Context(), "alpha")
		if err != nil {
			t.Fatalf("Digest: %v", err)
		}
		if want := sha256.Sum256([]byte(token)); string(got) != string(want[:]) {
			t.Errorf("Digest after Put(%q) = %x, want %x", token, got, want)
		}
	}
}
