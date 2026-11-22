// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKey derives a deterministic key; seedByte distinguishes keys.
func testKey(seedByte byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
}

// sign is the test-only signing helper (the signing CLI is P2-T3).
func sign(priv ed25519.PrivateKey, raw []byte) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	return Signature{KeyID: KeyID(pub), Sig: ed25519.Sign(priv, raw)}.Encode()
}

// signedExample returns the example manifest with publisher.key_id set to
// the key of priv. The edit is textual, so the bytes stay as authored.
func signedExample(t testing.TB, priv ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(apiDir, "examples", "security.scan.manifest.json"))
	if err != nil {
		t.Skipf("example not available: %v", err)
	}
	id := KeyID(priv.Public().(ed25519.PublicKey))
	placeholder := `"ed25519:` + strings.Repeat("4f1c2b7d9a2e6c01", 4) + `"`
	out := bytes.Replace(raw, []byte(placeholder), []byte(`"`+id+`"`), 1)
	if bytes.Equal(out, raw) {
		t.Fatal("example key_id not found")
	}
	return out
}

func mustStore(t testing.TB, keys ...TrustedKey) *StaticTrustStore {
	t.Helper()
	s, err := NewStaticTrustStore(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || !e.Has(code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestKeyID(t *testing.T) {
	// RFC 8032 §7.1 test 1 public key.
	pub, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	const want = "ed25519:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
	if got := KeyID(pub); got != want {
		t.Fatalf("KeyID = %s, want %s", got, want)
	}
	if !keyIDPattern.MatchString(want) {
		t.Fatal("KeyID does not match its own pattern")
	}
}

func TestVerifyAndParse(t *testing.T) {
	needAPI(t)
	priv := testKey(1)
	pub := priv.Public().(ed25519.PublicKey)
	raw := signedExample(t, priv)
	sig := sign(priv, raw)
	ts := mustStore(t, TrustedKey{PublicKey: pub})

	m, err := VerifyAndParse(raw, sig, ts)
	if err != nil {
		t.Fatal(err)
	}
	if m.Publisher.KeyID != KeyID(pub) || m.ID != "security.scan" {
		t.Fatalf("unexpected manifest %+v", m.Publisher)
	}

	t.Run("tampered", func(t *testing.T) {
		bad := bytes.Replace(raw, []byte(`"risk": "medium"`), []byte(`"risk": "low"   `), 1)
		_, err := VerifyAndParse(bad, sig, ts)
		wantCode(t, err, CodeSignatureInvalid)
	})
	t.Run("unknown key", func(t *testing.T) {
		_, err := VerifyAndParse(raw, sig, mustStore(t, TrustedKey{PublicKey: testKey(2).Public().(ed25519.PublicKey)}))
		wantCode(t, err, CodeKeyUnknown)
	})
	t.Run("signed by another trusted key", func(t *testing.T) {
		other := testKey(3)
		ts2 := mustStore(t, TrustedKey{PublicKey: pub}, TrustedKey{PublicKey: other.Public().(ed25519.PublicKey)})
		_, err := VerifyAndParse(raw, sign(other, raw), ts2)
		wantCode(t, err, CodeKeyIDMismatch)
	})
	t.Run("publisher binding", func(t *testing.T) {
		_, err := VerifyAndParse(raw, sig, mustStore(t, TrustedKey{PublicKey: pub, Publisher: "someone-else"}))
		wantCode(t, err, CodePublisherMismatch)
		if _, err := VerifyAndParse(raw, sig, mustStore(t, TrustedKey{PublicKey: pub, Publisher: "qwq-builtin"})); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("verified but invalid manifest", func(t *testing.T) {
		bad := append(bytes.Clone(raw), []byte(`{}`)...)
		_, err := VerifyAndParse(bad, sign(priv, bad), ts)
		wantCode(t, err, CodeTrailingData)
	})
	t.Run("signature checked before parsing", func(t *testing.T) {
		_, err := VerifyAndParse([]byte(`{"id":1,"id":2}`), sig, ts)
		wantCode(t, err, CodeSignatureInvalid)
	})
	t.Run("too large before signature", func(t *testing.T) {
		_, err := VerifyAndParse(make([]byte, MaxSize+1), []byte("garbage"), ts)
		wantCode(t, err, CodeTooLarge)
	})
	t.Run("trust store failure", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := VerifyAndParse(raw, sig, failingStore{boom})
		var e *Error
		if !errors.Is(err, boom) || errors.As(err, &e) {
			t.Fatalf("want wrapped trust store error, got %v", err)
		}
	})
	t.Run("lying trust store", func(t *testing.T) {
		_, err := VerifyAndParse(raw, sig, lyingStore{testKey(4).Public().(ed25519.PublicKey)})
		var e *Error
		if err == nil || errors.As(err, &e) {
			t.Fatalf("want a configuration error, got %v", err)
		}
	})
}

type failingStore struct{ err error }

func (f failingStore) LookupKey(string) (TrustedKey, error) { return TrustedKey{}, f.err }

type lyingStore struct{ pub ed25519.PublicKey }

func (l lyingStore) LookupKey(string) (TrustedKey, error) { return TrustedKey{PublicKey: l.pub}, nil }

func TestParseSignature(t *testing.T) {
	id := KeyID(testKey(1).Public().(ed25519.PublicKey))
	sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	good := `{"key_id":"` + id + `","signature":"` + sig + `"}`
	s, err := ParseSignature([]byte(good))
	if err != nil || s.KeyID != id || len(s.Sig) != 64 {
		t.Fatalf("ParseSignature(good) = %+v, %v", s, err)
	}
	if again, err := ParseSignature(s.Encode()); err != nil || again.KeyID != s.KeyID || !bytes.Equal(again.Sig, s.Sig) {
		t.Fatalf("Encode/ParseSignature round trip: %+v, %v", again, err)
	}
	bad := []string{
		``, `[]`, `{}`, `{"key_id":"` + id + `"}`,
		`{"key_id":"` + id + `","signature":"` + sig + `","extra":1}`,
		`{"key_id":"` + id + `","key_id":"` + id + `","signature":"` + sig + `"}`,
		`{"key_id":"` + strings.ToUpper(id) + `","signature":"` + sig + `"}`,
		`{"key_id":"ed25519:4f1c2b7d9a2e6c01","signature":"` + sig + `"}`,
		`{"key_id":"` + id + `0","signature":"` + sig + `"}`,
		`{"key_id":"` + id + `","signature":"` + base64.StdEncoding.EncodeToString(make([]byte, 63)) + `"}`,
		`{"key_id":"` + id + `","signature":"` + base64.RawStdEncoding.EncodeToString(make([]byte, 64)) + `"}`,
		`{"key_id":"` + id + `","signature":"` + base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 64)) + `"}`,
		`{"key_id":"` + id + `","signature":1}`,
		good + ` x`,
		good + strings.Repeat(" ", MaxSignatureSize),
	}
	for _, b := range bad {
		_, err := ParseSignature([]byte(b))
		var e *Error
		if !errors.As(err, &e) || !e.Has(CodeSignatureMalformed) {
			t.Errorf("ParseSignature(%.60q) = %v, want SIGNATURE_MALFORMED", b, err)
		}
	}
}

func TestStaticTrustStore(t *testing.T) {
	pub := testKey(1).Public().(ed25519.PublicKey)
	if _, err := NewStaticTrustStore(TrustedKey{PublicKey: pub[:31]}); err == nil {
		t.Error("short key accepted")
	}
	if _, err := NewStaticTrustStore(TrustedKey{PublicKey: pub}, TrustedKey{PublicKey: pub}); err == nil {
		t.Error("duplicate key accepted")
	}
	s := mustStore(t, TrustedKey{PublicKey: pub, Publisher: "p"})
	if k, err := s.LookupKey(KeyID(pub)); err != nil || !k.PublicKey.Equal(pub) || k.Publisher != "p" {
		t.Errorf("LookupKey = %+v, %v", k, err)
	}
	if _, err := s.LookupKey("ed25519:00"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound, got %v", err)
	}
}

func TestTrustedKeyPluginNamespace(t *testing.T) {
	priv := testKey(1)
	pub := priv.Public().(ed25519.PublicKey)
	raw := signedExample(t, priv) // id is security.scan
	sig := sign(priv, raw)
	for _, tc := range []struct {
		ids []string
		ok  bool
	}{
		{nil, true},
		{[]string{}, false},
		{[]string{"security.scan"}, true},
		{[]string{"security.*"}, true},
		{[]string{"security.scan.*"}, false},
		{[]string{"security"}, false},
		{[]string{"*"}, false},
		{[]string{"acme.*", "security.scan"}, true},
	} {
		_, err := VerifyAndParse(raw, sig, mustStore(t, TrustedKey{PublicKey: pub, PluginIDs: tc.ids}))
		if tc.ok && err != nil {
			t.Errorf("%v: %v", tc.ids, err)
		}
		if !tc.ok {
			wantCode(t, err, CodePluginNamespaceMismatch)
		}
	}
}
