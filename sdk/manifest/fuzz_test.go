// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var inlineSeeds = []string{
	`{}`, `[]`, `null`, `{"a":1,"a":2}`, `{"a":"\ud800"}`, `{"a":1.5}`, `{"a":1e400}`,
	`{"schema_version":"1.0"}`, `{} {}`, "\xff", `[[[[[[[[[[]]]]]]]]]]`,
}

// fuzzSeeds returns the example and every fixture input of at most 64 KiB.
func fuzzSeeds(f *testing.F) [][]byte {
	var out [][]byte
	for _, s := range inlineSeeds {
		out = append(out, []byte(s))
	}
	if _, err := os.Stat(apiDir); err != nil {
		return out
	}
	if b, err := os.ReadFile(filepath.Join(apiDir, "examples", "security.scan.manifest.json")); err == nil {
		out = append(out, b)
	}
	for _, c := range loadCases(f) {
		if b, err := buildInput(c); err == nil && len(b) <= 64<<10 {
			out = append(out, b)
		}
	}
	return out
}

// FuzzParse: Parse never panics; an accepted manifest re-encodes to bytes that
// Parse accepts again with the same result; the strict decoder never accepts
// what encoding/json rejects, and agrees with it on the decoded value.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if tree, derr := decodeStrict(raw); derr == nil {
			if !json.Valid(raw) {
				t.Fatalf("strict decoder accepted invalid JSON %q", raw)
			}
			var std any
			if err := json.Unmarshal(raw, &std); err != nil {
				t.Fatal(err)
			}
			if !sameJSON(tree, std) {
				t.Fatalf("strict decoder and encoding/json disagree on %q", raw)
			}
		} else if c := derr.Violations[0].Code; json.Valid(raw) && (c == CodeInvalidJSON || c == CodeTrailingData) {
			t.Fatalf("strict decoder: %s for valid JSON %q", c, raw)
		}

		m, err := Parse(raw)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || len(e.Violations) == 0 || len(e.Violations) > MaxViolations {
				t.Fatalf("bad error %#v", err)
			}
			return
		}
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) > MaxSize {
			return // HTML and U+2028 escaping can grow the text; not a property of Parse
		}
		m2, err := Parse(out)
		if err != nil {
			t.Fatalf("re-encoded manifest rejected: %v\n%s", err, out)
		}
		if !reflect.DeepEqual(m, m2) {
			t.Fatalf("round trip changed the manifest\n%s", out)
		}
	})
}

// sameJSON compares a decodeStrict tree with an encoding/json any value.
// Numbers are compared as float64, exact because |n| <= 2^53-1.
func sameJSON(a, b any) bool {
	switch a := a.(type) {
	case map[string]any:
		b, ok := b.(map[string]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for k, v := range a {
			if w, ok := b[k]; !ok || !sameJSON(v, w) {
				return false
			}
		}
		return true
	case []any:
		b, ok := b.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !sameJSON(a[i], b[i]) {
				return false
			}
		}
		return true
	case json.Number:
		f, err := a.Float64()
		g, ok := b.(float64)
		return err == nil && ok && f == g
	default:
		return a == b
	}
}

// FuzzVerifyAndParse: no panics; success implies a trusted, matching key.
func FuzzVerifyAndParse(f *testing.F) {
	priv := testKey(1)
	pub := priv.Public().(ed25519.PublicKey)
	ts := mustStore(f, TrustedKey{PublicKey: pub})
	if _, err := os.Stat(apiDir); err == nil {
		raw := signedExample(f, priv)
		f.Add(raw, sign(priv, raw))
		f.Add(raw, sign(testKey(2), raw))
	}
	f.Add([]byte(`{}`), sign(priv, []byte(`{}`)))
	f.Add([]byte(`{}`), []byte(`{"key_id":"x","signature":""}`))
	f.Fuzz(func(t *testing.T, raw, sig []byte) {
		_, _ = ParseSignature(sig)
		m, err := VerifyAndParse(raw, sig, ts)
		if err != nil {
			return
		}
		s, perr := ParseSignature(sig)
		if perr != nil || s.KeyID != KeyID(pub) || m.Publisher.KeyID != s.KeyID || !ed25519.Verify(pub, raw, s.Sig) {
			t.Fatalf("accepted without a valid trusted signature")
		}
	})
}
