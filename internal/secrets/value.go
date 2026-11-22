// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"fmt"
	"log/slog"
	"slices"

	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// RefKey is the member name of the JSON form of a secret reference.
const RefKey = "$secret"

// redacted is what every string form of secret material returns.
const redacted = "[REDACTED]"

// Ref is a secret reference: the id of one row in the secrets table. A
// reference is safe to store in settings, config snapshots, events, audit rows
// and logs; the value it points to is not (ARCH §5.6).
type Ref string

// ParseRef validates a secret reference.
func ParseRef(s string) (Ref, error) {
	if err := ids.Check(s, ids.Secret); err != nil {
		return "", problem.New(problem.ValidationFailed, "Not a secret reference.")
	}
	return Ref(s), nil
}

// String returns the reference, which is not sensitive.
func (r Ref) String() string { return string(r) }

// Valid reports whether the reference is well formed.
func (r Ref) Valid() bool { return ids.Valid(string(r), ids.Secret) }

// RefObject returns the JSON form of a reference: {"$secret": "sec_…"}.
//
// Config snapshots and settings store this object in place of a sensitive
// value. ResolveSecrets turns it back into the value before the config is
// applied, and RedactForExport never emits references.
func RefObject(r Ref) map[string]any { return map[string]any{RefKey: string(r)} }

// RefFromObject reports whether v is the JSON form of a reference and returns
// it.
func RefFromObject(v any) (Ref, bool) {
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != 1 {
		return "", false
	}
	raw, ok := obj[RefKey]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok {
		return "", false
	}
	r, err := ParseRef(s)
	if err != nil {
		return "", false
	}
	return r, true
}

// Secret is decrypted secret material. Its bytes are unexported and every
// string form is redacted, so a value cannot reach a log line, a template or an
// error message by accident. Bytes returns a copy; Clear overwrites the
// material this value holds (a best-effort wipe: the Go runtime may have copied
// it already).
type Secret struct {
	b []byte
}

// newSecret takes ownership of b.
func newSecret(b []byte) Secret { return Secret{b: b} }

// Bytes returns a copy of the plaintext.
func (s Secret) Bytes() []byte { return slices.Clone(s.b) }

// Len returns the length of the plaintext in bytes.
func (s Secret) Len() int { return len(s.b) }

// IsEmpty reports whether the secret holds no bytes.
func (s Secret) IsEmpty() bool { return len(s.b) == 0 }

// Clear overwrites the stored bytes.
func (s *Secret) Clear() {
	clear(s.b)
	s.b = nil
}

// String implements fmt.Stringer.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer so that %#v cannot print the plaintext.
func (s Secret) GoString() string { return "secrets.Secret{[REDACTED]}" }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON refuses to serialize secret material.
func (s Secret) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("secrets: refusing to encode secret material as JSON")
}
