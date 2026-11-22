// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// canonicalJSON re-encodes a JSON document deterministically: object members
// sorted by name, no insignificant whitespace, array order kept and numbers
// kept exactly as written. That is what idempotency fingerprints and plan
// binding need, and it never changes the meaning of a request.
//
// It is deliberately not a full RFC 8785 (JCS) implementation: the host has no
// canonicalisation dependency, so number literals are preserved (1.0 and 1 stay
// distinct) instead of being reformatted. Two clients sending the same value in
// the same notation get the same digest.
func canonicalJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("{}"), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("operations: trailing data after JSON value")
	}
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		enc, err := json.Marshal(x)
		if err != nil {
			return err
		}
		b.Write(enc)
	case json.Number:
		if !json.Valid([]byte(x)) {
			return fmt.Errorf("operations: invalid JSON number %q", string(x))
		}
		b.WriteString(string(x))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			enc, err := json.Marshal(k)
			if err != nil {
				return err
			}
			b.Write(enc)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("operations: unexpected JSON value of type %T", v)
	}
	return nil
}

// canonicalObject validates that raw is a JSON object and returns its canonical
// form. Actions take an object as arguments; null is treated as {}.
func canonicalObject(raw []byte) ([]byte, error) {
	canon, err := canonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	if string(canon) == "null" {
		return []byte("{}"), nil
	}
	if len(canon) == 0 || canon[0] != '{' {
		return nil, errors.New("operations: arguments must be a JSON object")
	}
	return canon, nil
}
