// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// SecretField accepts both raw JSON strings and host-protected secret envelopes
// produced by OperationProtector when a schema property declares x-secret: true:
//   - JSON string: `"sk-xxx"` -> Plain = "sk-xxx"
//   - Secret reference: `{"$secret":"sec_..."}` -> SecretRef = "sec_..."
//   - Keep marker: `{"$keep_secret":true}` or `{"$secret_present":true}` -> KeepExisting = true
type SecretField struct {
	Plain        string
	SecretRef    string
	KeepExisting bool
}

type secretEnvelope struct {
	Secret        string `json:"$secret"`
	KeepSecret    bool   `json:"$keep_secret"`
	SecretPresent bool   `json:"$secret_present"`
}

// IsEmpty reports whether no secret value, reference, or keep marker was supplied.
func (s SecretField) IsEmpty() bool {
	return s.Plain == "" && s.SecretRef == "" && !s.KeepExisting
}

// UnmarshalJSON strictly decodes either a JSON string or a host secret envelope,
// remaining compatible with json.Decoder.DisallowUnknownFields.
func (s *SecretField) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*s = SecretField{}
		return nil
	}
	if trimmed[0] == '"' {
		var plain string
		if err := json.Unmarshal(trimmed, &plain); err != nil {
			return err
		}
		*s = SecretField{Plain: plain}
		return nil
	}
	if trimmed[0] == '{' {
		var env secretEnvelope
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&env); err != nil {
			return fmt.Errorf("invalid secret reference object: %w", err)
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return errors.New("unexpected trailing tokens in secret reference object")
		}
		if env.Secret != "" {
			*s = SecretField{SecretRef: env.Secret}
			return nil
		}
		if env.KeepSecret || env.SecretPresent {
			*s = SecretField{KeepExisting: true}
			return nil
		}
		*s = SecretField{}
		return nil
	}
	return errors.New("secret field must be a JSON string or {$secret} object")
}

// MarshalJSON redacts plaintext secrets so accidental marshaling into logs or
// responses never leaks raw secret bytes.
func (s SecretField) MarshalJSON() ([]byte, error) {
	if s.SecretRef != "" {
		return json.Marshal(map[string]string{"$secret": s.SecretRef})
	}
	if s.KeepExisting || s.Plain != "" {
		return []byte(`{"$secret_present":true}`), nil
	}
	return []byte(`""`), nil
}

// ResolveBytes reveals the plaintext bytes of the secret. Callers must invoke
// the returned cleanup function to zero the buffer once done.
func (s *SecretField) ResolveBytes(ctx context.Context, host *Host, purpose string) (secret []byte, keepExisting bool, cleanup func(), err error) {
	noop := func() {}
	if s == nil || s.IsEmpty() {
		return nil, false, noop, nil
	}
	if s.KeepExisting {
		return nil, true, noop, nil
	}
	if s.SecretRef != "" {
		if host == nil || host.Conn() == nil {
			return nil, false, noop, ErrNoHost
		}
		raw, revErr := host.RevealSecret(ctx, s.SecretRef, purpose)
		if revErr != nil {
			return nil, false, noop, revErr
		}
		// Host secret storage may wrap string secrets as JSON string literals.
		if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
			var unquoted string
			if json.Unmarshal(raw, &unquoted) == nil {
				clear(raw)
				buf := []byte(unquoted)
				return buf, false, func() { clear(buf) }, nil
			}
		}
		return raw, false, func() { clear(raw) }, nil
	}
	buf := []byte(s.Plain)
	s.Plain = ""
	return buf, false, func() { clear(buf) }, nil
}

// ResolveString reveals the secret as a short-lived string while still zeroing
// the intermediate byte buffer.
func (s *SecretField) ResolveString(ctx context.Context, host *Host, purpose string) (val string, keepExisting bool, err error) {
	raw, keep, cleanup, err := s.ResolveBytes(ctx, host, purpose)
	if err != nil || keep {
		return "", keep, err
	}
	defer cleanup()
	return string(raw), false, nil
}
