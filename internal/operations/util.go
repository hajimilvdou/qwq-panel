// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"encoding/base64"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// base64URL makes a cursor opaque (OpenAPI Cursor is an opaque string).
func base64URL(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func base64URLDecode(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// encodeCursor turns an operation or approval ID into an opaque cursor.
func encodeCursor(id string) string { return base64URL(id) }

func decodeCursor(c string) (string, error) { return base64URLDecode(c) }

// violation builds a field-level problem for a request field.
func violation(pointer, code, message string) problem.Violation {
	return problem.Violation{Pointer: pointer, Code: code, Message: message}
}

// stateConflict is the STATE_CONFLICT error of an illegal transition.
func stateConflict(op *Operation, from, to Status) error {
	return &problem.Error{
		Code:        problem.StateConflict,
		Detail:      "The operation cannot move from " + string(from) + " to " + string(to) + ".",
		OperationID: op.ID,
	}
}

// pageRevision is the collection watermark of a page: the journal head at the
// time of the read. Changes committed later have higher revisions, so passing
// it back as since_revision never misses one (ADR-0008 §4).
func (s *Service) pageRevision() string {
	return storage.Revision(s.db.HeadSeq())
}

// expiresAt returns now+d truncated to the storage resolution.
func expiresAt(now time.Time, d time.Duration) time.Time {
	return now.Add(d).UTC().Truncate(time.Millisecond)
}
