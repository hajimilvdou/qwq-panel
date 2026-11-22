// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/ids"
)

// idempotencyKeyRe is the IdempotencyKeyValue schema. internal/gateway has the
// same expression; it is repeated here because the derived key is validated
// before it is passed to internal/operations.
var idempotencyKeyRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

// toolKey resolves the Idempotency-Key of a mutating tool call.
//
// The `execute` and `cancel` tools declare x-qwq-idempotency: required, but an
// MCP adapter that retries a transport error must produce the same key twice,
// so the header is only one of the sources. The order is:
//
//  1. the Idempotency-Key header, when the client sent one (validated);
//  2. X-Tool-Call-Id, the adapter's identifier of one tool invocation;
//  3. X-Request-Id, which the gateway preserves and echoes;
//  4. the request ID the gateway assigned (stable for this request and stored
//     in its logs, so a retried *request* is still deduplicated if the adapter
//     resends the same identifier);
//  5. a fresh idempotency ID, when none of the above exists.
//
// The composed key is always a valid IdempotencyKeyValue: a source that is too
// short or contains other characters is hashed, which keeps it stable.
func (h *handlers) toolKey(r *http.Request, tool string) (string, error) {
	if key, err := gateway.IdempotencyKey(r); err != nil {
		return "", err
	} else if key != "" {
		return key, nil
	}
	source := strings.TrimSpace(r.Header.Get("X-Tool-Call-Id"))
	if source == "" {
		source = strings.TrimSpace(r.Header.Get("X-Request-Id"))
	}
	if source == "" {
		source = gateway.RequestID(r.Context())
	}
	if source == "" {
		source = h.ids.New(ids.Idempotency)
	}
	key := tool + ":" + source
	if idempotencyKeyRe.MatchString(key) {
		return key, nil
	}
	sum := sha256.Sum256([]byte(key))
	return tool + ":" + hex.EncodeToString(sum[:])[:32], nil
}
