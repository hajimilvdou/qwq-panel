// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// idempotency returns the key and fingerprint of a mutating request. The gateway
// already rejected a malformed key on routes that require one; a conditional
// route calls this and treats a malformed key as a validation error.
func (a *api) idempotency(r *http.Request, request any) (operations.Idempotency, error) {
	key, err := gateway.IdempotencyKey(r)
	if err != nil {
		return operations.Idempotency{}, err
	}
	return operations.Idempotency{
		Key:         key,
		Method:      r.Method,
		Route:       r.URL.Path,
		Fingerprint: fingerprint(request),
	}, nil
}

// fingerprint is the request fingerprint the operation manager stores with an
// idempotency key: the SHA-256 of the canonical JSON of the request.
func fingerprint(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// replayTTL matches the idempotency_ttl of the public document (24 h). The cache
// lives in memory, so a restart forgets keys; the domain write is still guarded
// by expected_revision, which turns a replay into REVISION_CONFLICT instead of a
// second change.
const replayTTL = 24 * time.Hour

// replayCapacity bounds the cache on a 1 GiB host.
const replayCapacity = 256

// replayEntry is one stored response.
type replayEntry struct {
	fingerprint string
	status      int
	body        []byte
	expires     time.Time
}

// replayCache bridges the idempotency contract for the catalog-exempt routes
// (delegation management, enrollment links). operations.Service owns the
// durable key store for everything that travels through Run/ExecutePlan/Decide;
// those routes are not catalog actions, so the host half stores their response
// here instead of leaving a documented requirement unimplemented.
type replayCache struct {
	mu      sync.Mutex
	entries map[string]*replayEntry
	order   []string
	clock   clock.Clock
}

func newReplayCache(c clock.Clock) *replayCache {
	return &replayCache{entries: make(map[string]*replayEntry, replayCapacity), clock: c}
}

// replayKey is the documented key scope: principal + method + concrete path + key.
func replayKey(scope, key string) string {
	return scope + "\x00" + key
}

// lookup returns the stored response, or IDEMPOTENCY_KEY_REUSED when the key was
// used for a different request.
func (c *replayCache) lookup(scope, key, requestFingerprint string) (*replayEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := replayKey(scope, key)
	entry, ok := c.entries[k]
	if !ok {
		return nil, nil
	}
	if !entry.expires.After(c.clock.Now().UTC()) {
		delete(c.entries, k)
		return nil, nil
	}
	if entry.fingerprint != requestFingerprint {
		return nil, problem.New(problem.IdempotencyKeyReused,
			"The idempotency key was already used for a different request.")
	}
	return entry, nil
}

// store keeps the response of a finished request and evicts expired or oldest
// entries so the cache cannot grow without bound.
func (c *replayCache) store(scope, key, requestFingerprint string, status int, body []byte) {
	now := c.clock.Now().UTC()
	k := replayKey(scope, key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[k]; !ok {
		c.order = append(c.order, k)
	}
	c.entries[k] = &replayEntry{fingerprint: requestFingerprint, status: status, body: append([]byte(nil), body...), expires: now.Add(replayTTL)}
	for len(c.entries) > replayCapacity && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}

// withoutMember returns body with one top-level JSON member removed. It keeps a
// secret that is shown exactly once out of an idempotent replay: the delegation
// token (OpenAPI DelegationCreated.token) and the enrollment token (OpenAPI
// EnrollmentToken.enrollment_token).
func withoutMember(body []byte, member string) []byte {
	if len(body) == 0 {
		return body
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	if _, ok := doc[member]; !ok {
		return body
	}
	delete(doc, member)
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}
