// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ListQuery is the parsed pagination and increment parameters shared by list
// endpoints: `fields`, `since_revision`, `cursor` and `limit`.
type ListQuery struct {
	// Fields is the projection, nil when the caller did not ask for one.
	Fields *Projection
	// SinceRevision is the watermark of an earlier list response ("" = full
	// snapshot).
	SinceRevision string
	// Cursor is the opaque page cursor ("" = first page).
	Cursor string
	// Limit is the page size, defaulted and bounded by x-qwq-limits.
	Limit int
}

// ListQuery parses the query parameters of a list endpoint. Violations point at
// the query parameter that failed.
func (g *Gateway) ListQuery(r *http.Request) (ListQuery, error) {
	q := r.URL.Query()
	out := ListQuery{Limit: g.limits.ListLimitDefault}

	fields, err := ParseFields(q.Get("fields"), g.limits.FieldsMax)
	if err != nil {
		return ListQuery{}, err
	}
	out.Fields = fields

	if v := q.Get("since_revision"); v != "" {
		if err := checkRevision(v); err != nil {
			return ListQuery{}, err
		}
		out.SinceRevision = v
	}
	if v := q.Get("cursor"); v != "" {
		if len(v) > 512 {
			return ListQuery{}, badRequest("query", "/cursor", "INVALID",
				"The cursor is longer than 512 characters.")
		}
		out.Cursor = v
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > g.limits.ListLimitMax {
			return ListQuery{}, badRequest("query", "/limit", "OUT_OF_RANGE",
				fmt.Sprintf("limit must be an integer between 1 and %d.", g.limits.ListLimitMax))
		}
		out.Limit = n
	}
	return out, nil
}

// checkRevision validates an opaque revision (Revision in the public schema):
// 1 to 64 characters of [A-Za-z0-9._~-].
func checkRevision(v string) error {
	if len(v) == 0 || len(v) > 64 {
		return badRequest("query", "/since_revision", "INVALID",
			"A revision is 1 to 64 characters long.")
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '~' || c == '-') {
			return badRequest("query", "/since_revision", "INVALID",
				"The revision is not a valid opaque revision string.")
		}
	}
	return nil
}

// ExpectedRevisionQuery returns the required expected_revision query parameter
// of a DELETE, which has no body to carry it (ADR-0006 D5).
func ExpectedRevisionQuery(r *http.Request) (string, error) {
	v := r.URL.Query().Get("expected_revision")
	if v == "" {
		return "", badRequest("query", "/expected_revision", codeRequired,
			"expected_revision is required.")
	}
	if err := checkRevision(v); err != nil {
		return "", badRequest("query", "/expected_revision", "INVALID",
			"The revision is not a valid opaque revision string.")
	}
	return v, nil
}

// ParseTopics parses the `topics` query parameter of the event stream: event
// types or prefixes ending in ".*", at most max of them.
func ParseTopics(values []string, max int) ([]string, error) {
	var topics []string
	seen := make(map[string]struct{})
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			topic := strings.TrimSpace(part)
			if topic == "" {
				continue
			}
			if len(topic) > 128 {
				return nil, topicsProblem("A topic is longer than 128 characters.")
			}
			if !validTopic(topic) {
				return nil, topicsProblem(fmt.Sprintf("%q is not an event type or a prefix ending in .*", topic))
			}
			if _, dup := seen[topic]; dup {
				continue
			}
			seen[topic] = struct{}{}
			topics = append(topics, topic)
		}
	}
	if len(topics) > max {
		return nil, topicsProblem(fmt.Sprintf("At most %d topics can be subscribed.", max))
	}
	return topics, nil
}

// validTopic implements the topics item pattern: a lower-case event type with
// optional ".*" prefix wildcard.
func validTopic(t string) bool {
	base, _ := strings.CutSuffix(t, ".*")
	if base == "" {
		return false
	}
	if base[0] < 'a' || base[0] > 'z' {
		return false
	}
	for i := 1; i < len(base); i++ {
		c := base[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return !strings.HasSuffix(base, ".")
}

// topicsProblem is the VALIDATION_FAILED error for a bad `topics` parameter.
func topicsProblem(message string) *problem.Error {
	return badRequest("query", "/topics", "INVALID", message)
}

// ParseSequence parses an event sequence (Sequence in the public schema): a
// decimal string of at most 20 digits.
func ParseSequence(raw string) (int64, bool) {
	if raw == "" || len(raw) > 20 {
		return 0, false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// IdempotencyKey returns the validated Idempotency-Key header, or "" when the
// request has none. A malformed value is VALIDATION_FAILED at
// /Idempotency-Key (header).
func IdempotencyKey(r *http.Request) (string, error) {
	v := r.Header.Get("Idempotency-Key")
	if v == "" {
		return "", nil
	}
	if len(v) < 16 || len(v) > 128 {
		return "", badRequest("header", "/Idempotency-Key", "INVALID",
			"An idempotency key is 16 to 128 characters long.")
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == ':' || c == '-') {
			return "", badRequest("header", "/Idempotency-Key", "INVALID",
				"The idempotency key contains characters that are not allowed.")
		}
	}
	return v, nil
}
