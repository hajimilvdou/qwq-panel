// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"fmt"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// maxPointerLen is the JsonPointer maxLength of the public schema.
const maxPointerLen = 256

// Projection is a validated `fields` selection: RFC 6901 JSON Pointers into a
// resource, at most fields_max of them.
type Projection struct {
	pointers []string
	whole    bool
}

// ParseFields parses the `fields` query parameter: comma-separated RFC 6901
// JSON Pointers relative to the resource. It returns (nil, nil) for an empty
// value, and a VALIDATION_FAILED problem at /fields for anything malformed.
//
// Pointers traverse objects only; index segments are rejected because an array
// is selected whole (openapi.yaml, Fields).
func ParseFields(raw string, max int) (*Projection, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	p := &Projection{}
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		ptr := strings.TrimSpace(part)
		if ptr == "" {
			p.whole = true
			continue
		}
		if len(ptr) > maxPointerLen {
			return nil, fieldsProblem("A field pointer is longer than 256 characters.")
		}
		if !strings.HasPrefix(ptr, "/") {
			return nil, fieldsProblem("Field pointers must start with /.")
		}
		for _, seg := range strings.Split(ptr[1:], "/") {
			key, ok := unescapePointer(seg)
			if !ok {
				return nil, fieldsProblem("A field pointer has an invalid ~ escape.")
			}
			if isIndexSegment(key) {
				return nil, fieldsProblem("Index segments are not supported; select the whole array.")
			}
		}
		if _, dup := seen[ptr]; dup {
			continue
		}
		seen[ptr] = struct{}{}
		p.pointers = append(p.pointers, ptr)
	}
	if len(p.pointers) > max || (p.whole && len(p.pointers) > max-1) {
		return nil, fieldsProblem(fmt.Sprintf("At most %d fields can be selected.", max))
	}
	if len(p.pointers) == 0 && !p.whole {
		return nil, nil
	}
	return p, nil
}

// Pointers returns the selected pointers (sorted as given).
func (p *Projection) Pointers() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.pointers...)
}

// Apply projects doc. It keeps the original nesting and the selected members,
// plus the identifier and revision members the Fields parameter always keeps
// (top-level `id`, any `*_id` and `revision`), so a client can merge the result
// into its cache. An unknown pointer is a VALIDATION_FAILED problem at
// /fields.
func (p *Projection) Apply(doc map[string]any) (map[string]any, error) {
	if p == nil || p.whole {
		return doc, nil
	}
	out := make(map[string]any, len(p.pointers)+4)
	for _, ptr := range p.pointers {
		segs := strings.Split(ptr[1:], "/")
		cur := doc
		for i, rawSeg := range segs {
			key, _ := unescapePointer(rawSeg)
			value, ok := cur[key]
			if !ok {
				return nil, fieldsProblem(fmt.Sprintf("Unknown field pointer %q.", ptr))
			}
			if i == len(segs)-1 {
				objectPath(out, segs[:i])[key] = value
				break
			}
			next, ok := value.(map[string]any)
			if !ok {
				return nil, fieldsProblem(fmt.Sprintf("Field pointer %q does not address an object.", ptr))
			}
			cur = next
		}
	}
	for key, value := range doc {
		if key == "revision" || key == "id" || strings.HasSuffix(key, "_id") {
			out[key] = value
		}
	}
	return out, nil
}

// objectPath returns the object at the given pointer segments inside dst,
// creating intermediate objects as needed.
func objectPath(dst map[string]any, path []string) map[string]any {
	cur := dst
	for _, rawSeg := range path {
		key, _ := unescapePointer(rawSeg)
		next, ok := cur[key].(map[string]any)
		if !ok {
			next = make(map[string]any, 1)
			cur[key] = next
		}
		cur = next
	}
	return cur
}

// isIndexSegment reports whether s is an array index, which the public Fields
// parameter rejects.
func isIndexSegment(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// fieldsProblem is the VALIDATION_FAILED error for a bad `fields` parameter.
func fieldsProblem(message string) *problem.Error {
	return badRequest("query", "/fields", "INVALID_POINTER", message)
}
