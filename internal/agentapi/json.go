// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// maxPointerLen is JsonPointer.maxLength in the public schema.
const maxPointerLen = 256

// checkFields validates the `fields` member of a read request and returns it
// without duplicates. Every pointer is an RFC 6901 pointer into an object; an
// array is selected whole, exactly like the `fields` parameter of the REST
// routes (index segments are rejected).
func checkFields(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	if len(fields) > 32 {
		return nil, invalid("/fields", "TOO_MANY", "At most 32 fields can be selected.")
	}
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for i, pointer := range fields {
		at := fmt.Sprintf("/fields/%d", i)
		if len(pointer) > maxPointerLen {
			return nil, wrongFormat(at, "A field pointer is longer than 256 characters.")
		}
		if !pointerRe.MatchString(pointer) {
			return nil, wrongFormat(at, "A field pointer is an RFC 6901 JSON Pointer such as /display_name.")
		}
		if hasIndexSegment(pointer) {
			return nil, wrongFormat(at, "Index segments are not supported; select the whole array.")
		}
		if _, dup := seen[pointer]; dup {
			continue
		}
		seen[pointer] = struct{}{}
		out = append(out, pointer)
	}
	return out, nil
}

// hasIndexSegment reports whether the pointer addresses an array element.
func hasIndexSegment(pointer string) bool {
	if pointer == "" {
		return false
	}
	for _, seg := range strings.Split(pointer[1:], "/") {
		if seg == "" {
			continue
		}
		digits := true
		for i := 0; i < len(seg); i++ {
			if seg[i] < '0' || seg[i] > '9' {
				digits = false
				break
			}
		}
		if digits {
			return true
		}
	}
	return false
}

// unescapeSegment decodes the ~1 and ~0 escapes of one pointer segment.
func unescapeSegment(seg string) (string, bool) {
	if !strings.Contains(seg, "~") {
		return seg, true
	}
	var b strings.Builder
	b.Grow(len(seg))
	for i := 0; i < len(seg); i++ {
		if seg[i] != '~' {
			b.WriteByte(seg[i])
			continue
		}
		if i+1 >= len(seg) {
			return "", false
		}
		switch seg[i+1] {
		case '0':
			b.WriteByte('~')
		case '1':
			b.WriteByte('/')
		default:
			return "", false
		}
		i++
	}
	return b.String(), true
}

// lookupPointer resolves pointer against doc and reports whether it exists.
func lookupPointer(doc map[string]any, pointer string) (any, bool) {
	if pointer == "" {
		return doc, true
	}
	cur := doc
	segs := strings.Split(pointer[1:], "/")
	for i, seg := range segs {
		key, ok := unescapeSegment(seg)
		if !ok {
			return nil, false
		}
		value, ok := cur[key]
		if !ok {
			return nil, false
		}
		if i == len(segs)-1 {
			return value, true
		}
		next, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return nil, false
}

// projectItem returns doc limited to the selected pointers. The identifier and
// revision members the REST `fields` parameter always keeps (top-level `id`,
// any `*_id` and `revision`) stay in the result so a client can merge it into
// its cache.
func projectItem(doc map[string]any, fields []string) map[string]any {
	if len(fields) == 0 || len(doc) == 0 {
		return doc
	}
	out := make(map[string]any, len(fields)+4)
	for _, pointer := range fields {
		if pointer == "" {
			return doc
		}
		value, ok := lookupPointer(doc, pointer)
		if !ok {
			continue
		}
		setPointer(out, pointer, value)
	}
	for key, value := range doc {
		if key == "revision" || key == "id" || strings.HasSuffix(key, "_id") {
			out[key] = value
		}
	}
	return out
}

// setPointer writes value at pointer inside dst, creating intermediate
// objects. Pointer validation guarantees object segments only.
func setPointer(dst map[string]any, pointer string, value any) {
	if pointer == "" {
		return
	}
	segs := strings.Split(pointer[1:], "/")
	cur := dst
	for i, seg := range segs {
		key, ok := unescapeSegment(seg)
		if !ok {
			return
		}
		if i == len(segs)-1 {
			cur[key] = value
			return
		}
		next, ok := cur[key].(map[string]any)
		if !ok {
			next = make(map[string]any, 1)
			cur[key] = next
		}
		cur = next
	}
}

// sortedKeys returns the keys of m in a deterministic order.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// payloadBytes is the encoded size of one response member.
func payloadBytes(v any) int {
	raw, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(raw)
}

// fitValues enforces agent_read_response_bytes on a single-resource answer. It
// drops projected members from the end (sorted order) until the response
// fits and then reports the cap, so the caller knows the answer is partial.
func (h *handlers) fitValues(resp *readResponse) {
	if resp.Values == nil {
		return
	}
	for {
		if fits(resp) {
			return
		}
		keys := sortedKeys(*resp.Values)
		if len(keys) == 0 {
			resp.Truncated = &readTruncated{
				Reason: "max_bytes",
				Hint:   "The resource is larger than one response; request narrower JSON Pointers.",
			}
			return
		}
		delete(*resp.Values, keys[len(keys)-1])
		resp.Truncated = &readTruncated{
			Reason:   "max_bytes",
			Returned: payloadBytes(*resp.Values),
			Hint:     "The resource is larger than one response; request narrower JSON Pointers.",
		}
	}
}

// fitItems enforces agent_read_response_bytes on a collection answer, keeping
// the first items. When an item is dropped the page cursor is dropped too: the
// cursor of the service points past the last fetched item, so returning it
// would skip the item that did not fit. The hint tells the caller to retry the
// same cursor with a smaller limit.
func (h *handlers) fitItems(resp *readResponse) {
	if resp.Items == nil {
		return
	}
	for {
		if fits(resp) {
			return
		}
		items := *resp.Items
		if len(items) == 0 {
			resp.Truncated = &readTruncated{
				Reason: "max_bytes",
				Hint:   "The items do not fit one response; request fewer fields.",
			}
			return
		}
		*resp.Items = items[:len(items)-1]
		resp.NextCursor = ""
		resp.Truncated = &readTruncated{
			Reason:   "max_bytes",
			Returned: len(*resp.Items),
			Hint:     "The items do not fit one response; retry with the same cursor and a smaller limit.",
		}
	}
}

// fits reports whether the encoded response stays inside the byte cap.
func fits(resp *readResponse) bool {
	raw, err := json.Marshal(resp)
	return err == nil && len(raw) <= ReadResponseBytes
}

// capItems marks a collection that the host cut at agent_read_items_max. The
// services already bound a page to the requested limit, so this is a safety
// net; it keeps `truncated` honest if a service ever returns more.
func (h *handlers) capItems(resp *readResponse, max int) {
	if resp.Items == nil {
		return
	}
	items := *resp.Items
	if len(items) <= max {
		return
	}
	*resp.Items = items[:max]
	resp.NextCursor = ""
	resp.Truncated = &readTruncated{
		Reason:   "max_items",
		Returned: max,
		Hint:     "At most 100 items are returned; request a smaller limit or narrow fields.",
	}
}

// planBody renders a plan as the public Plan schema: nil slices become empty
// arrays so every `type: array` member is present.
func planBody(plan *operations.Plan) (map[string]any, error) {
	body, err := jsonObject(plan)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"changes", "violations", "warnings", "preconditions"} {
		ensureArray(body, key)
	}
	return body, nil
}

// outcomeBody renders an operation outcome as the public OperationOutcome
// schema. The revision is dropped when the operation has no record (a plugin
// read action), because Revision has minLength 1.
func outcomeBody(out *operations.Outcome) (map[string]any, error) {
	body, err := jsonObject(out)
	if err != nil {
		return nil, err
	}
	if rev, ok := body["revision"].(string); ok && rev == "" {
		delete(body, "revision")
	}
	return body, nil
}

// outcomeOf extracts the OperationOutcome of a mutating call. It covers a
// fresh call (Outcome or Operation set) and an idempotent replay, whose stored
// body is one of the two JSON documents.
func outcomeOf(resp *operations.Response) (*operations.Outcome, error) {
	if resp == nil {
		return nil, problem.Wrap(errors.New("agentapi: empty operations response"))
	}
	if resp.Outcome != nil {
		return resp.Outcome, nil
	}
	if resp.Operation != nil {
		return resp.Operation.Outcome(), nil
	}
	var op operations.Operation
	if err := json.Unmarshal(resp.Body, &op); err == nil && op.ID != "" && op.Status.Valid() {
		return op.Outcome(), nil
	}
	var out operations.Outcome
	if err := json.Unmarshal(resp.Body, &out); err == nil && out.Status.Valid() {
		return &out, nil
	}
	return nil, problem.Wrap(fmt.Errorf("agentapi: unreadable response for operation %q", resp.OperationID))
}
