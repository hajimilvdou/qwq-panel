// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestToolKey(t *testing.T) {
	h := &handlers{ids: ids.New(func() time.Time { return time.Unix(0, 0) })}

	r := httptest.NewRequest("POST", "/api/v1/agent/execute", nil)
	r.Header.Set("Idempotency-Key", "abcdefghijklmnop")
	key, err := h.toolKey(r, "execute")
	if err != nil || key != "abcdefghijklmnop" {
		t.Fatalf("explicit key = %q, %v", key, err)
	}

	// A tool-call ID is stable: two calls of one tool invocation agree.
	first := httptest.NewRequest("POST", "/api/v1/agent/execute", nil)
	first.Header.Set("X-Tool-Call-Id", "call-1")
	k1, err := h.toolKey(first, "execute")
	if err != nil {
		t.Fatalf("tool call id: %v", err)
	}
	second := httptest.NewRequest("POST", "/api/v1/agent/execute", nil)
	second.Header.Set("X-Tool-Call-Id", "call-1")
	k2, err := h.toolKey(second, "execute")
	if err != nil {
		t.Fatalf("tool call id: %v", err)
	}
	if k1 != k2 {
		t.Fatalf("keys differ: %q vs %q", k1, k2)
	}
	if !idempotencyKeyRe.MatchString(k1) {
		t.Fatalf("derived key %q does not match the schema", k1)
	}
	// A different tool or a different call id gives a different key.
	other := httptest.NewRequest("POST", "/api/v1/agent/cancel", nil)
	other.Header.Set("X-Tool-Call-Id", "call-2")
	k3, err := h.toolKey(other, "cancel")
	if err != nil {
		t.Fatalf("cancel key: %v", err)
	}
	if k3 == k1 || !idempotencyKeyRe.MatchString(k3) {
		t.Fatalf("cancel key = %q", k3)
	}

	// The request ID is the third source.
	withRequest := httptest.NewRequest("POST", "/api/v1/agent/execute", nil)
	withRequest.Header.Set("X-Request-Id", "req_0123456789abcdef")
	k4, err := h.toolKey(withRequest, "execute")
	if err != nil || k4 != "execute:req_0123456789abcdef" {
		t.Fatalf("request id key = %q, %v", k4, err)
	}

	// Without any identifier a fresh, well-formed key is minted.
	bare := httptest.NewRequest("POST", "/api/v1/agent/execute", nil)
	k5, err := h.toolKey(bare, "execute")
	if err != nil || !idempotencyKeyRe.MatchString(k5) {
		t.Fatalf("minted key = %q, %v", k5, err)
	}
	if k5 == k4 {
		t.Fatal("the minted key repeats")
	}

	// A malformed explicit key is a validation problem, not a silent rewrite.
	bad := httptest.NewRequest("POST", "/api/v1/agent/execute", nil)
	bad.Header.Set("Idempotency-Key", "short")
	if _, err := h.toolKey(bad, "execute"); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("malformed key: %s", errString(err))
	}
}

func TestOutcomeOf(t *testing.T) {
	op := &operations.Operation{
		ID: "op_1", Action: actionScan, Status: operations.Succeeded, Revision: "9",
	}
	body, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := outcomeOf(&operations.Response{Body: body, OperationID: "op_1"})
	if err != nil {
		t.Fatalf("replay of an operation: %v", err)
	}
	if out.OperationID != "op_1" || out.Status != operations.Succeeded {
		t.Fatalf("outcome = %+v", out)
	}

	read := &operations.Outcome{
		Action: actionReport, Status: operations.Succeeded, Result: json.RawMessage(`{"ok":true}`),
	}
	body, err = json.Marshal(read)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err = outcomeOf(&operations.Response{Body: body})
	if err != nil {
		t.Fatalf("replay of a read outcome: %v", err)
	}
	if out.OperationID != "" || out.Action != actionReport {
		t.Fatalf("outcome = %+v", out)
	}

	if _, err := outcomeOf(nil); err == nil {
		t.Fatal("outcomeOf(nil) succeeded")
	}
	if _, err := outcomeOf(&operations.Response{Body: json.RawMessage(`"nope"`)}); err == nil {
		t.Fatal("outcomeOf(garbage) succeeded")
	}
}

func TestOutcomeBodyDropsEmptyRevision(t *testing.T) {
	body, err := outcomeBody(&operations.Outcome{
		Action: actionReport, Status: operations.Succeeded, Revision: "",
	})
	if err != nil {
		t.Fatalf("outcomeBody: %v", err)
	}
	if _, ok := body["revision"]; ok {
		t.Fatalf("revision = %v, want it dropped", body["revision"])
	}
	body, err = outcomeBody(&operations.Outcome{
		OperationID: "op_1", Action: actionScan, Status: operations.Succeeded, Revision: "4",
	})
	if err != nil {
		t.Fatalf("outcomeBody: %v", err)
	}
	if body["revision"] != "4" {
		t.Fatalf("revision = %v", body["revision"])
	}
}

func TestPlanBodyHasArrays(t *testing.T) {
	body, err := planBody(&operations.Plan{ID: "pln_1", Action: actionScan, Revision: "3"})
	if err != nil {
		t.Fatalf("planBody: %v", err)
	}
	for _, key := range []string{"changes", "violations", "warnings", "preconditions"} {
		arr, ok := body[key].([]any)
		if !ok || len(arr) != 0 {
			t.Fatalf("%s = %v, want []", key, body[key])
		}
	}
}

func TestCheckFields(t *testing.T) {
	good := [][]string{
		nil,
		{""},
		{"/username"},
		{"/a", "/b/c", "/d~1e", "/f~0g"},
	}
	for _, fields := range good {
		if _, err := checkFields(fields); err != nil {
			t.Fatalf("%v: %s", fields, errString(err))
		}
	}
	bad := [][]string{
		{"username"},
		{"/a/0"},
		{"/" + strings.Repeat("x", 300)},
	}
	for _, fields := range bad {
		if _, err := checkFields(fields); err == nil {
			t.Fatalf("%v was accepted", fields)
		}
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = "/f"
	}
	if _, err := checkFields(many); err == nil {
		t.Fatal("33 fields were accepted")
	}
	// Duplicates collapse instead of counting twice.
	got, err := checkFields([]string{"/a", "/a"})
	if err != nil || len(got) != 1 {
		t.Fatalf("duplicates: %v, %v", got, err)
	}
}

func TestLookupAndProject(t *testing.T) {
	doc := map[string]any{
		"user_id":  "usr_1",
		"revision": "5",
		"profile":  map[string]any{"display_name": "Alice", "role": "admin"},
		"tags":     []any{"a", "b"},
	}
	if v, ok := lookupPointer(doc, "/profile/display_name"); !ok || v != "Alice" {
		t.Fatalf("lookup = %v, %v", v, ok)
	}
	if _, ok := lookupPointer(doc, "/profile/nope"); ok {
		t.Fatal("missing pointer found")
	}
	if _, ok := lookupPointer(doc, "/tags/0"); ok {
		t.Fatal("an array was traversed")
	}
	projected := projectItem(doc, []string{"/profile/display_name"})
	if got := obj(t, projected["profile"])["display_name"]; got != "Alice" {
		t.Fatalf("projected = %v", projected)
	}
	if projected["user_id"] != "usr_1" || projected["revision"] != "5" {
		t.Fatalf("identifiers were dropped: %v", projected)
	}
	if _, ok := projected["tags"]; ok {
		t.Fatalf("unselected member survived: %v", projected)
	}
}

func TestCapItems(t *testing.T) {
	h := &handlers{}
	items := make([]map[string]any, 120)
	for i := range items {
		items[i] = map[string]any{"operation_id": "op_" + strings.Repeat("x", 6)}
	}
	resp := &readResponse{Subject: "operations", Revision: "1", Items: &items, NextCursor: "abc"}
	h.capItems(resp, ReadItemsMax)
	if len(*resp.Items) != ReadItemsMax {
		t.Fatalf("items = %d, want %d", len(*resp.Items), ReadItemsMax)
	}
	if resp.Truncated == nil || resp.Truncated.Reason != "max_items" || resp.Truncated.Returned != ReadItemsMax {
		t.Fatalf("truncated = %+v", resp.Truncated)
	}
	if resp.NextCursor != "" {
		t.Fatalf("next_cursor = %q, want it dropped", resp.NextCursor)
	}
}

func TestFitItemsByteCap(t *testing.T) {
	h := &handlers{}
	items := make([]map[string]any, 4)
	for i := range items {
		items[i] = map[string]any{"blob": strings.Repeat("y", 20000), "operation_id": "op_x"}
	}
	total := len(items)
	resp := &readResponse{Subject: "operations", Revision: "1", Items: &items, NextCursor: "abc"}
	h.fitItems(resp)
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(raw) > ReadResponseBytes {
		t.Fatalf("response is %d bytes, cap is %d", len(raw), ReadResponseBytes)
	}
	if resp.Truncated == nil || resp.Truncated.Reason != "max_bytes" {
		t.Fatalf("truncated = %+v", resp.Truncated)
	}
	if resp.NextCursor != "" {
		t.Fatalf("next_cursor = %q, want it dropped", resp.NextCursor)
	}
	if len(*resp.Items) >= total {
		t.Fatalf("items = %d, want fewer than %d", len(*resp.Items), total)
	}
}

func TestFitValuesByteCap(t *testing.T) {
	h := &handlers{}
	values := map[string]any{"": map[string]any{"blob": strings.Repeat("z", 40000)}}
	resp := &readResponse{Subject: "operations/op_1", Revision: "1", Values: &values}
	h.fitValues(resp)
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(raw) > ReadResponseBytes {
		t.Fatalf("response is %d bytes, cap is %d", len(raw), ReadResponseBytes)
	}
	if resp.Truncated == nil || resp.Truncated.Reason != "max_bytes" || resp.Truncated.Hint == "" {
		t.Fatalf("truncated = %+v", resp.Truncated)
	}
	if len(*resp.Values) != 0 {
		t.Fatalf("values = %v, want none", *resp.Values)
	}
}

func TestWaitLimiter(t *testing.T) {
	l := newWaitLimiter(2)
	for i := 0; i < 2; i++ {
		if !l.acquire("a") {
			t.Fatalf("acquire %d failed under the limit", i)
		}
	}
	if l.acquire("a") {
		t.Fatal("acquire succeeded over the limit")
	}
	if l.count("a") != 2 {
		t.Fatalf("count = %d", l.count("a"))
	}
	// Another key has its own budget.
	if !l.acquire("b") {
		t.Fatal("a second key was refused")
	}
	l.release("a")
	l.release("a")
	if l.count("a") != 0 {
		t.Fatalf("count = %d, want the key to be pruned", l.count("a"))
	}
	if _, ok := l.active["a"]; ok {
		t.Fatal("the idle key is still in the map")
	}
	// Releasing without acquiring must not go negative.
	l.release("a")
	if l.count("a") != 0 {
		t.Fatalf("count = %d", l.count("a"))
	}
}

func TestCheckSubjectKinds(t *testing.T) {
	cases := []struct {
		subject string
		head    string
		id      string
		ok      bool
	}{
		{"users", "users", "", true},
		{"users/usr_01J9Z3", "users", "usr_01J9Z3", true},
		{"operations", "operations", "", true},
		{"nodes/local/plugins/com.example.monitor/instances/default/resources/alerts/cpu",
			"nodes", "local/plugins/com.example.monitor/instances/default/resources/alerts/cpu", true},
		{"Users/alice", "", "", false},
		{"", "", "", false},
		{"users/", "", "", false},
		{"users/a b", "", "", false},
	}
	for _, tc := range cases {
		head, id, err := checkSubject(tc.subject)
		if tc.ok != (err == nil) {
			t.Fatalf("%q: err = %v, want ok=%v", tc.subject, errString(err), tc.ok)
		}
		if tc.ok && (head != tc.head || id != tc.id) {
			t.Fatalf("%q: head = %q, id = %q", tc.subject, head, id)
		}
	}
}
