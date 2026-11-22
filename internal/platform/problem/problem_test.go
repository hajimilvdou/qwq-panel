// SPDX-License-Identifier: AGPL-3.0-only

package problem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestCodesMatchOpenAPI keeps the code table in sync with ProblemCode in the
// public OpenAPI document: same codes, same HTTP status, same retryability.
func TestCodesMatchOpenAPI(t *testing.T) {
	doc, err := os.ReadFile("../../../api/public/v1/openapi.yaml")
	if err != nil {
		t.Skipf("openapi.yaml not available: %v", err)
	}
	s := string(doc)
	i := strings.Index(s, "\n    ProblemCode:\n")
	if i < 0 {
		t.Fatal("ProblemCode schema not found")
	}
	s = s[i:]
	if j := strings.Index(s[1:], "\n    "+"FieldViolation:"); j > 0 {
		s = s[:j+1]
	}
	row := regexp.MustCompile("(?m)^\\s*\\| `([A-Z_]+)` \\| (\\d{3}) \\| (yes|no|per plugin) \\|")
	table := map[Code]codeInfo{}
	for _, m := range row.FindAllStringSubmatch(s, -1) {
		var st int
		fmt.Sscan(m[2], &st)
		table[Code(m[1])] = codeInfo{status: st, retryable: m[3] == "yes"}
	}
	enum := map[Code]bool{}
	if k := strings.Index(s, "\n      enum:\n"); k >= 0 {
		for _, line := range strings.Split(s[k+len("\n      enum:\n"):], "\n") {
			v, ok := strings.CutPrefix(line, "        - ")
			if !ok {
				break
			}
			enum[Code(strings.TrimSpace(v))] = true
		}
	}
	if len(table) == 0 || len(enum) == 0 {
		t.Fatalf("parsed %d table rows and %d enum values", len(table), len(enum))
	}
	for c, info := range codes {
		if !enum[c] {
			t.Errorf("%s missing from ProblemCode enum", c)
		}
		ti, ok := table[c]
		if !ok {
			t.Errorf("%s missing from ProblemCode table", c)
			continue
		}
		if ti.status != info.status {
			t.Errorf("%s: status %d here, %d in OpenAPI", c, info.status, ti.status)
		}
		if c != PluginError && ti.retryable != info.retryable {
			t.Errorf("%s: retryable %v here, %v in OpenAPI", c, info.retryable, ti.retryable)
		}
	}
	for c := range enum {
		if !c.Known() {
			t.Errorf("OpenAPI code %s not defined here", c)
		}
	}
}

func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	err := &Error{Code: RateLimited, Detail: "slow down", RetryAfterSec: 7, Limit: &Limit{Name: "login_per_minute", Max: 5}}
	Write(rec, fmt.Errorf("wrapped: %w", err), "req_1", "/api/v1/sessions")

	if rec.Code != 429 || rec.Header().Get("Content-Type") != "application/problem+json" ||
		rec.Header().Get("Retry-After") != "7" || rec.Header().Get("X-Request-Id") != "req_1" {
		t.Fatalf("status %d headers %v", rec.Code, rec.Header())
	}
	var p map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p["type"] != "urn:qwq:problem:RATE_LIMITED" || p["code"] != "RATE_LIMITED" || p["retryable"] != true ||
		p["request_id"] != "req_1" || p["instance"] != "/api/v1/sessions" || p["retry_after"].(float64) != 7 {
		t.Fatalf("problem %v", p)
	}
}

func TestInternalHidesCause(t *testing.T) {
	rec := httptest.NewRecorder()
	p := Write(rec, errors.New("sql: no such table: users at /var/lib/qwq/qwq.db"), "req_2", "")
	if p.Code != Internal || rec.Code != 500 || strings.Contains(rec.Body.String(), "sql") || strings.Contains(rec.Body.String(), "/var/lib") {
		t.Fatalf("leaked cause: %s", rec.Body.String())
	}
}

func TestUnknownCodeBecomesInternal(t *testing.T) {
	p := (&Error{Code: "TYPO", Detail: "secret detail"}).Problem("r", "")
	if p.Code != Internal || p.Status != 500 || strings.Contains(p.Detail, "secret") {
		t.Fatalf("%+v", p)
	}
}

func TestDeadlineIsTimeout(t *testing.T) {
	if From(fmt.Errorf("call: %w", context.DeadlineExceeded)).Code != Timeout {
		t.Fatal("deadline not mapped to TIMEOUT")
	}
}

func TestViolationsAndPreconditions(t *testing.T) {
	vs := make([]Violation, MaxViolations+5)
	for i := range vs {
		vs[i] = Violation{In: "body", Pointer: fmt.Sprintf("/x/%d", i), Code: "REQUIRED", Message: strings.Repeat("长", 400)}
	}
	e := Validation(vs...)
	e.FailedPreconditions = []FailedPrecondition{{Subject: "nodes/local", ExpectedRevision: "3", CurrentRevision: "5"}, {Subject: "users/usr_1", ExpectedRevision: "9"}}
	p := e.Problem("r", "")
	if len(p.Violations) != MaxViolations || !p.ViolationsTruncated {
		t.Fatalf("%d violations, truncated=%v", len(p.Violations), p.ViolationsTruncated)
	}
	if p.Violations[0].In != "" || len(p.Violations[0].Message) > maxMessage {
		t.Fatalf("violation not normalized: %+v", p.Violations[0])
	}
	b, _ := json.Marshal(p)
	if !strings.Contains(string(b), `"current_revision":"5"`) || !strings.Contains(string(b), `"current_revision":null`) {
		t.Fatalf("preconditions: %s", b)
	}
}

func TestFromPlugin(t *testing.T) {
	if e := FromPlugin("PRECONDITION_FAILED", "changed", false, nil); e.Code != PreconditionFailed {
		t.Fatalf("%+v", e)
	}
	e := FromPlugin("PORT_IN_USE", "port 443 is in use", true, nil)
	p := e.Problem("r", "")
	if p.Code != PluginError || p.PluginCode != "PORT_IN_USE" || !p.Retryable || p.Status != 422 {
		t.Fatalf("%+v", p)
	}
}

func TestIsAndHasCode(t *testing.T) {
	err := fmt.Errorf("lookup: %w", New(NotFound, "no user %s", "usr_1"))
	if !errors.Is(err, Sentinel(NotFound)) || errors.Is(err, Sentinel(Internal)) || !HasCode(err, NotFound) {
		t.Fatal("matching by code failed")
	}
}
