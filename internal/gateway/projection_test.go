// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestParseFields(t *testing.T) {
	if p, err := gateway.ParseFields("", 4); err != nil || p != nil {
		t.Fatalf("empty fields = (%v, %v)", p, err)
	}
	p, err := gateway.ParseFields("/name, /status/state", 4)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if got := p.Pointers(); !reflect.DeepEqual(got, []string{"/name", "/status/state"}) {
		t.Fatalf("pointers = %v", got)
	}

	bad := []string{
		"name",                 // no leading slash
		"/items/0",             // index segment
		"/a~2b",                // invalid escape
		"/a,/b,/c,/d,/e",       // more than the limit
		"/" + repeat("x", 257), // longer than 256
	}
	for _, raw := range bad {
		if _, err := gateway.ParseFields(raw, 4); err == nil {
			t.Errorf("ParseFields(%q) was accepted", raw)
		} else if !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("ParseFields(%q) error = %v, want VALIDATION_FAILED", raw, err)
		}
	}

	// Duplicates are collapsed, "~1" and "~0" unescape.
	p, err = gateway.ParseFields("/a~1b,/a~1b,/c~0d", 4)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if got := len(p.Pointers()); got != 2 {
		t.Fatalf("pointers = %v", p.Pointers())
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestProjectionApply(t *testing.T) {
	doc := map[string]any{
		"user_id":  "usr_1",
		"revision": "42",
		"name":     "alice",
		"roles":    []any{"admin", "ops"},
		"status": map[string]any{
			"state":   "active",
			"mfa":     true,
			"created": "2026-11-01T00:00:00Z",
		},
	}
	p, err := gateway.ParseFields("/name,/status/state,/roles", 4)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	got, err := p.Apply(doc)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := map[string]any{
		"user_id":  "usr_1",
		"revision": "42",
		"name":     "alice",
		"roles":    []any{"admin", "ops"},
		"status":   map[string]any{"state": "active"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projected = %#v, want %#v", got, want)
	}

	// The source document is not modified.
	if _, ok := doc["status"].(map[string]any)["mfa"]; !ok {
		t.Fatal("Apply modified the source document")
	}

	// An unknown pointer is a field-level validation error.
	unknown, err := gateway.ParseFields("/nope", 4)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if _, err := unknown.Apply(doc); err == nil {
		t.Fatal("unknown pointer was accepted")
	} else {
		var pe *problem.Error
		if !errors.As(err, &pe) || pe.Code != problem.ValidationFailed {
			t.Fatalf("error = %v", err)
		}
		if len(pe.Violations) != 1 || pe.Violations[0].Pointer != "/fields" {
			t.Fatalf("violations = %+v", pe.Violations)
		}
	}

	// A pointer through a non-object is rejected too.
	throughArray, err := gateway.ParseFields("/roles/x", 4)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if _, err := throughArray.Apply(doc); err == nil {
		t.Fatal("pointer through an array was accepted")
	}

	// An empty pointer selects the whole document.
	all, err := gateway.ParseFields(",", 4)
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	if out, err := all.Apply(doc); err != nil || len(out) != len(doc) {
		t.Fatalf("whole document projection = (%v, %v)", out, err)
	}
}

func TestProjectionNilIsIdentity(t *testing.T) {
	var p *gateway.Projection
	doc := map[string]any{"a": 1}
	got, err := p.Apply(doc)
	if err != nil || len(got) != 1 {
		t.Fatalf("nil projection = (%v, %v)", got, err)
	}
}
