// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/gateway"
)

func TestListQueryDefaultsAndValidation(t *testing.T) {
	g := testGateway(t)

	lq, err := g.ListQuery(newRequest(http.MethodGet, "/api/v1/things", ""))
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if lq.Limit != 5 || lq.Cursor != "" || lq.SinceRevision != "" || lq.Fields != nil {
		t.Fatalf("defaults = %+v", lq)
	}

	lq, err = g.ListQuery(newRequest(http.MethodGet,
		"/api/v1/things?fields=/name&since_revision=42&cursor=abc&limit=7", ""))
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if lq.Limit != 7 || lq.Cursor != "abc" || lq.SinceRevision != "42" || lq.Fields == nil {
		t.Fatalf("parsed = %+v", lq)
	}

	bad := []string{
		"?limit=0",
		"?limit=11",
		"?limit=abc",
		"?since_revision=bad%20revision",
		"?cursor=" + repeat("c", 513),
		"?fields=/a/0",
	}
	for _, query := range bad {
		if _, err := g.ListQuery(newRequest(http.MethodGet, "/api/v1/things"+query, "")); err == nil {
			t.Errorf("ListQuery(%q) was accepted", query)
		}
	}
}

func TestParseTopics(t *testing.T) {
	got, err := gateway.ParseTopics([]string{"resource.changed, operation.updated"}, 4)
	if err != nil {
		t.Fatalf("ParseTopics: %v", err)
	}
	if len(got) != 2 || got[0] != "resource.changed" || got[1] != "operation.updated" {
		t.Fatalf("topics = %v", got)
	}

	got, err = gateway.ParseTopics([]string{"resource.*", "resource.*"}, 4)
	if err != nil || len(got) != 1 {
		t.Fatalf("prefix topics = (%v, %v)", got, err)
	}

	if _, err := gateway.ParseTopics([]string{"Resource.Cha"}, 4); err == nil {
		t.Fatal("uppercase topic was accepted")
	}
	if _, err := gateway.ParseTopics([]string{"a,b,c"}, 2); err == nil {
		t.Fatal("too many topics were accepted")
	}
	if _, err := gateway.ParseTopics([]string{"a.*.b"}, 4); err == nil {
		t.Fatal("misplaced wildcard was accepted")
	}
	if got, err := gateway.ParseTopics([]string{""}, 4); err != nil || len(got) != 0 {
		t.Fatalf("empty topics = (%v, %v)", got, err)
	}
}

func TestParseSequence(t *testing.T) {
	cases := map[string]struct {
		want int64
		ok   bool
	}{
		"0":                     {0, true},
		"42":                    {42, true},
		"18446744073709551615":  {0, false}, // overflows int64
		"abc":                   {0, false},
		"-1":                    {0, false},
		"000000000000000000001": {0, false},
	}
	for raw, tc := range cases {
		got, ok := gateway.ParseSequence(raw)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("ParseSequence(%q) = (%d, %v), want (%d, %v)", raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIdempotencyKey(t *testing.T) {
	req := newRequest(http.MethodPost, "/api/v1/things", "{}")
	if key, err := gateway.IdempotencyKey(req); err != nil || key != "" {
		t.Fatalf("absent key = (%q, %v)", key, err)
	}
	req.Header.Set("Idempotency-Key", "0123456789abcdef")
	if key, err := gateway.IdempotencyKey(req); err != nil || key != "0123456789abcdef" {
		t.Fatalf("key = (%q, %v)", key, err)
	}
	for _, bad := range []string{"short", repeat("k", 129), "has spaces here"} {
		req.Header.Set("Idempotency-Key", bad)
		if _, err := gateway.IdempotencyKey(req); err == nil {
			t.Errorf("IdempotencyKey(%q) was accepted", bad)
		}
	}
}

func TestExpectedRevisionQuery(t *testing.T) {
	req := newRequest(http.MethodDelete, "/api/v1/things/1", "")
	if _, err := gateway.ExpectedRevisionQuery(req); err == nil {
		t.Fatal("missing expected_revision was accepted")
	}
	req = newRequest(http.MethodDelete, "/api/v1/things/1?expected_revision=42", "")
	rev, err := gateway.ExpectedRevisionQuery(req)
	if err != nil || rev != "42" {
		t.Fatalf("revision = (%q, %v)", rev, err)
	}
}
