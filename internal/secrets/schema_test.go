// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

const nestedSchema = `{
  "$defs": {
    "credential": {
      "type": "object",
      "properties": {
        "user": {"type": "string"},
        "password": {"type": "string", "writeOnly": true}
      }
    }
  },
  "type": "object",
  "properties": {
    "host": {"type": "string"},
    "auth": {"$ref": "#/$defs/credential"},
    "extra": {"type": "object", "additionalProperties": {"type": "string", "x-secret": true}},
    "servers": {"type": "array", "items": {"type": "object", "properties": {"token": {"type": "string", "x-secret": true}}}},
    "pair": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "string", "writeOnly": true}]}
  }
}`

const nestedConfig = `{
  "host": "example.com",
  "auth": {"user": "alice", "password": "p@ss"},
  "extra": {"k1": "v1", "k2": "v2"},
  "servers": [{"token": "t1"}, {"token": "t2"}],
  "pair": ["left", "right"],
  "undeclared": "plain"
}`

var nestedPointers = []string{
	"/auth/password",
	"/extra/k1",
	"/extra/k2",
	"/pair/1",
	"/servers/0/token",
	"/servers/1/token",
}

var nestedValues = map[string]string{
	"/auth/password":   `"p@ss"`,
	"/extra/k1":        `"v1"`,
	"/extra/k2":        `"v2"`,
	"/pair/1":          `"right"`,
	"/servers/0/token": `"t1"`,
	"/servers/1/token": `"t2"`,
}

func TestExtractSecretsNested(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	opts := ExtractOptions{Owner: "plugins/core.xray/instances/inst_01jtest", Purpose: "plugin.config"}

	redacted, extracted, err := s.ExtractSecrets(ctx, []byte(nestedSchema), []byte(nestedConfig), opts)
	if err != nil {
		t.Fatalf("ExtractSecrets: %v", err)
	}
	if len(extracted) != len(nestedPointers) {
		t.Fatalf("extracted %d fields, want %d: %+v", len(extracted), len(nestedPointers), extracted)
	}
	for i, want := range nestedPointers {
		if extracted[i].Pointer != want {
			t.Fatalf("extracted[%d].Pointer = %q, want %q", i, extracted[i].Pointer, want)
		}
		if extracted[i].Purpose != opts.Purpose {
			t.Fatalf("extracted[%d].Purpose = %q, want %q", i, extracted[i].Purpose, opts.Purpose)
		}
	}

	for _, ex := range extracted {
		if !ex.Ref.Valid() {
			t.Fatalf("%s: %q is not a valid reference", ex.Pointer, ex.Ref)
		}
		secret, err := s.Reveal(ctx, ex.Ref, opts.Purpose)
		if err != nil {
			t.Fatalf("%s: Reveal: %v", ex.Pointer, err)
		}
		if got, want := string(secret.Bytes()), nestedValues[ex.Pointer]; got != want {
			t.Fatalf("%s: value %s, want %s", ex.Pointer, got, want)
		}
		var owner, purpose string
		if err := db.Reader().QueryRowContext(ctx, `SELECT owner, purpose FROM secrets WHERE id = ?`, string(ex.Ref)).Scan(&owner, &purpose); err != nil {
			t.Fatalf("%s: read row: %v", ex.Pointer, err)
		}
		if owner != opts.Owner || purpose != opts.Purpose {
			t.Fatalf("%s: stored owner/purpose %q/%q, want %q/%q", ex.Pointer, owner, purpose, opts.Owner, opts.Purpose)
		}
	}

	// The redacted document keeps the shape, replaces the values with
	// references, and contains no plaintext.
	text := string(redacted)
	for _, leak := range []string{"p@ss", `"v1"`, `"t1"`, `"right"`} {
		if strings.Contains(text, leak) {
			t.Fatalf("redacted config leaks %s: %s", leak, text)
		}
	}
	doc, err := decodeJSON(redacted)
	if err != nil {
		t.Fatalf("decode redacted: %v", err)
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("redacted config is not an object: %s", text)
	}
	if obj["host"] != "example.com" || obj["undeclared"] != "plain" {
		t.Fatalf("non-sensitive values changed: %s", text)
	}
	auth, ok := obj["auth"].(map[string]any)
	if !ok {
		t.Fatalf("auth is not an object: %s", text)
	}
	if auth["user"] != "alice" {
		t.Fatalf("auth.user changed: %v", auth["user"])
	}
	if _, ok := RefFromObject(auth["password"]); !ok {
		t.Fatalf("auth.password is not a reference: %#v", auth["password"])
	}

	// ResolveSecrets restores the original document.
	resolved, err := s.ResolveSecrets(ctx, redacted, opts.Owner, opts.Purpose)
	if err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	want, err := decodeJSON([]byte(nestedConfig))
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	got, err := decodeJSON(resolved)
	if err != nil {
		t.Fatalf("decode resolved: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved config = %s\nwant %s", resolved, nestedConfig)
	}
}

func TestExtractSecretsComposition(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	schema := `{
	  "allOf": [{"properties": {"a": {"x-secret": true}}}],
	  "oneOf": [{"properties": {"b": {"writeOnly": true}}}]
	}`
	_, extracted, err := s.ExtractSecrets(ctx, []byte(schema), []byte(`{"a": "1", "b": "2", "c": "3"}`),
		ExtractOptions{Owner: "config", Purpose: "config"})
	if err != nil {
		t.Fatalf("ExtractSecrets: %v", err)
	}
	if len(extracted) != 2 || extracted[0].Pointer != "/a" || extracted[1].Pointer != "/b" {
		t.Fatalf("extracted %+v, want /a and /b", extracted)
	}
}

func TestExtractSecretsRefCycle(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	schema := `{
	  "$defs": {
	    "node": {
	      "type": "object",
	      "properties": {
	        "name": {"type": "string"},
	        "secret": {"type": "string", "x-secret": true},
	        "children": {"type": "array", "items": {"$ref": "#/$defs/node"}}
	      }
	    }
	  },
	  "$ref": "#/$defs/node"
	}`
	config := `{"name": "root", "secret": "s0", "children": [{"name": "child", "secret": "s1", "children": []}]}`
	_, extracted, err := s.ExtractSecrets(ctx, []byte(schema), []byte(config), ExtractOptions{Owner: "config", Purpose: "config"})
	if err != nil {
		t.Fatalf("ExtractSecrets: %v", err)
	}
	want := []string{"/children/0/secret", "/secret"}
	if len(extracted) != len(want) {
		t.Fatalf("extracted %+v, want %v", extracted, want)
	}
	for i, p := range want {
		if extracted[i].Pointer != p {
			t.Fatalf("extracted[%d] = %q, want %q", i, extracted[i].Pointer, p)
		}
	}
}

func TestExtractSecretsWholeDocument(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	schema := `{"type": "object", "writeOnly": true}`
	config := `{"user": "alice", "password": "p@ss"}`

	redacted, extracted, err := s.ExtractSecrets(ctx, []byte(schema), []byte(config), ExtractOptions{Owner: "config", Purpose: "config"})
	if err != nil {
		t.Fatalf("ExtractSecrets: %v", err)
	}
	if len(extracted) != 1 || extracted[0].Pointer != "" {
		t.Fatalf("extracted %+v, want one root reference", extracted)
	}
	doc, err := decodeJSON(redacted)
	if err != nil {
		t.Fatalf("decode redacted: %v", err)
	}
	if _, ok := RefFromObject(doc); !ok {
		t.Fatalf("whole document was not replaced by a reference: %s", redacted)
	}
	resolved, err := s.ResolveSecrets(ctx, redacted, "config", "config")
	if err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	want, got := mustDecode(t, config), mustDecode(t, string(resolved))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved = %s, want %s", resolved, config)
	}
}

func TestExtractSecretsWithoutSecrets(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	schema := `{"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}}}`
	config := `{"host": "example.com", "port": 8443}`
	redacted, extracted, err := s.ExtractSecrets(ctx, []byte(schema), []byte(config), ExtractOptions{Owner: "config", Purpose: "config"})
	if err != nil {
		t.Fatalf("ExtractSecrets: %v", err)
	}
	if len(extracted) != 0 {
		t.Fatalf("extracted %+v, want none", extracted)
	}
	if want := mustDecode(t, config); !reflect.DeepEqual(mustDecode(t, string(redacted)), want) {
		t.Fatalf("redacted = %s, want the config unchanged", redacted)
	}
	var n int
	if err := db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("stored %d secrets for a config without sensitive fields", n)
	}
}

func TestExtractSecretsRejectsUnsupportedSchemas(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)

	depthSchema := `{"type": "number"}`
	depthConfig := `0`
	for range maxSchemaDepth + 2 {
		depthSchema = `{"type": "array", "items": ` + depthSchema + `}`
		depthConfig = `[` + depthConfig + `]`
	}

	cases := []struct {
		name    string
		schema  string
		config  string
		keyword string
	}{
		{"pattern properties", `{"patternProperties": {"^x": {"writeOnly": true}}}`, `{"x1": "v"}`, "patternProperties"},
		{"conditional", `{"if": {"properties": {"a": {"writeOnly": true}}}}`, `{"a": "v"}`, "if"},
		{"negation", `{"not": {"writeOnly": true}}`, `"v"`, "not"},
		{"dependent schemas", `{"dependentSchemas": {"a": {"writeOnly": true}}}`, `{"a": "v"}`, "dependentSchemas"},
		{"remote reference", `{"$ref": "https://example.com/schema.json"}`, `{}`, "$ref"},
		{"missing reference", `{"$ref": "#/$defs/nope"}`, `{}`, "$ref"},
		{"non-boolean writeOnly", `{"properties": {"a": {"writeOnly": "yes"}}}`, `{"a": "v"}`, "writeOnly"},
		{"bad items", `{"properties": {"a": {"items": []}}}`, `{"a": []}`, "items"},
		{"too deep", depthSchema, depthConfig, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := s.ExtractSecrets(ctx, []byte(tc.schema), []byte(tc.config), ExtractOptions{Owner: "config", Purpose: "config"})
			requireCode(t, err, problem.ValidationFailed)
			var se *SchemaError
			if !errors.As(err, &se) {
				t.Fatalf("error does not carry a SchemaError: %v", err)
			}
			if tc.keyword != "" && se.Keyword != tc.keyword {
				t.Fatalf("SchemaError keyword %q, want %q (%v)", se.Keyword, tc.keyword, se)
			}
		})
	}
}

func TestExtractSecretsRejectsBadJSON(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	_, _, err := s.ExtractSecrets(ctx, []byte(`{"type":`), []byte(`{}`), ExtractOptions{Owner: "config", Purpose: "config"})
	requireCode(t, err, problem.ValidationFailed)
	_, _, err = s.ExtractSecrets(ctx, []byte(`{}`), []byte(`{} {}`), ExtractOptions{Owner: "config", Purpose: "config"})
	requireCode(t, err, problem.ValidationFailed)
	_, _, err = s.ExtractSecrets(ctx, []byte(`{}`), []byte(`{}`), ExtractOptions{Owner: "", Purpose: "config"})
	requireCode(t, err, problem.ValidationFailed)
}

func TestRedactForExport(t *testing.T) {
	out, err := RedactForExport([]byte(nestedSchema), []byte(nestedConfig))
	if err != nil {
		t.Fatalf("RedactForExport: %v", err)
	}
	text := string(out)
	for _, leak := range []string{"p@ss", "v1", "t1", "right", "$secret", "sec_"} {
		if strings.Contains(text, leak) {
			t.Fatalf("export leaks %q: %s", leak, text)
		}
	}
	doc := mustDecode(t, text).(map[string]any)
	if doc["host"] != "example.com" {
		t.Fatalf("host changed: %v", doc["host"])
	}
	auth := doc["auth"].(map[string]any)
	if auth["password"] != redacted || auth["user"] != "alice" {
		t.Fatalf("auth = %v", auth)
	}
	pair := doc["pair"].([]any)
	if pair[0] != "left" || pair[1] != redacted {
		t.Fatalf("pair = %v", pair)
	}
	servers := doc["servers"].([]any)
	for i, srv := range servers {
		if srv.(map[string]any)["token"] != redacted {
			t.Fatalf("servers[%d] = %v", i, srv)
		}
	}

	// A schema that marks the whole document secret redacts everything.
	out, err = RedactForExport([]byte(`{"writeOnly": true}`), []byte(`{"a": "b"}`))
	if err != nil {
		t.Fatalf("RedactForExport whole document: %v", err)
	}
	if string(out) != `"`+redacted+`"` {
		t.Fatalf("whole document export = %s, want the marker", out)
	}
}

func TestRefObjectRoundTrip(t *testing.T) {
	ref, err := ParseRef("sec_01jtestsecret0000000000000")
	if err != nil {
		t.Fatalf("ParseRef: %v", err)
	}
	obj := RefObject(ref)
	got, ok := RefFromObject(obj)
	if !ok || got != ref {
		t.Fatalf("RefFromObject(%#v) = %q, %v", obj, got, ok)
	}
	for _, bad := range []any{
		nil,
		"sec_01jtestsecret0000000000000",
		map[string]any{RefKey: 42},
		map[string]any{RefKey: "sec_01jtestsecret0000000000000", "extra": "x"},
		map[string]any{RefKey: "not-a-ref"},
	} {
		if _, ok := RefFromObject(bad); ok {
			t.Fatalf("RefFromObject(%#v) accepted a non-reference", bad)
		}
	}
}

// mustDecode decodes JSON in a test or fails.
func mustDecode(t *testing.T, s string) any {
	t.Helper()
	v, err := decodeJSON([]byte(s))
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return v
}
