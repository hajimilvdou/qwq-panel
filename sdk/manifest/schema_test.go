// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSchemaCopyInSync: sdk/manifest/manifest.schema.json must be a byte-identical
// copy of the authoritative api/manifest/v1/manifest.schema.json.
func TestSchemaCopyInSync(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(apiDir, "manifest.schema.json"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("api/ not available (SDK used outside the repository)")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(schemaJSON, want) {
		t.Fatal("sdk/manifest/manifest.schema.json differs from api/manifest/v1/manifest.schema.json; copy it again")
	}
	if !bytes.Equal(Schema(), want) {
		t.Fatal("Schema() differs")
	}
}

func TestSchemaCompiles(t *testing.T) {
	s, err := compiledSchema()
	if err != nil {
		t.Fatal(err)
	}
	if s2, _ := compiledSchema(); s2 != s {
		t.Fatal("schema is compiled more than once")
	}
}

// TestSchemaRefsStayLocal: any $ref outside the registered document fails at
// compile time instead of touching the network or the filesystem.
func TestSchemaRefsStayLocal(t *testing.T) {
	refs := []string{
		"https://example.com/other.schema.json",
		"http://127.0.0.1:1/x.json",
		"file:///etc/passwd",
		"other.schema.json",
		"urn:qwq:something-else",
	}
	for _, ref := range refs {
		doc := `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"` + SchemaID + `",` +
			`"properties":{"a":{"$ref":"` + ref + `"}}}`
		_, err := compileSchema([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), errNoLoader.Error()) {
			t.Errorf("$ref %q: want %q, got %v", ref, errNoLoader, err)
		}
	}
	if _, err := compileSchema([]byte(`{"$id":"urn:other"}`)); err == nil {
		t.Error("wrong $id accepted")
	}
	// A custom metaschema reaches the loader, which refuses it.
	meta := `{"$schema":"https://example.com/meta","$id":"` + SchemaID + `"}`
	if _, err := compileSchema([]byte(meta)); err == nil || !strings.Contains(err.Error(), errNoLoader.Error()) {
		t.Errorf("custom $schema: want %q, got %v", errNoLoader, err)
	}
}

func TestPropertyNamesLocations(t *testing.T) {
	cases := map[string][]string{
		SchemaID + "#/properties/files/propertyNames":                 {"files"},
		SchemaID + "#/properties/a~1b/properties/c%25d/propertyNames": {"a/b", "c%d"},
		SchemaID + "#/propertyNames":                                  {},
		SchemaID + "#/properties/ops/items/propertyNames":             nil,
		"urn:other#/properties/files/propertyNames":                   nil,
	}
	for in, want := range cases {
		got := propertyNamesLocation(in)
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") || (got == nil) != (want == nil) {
			t.Errorf("propertyNamesLocation(%q) = %q, want %q", in, got, want)
		}
	}
	// Regression for the library aliasing bug: with siblings after "files"
	// the pointer must still be /files/<key>, on every map iteration order.
	for i := 0; i < 50; i++ {
		_, err := Parse([]byte(`{"name":"","files":{"../x":"sha256:00"},"zzz":1,"version":"x"}`))
		var e *Error
		if !errors.As(err, &e) {
			t.Fatal(err)
		}
		found := false
		for _, v := range e.Violations {
			if v.Code == CodeSchemaPropertyNames {
				found = true
				if v.Pointer != "/files/..~1x" {
					t.Fatalf("propertyNames pointer %q", v.Pointer)
				}
			}
		}
		if !found {
			t.Fatal("no propertyNames violation")
		}
	}
}

// TestPatternIsRE2: "$" only matches at the end of input and \s is ASCII.
// Python's re differs on both; tools/manifest_check.py rewrites the patterns.
func TestPatternIsRE2(t *testing.T) {
	doc := `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"` + SchemaID + `",` +
		`"properties":{"a":{"pattern":"^x$"},"b":{"pattern":"^[^\\s]+$"}}}`
	s, err := compileSchema([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		inst map[string]any
		ok   bool
	}{
		{map[string]any{"a": "x"}, true},
		{map[string]any{"a": "x\n"}, false},
		{map[string]any{"b": "a\u000bb"}, true},
		{map[string]any{"b": "a\u3000b"}, true},
		{map[string]any{"b": "a b"}, false},
	}
	for _, c := range cases {
		if err := s.Validate(c.inst); (err == nil) != c.ok {
			t.Errorf("%q: valid=%v, want %v", c.inst, err == nil, c.ok)
		}
	}
	// Lookaround is not RE2: such a schema must not compile.
	bad := `{"$id":"` + SchemaID + `","pattern":"^(?=a)"}`
	if _, err := compileSchema([]byte(bad)); err == nil {
		t.Error("lookaround pattern compiled")
	}
}
