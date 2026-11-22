// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

// SchemaID is the $id of the manifest schema.
const SchemaID = "urn:qwq:plugin-manifest:v1"

// schemaJSON is a byte-identical copy of api/manifest/v1/manifest.schema.json,
// which stays authoritative (api/ is outside this Go module, so it cannot be
// embedded directly). TestSchemaCopyInSync keeps the two in step.
//
//go:embed manifest.schema.json
var schemaJSON []byte

// Schema returns the embedded manifest JSON Schema (a copy).
func Schema() []byte { return bytes.Clone(schemaJSON) }

// compiledSchema compiles the embedded schema once. The result is immutable.
var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	return compileSchema(schemaJSON)
})

// errNoLoader is returned for any $ref outside the registered schema.
var errNoLoader = errors.New("external schema references are not allowed")

// denyLoader replaces the library default (FileLoader). Nothing is ever
// fetched from the network or the filesystem; the Draft 2020-12 metaschema
// comes from the library's embedded copy and never reaches a loader.
type denyLoader struct{}

func (denyLoader) Load(string) (any, error) { return nil, errNoLoader }

func compileSchema(doc []byte) (*jsonschema.Schema, error) {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return nil, fmt.Errorf("manifest schema: %w", err)
	}
	if m, ok := v.(map[string]any); !ok || m["$id"] != SchemaID {
		return nil, fmt.Errorf("manifest schema: $id must be %q", SchemaID)
	}
	if err := checkLocalRefs(v); err != nil {
		return nil, fmt.Errorf("manifest schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyLoader{})
	// "pattern" must use RE2 semantics (no backtracking, "$" only at the end
	// of input); this is also the library default, set here explicitly.
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) { return regexp.Compile(s) })
	if err := c.AddResource(SchemaID, v); err != nil {
		return nil, fmt.Errorf("manifest schema: %w", err)
	}
	s, err := c.Compile(SchemaID)
	if err != nil {
		return nil, fmt.Errorf("manifest schema: %w", err)
	}
	return s, nil
}

// validateSchema validates a tree produced by decodeStrict.
func validateSchema(tree any) []Violation {
	s, err := compiledSchema()
	if err != nil {
		// The embedded schema is covered by tests; fail closed regardless.
		return []Violation{{Code: CodeSchemaViolation, Message: "schema unavailable: " + err.Error()}}
	}
	err = s.Validate(tree)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return []Violation{{Code: CodeSchemaViolation, Message: "schema validation failed"}}
	}
	var out []Violation
	walkValidation(ve, &out)
	if len(out) == 0 {
		out = append(out, Violation{Code: CodeSchemaViolation, Message: "schema validation failed"})
	}
	return out
}

// walkValidation flattens the library's error tree into leaf violations.
// tools/manifest_check.py produces the same (pointer, code) set.
func walkValidation(e *jsonschema.ValidationError, out *[]Violation) {
	loc := e.InstanceLocation
	child := func(p string) string { return pointer(append(slices.Clip(loc), p)) }
	switch k := e.ErrorKind.(type) {
	case *kind.Schema, *kind.Group, *kind.Reference, *kind.AllOf:
		for _, c := range e.Causes {
			walkValidation(c, out)
		}
	case *kind.AdditionalProperties:
		for _, p := range k.Properties {
			*out = append(*out, Violation{child(p), CodeSchemaAdditionalProperties, "property is not allowed"})
		}
	case *kind.Required:
		for _, p := range k.Missing {
			*out = append(*out, Violation{child(p), CodeSchemaRequired, "required property is missing"})
		}
	case *kind.PropertyNames:
		// jsonschema v6.0.3 stores the validator's location slice without
		// copying it for propertyNames errors (validator.go:296), so later
		// sibling properties overwrite it. Recompute it from the schema
		// location instead; TestPropertyNamesLocations checks the mapping.
		loc = propertyNamesLocation(e.SchemaURL)
		*out = append(*out, Violation{child(k.Property), CodeSchemaPropertyNames, "property name is not allowed by the schema"})
	default:
		*out = append(*out, Violation{pointer(loc), kindCode(k), kindMessage(k)})
	}
}

// propertyNamesLocation maps "<SchemaID>#/properties/a/properties/b/propertyNames"
// to the instance tokens [a b]. Anything else maps to the document root, which
// is still a valid (if coarser) pointer.
func propertyNamesLocation(schemaURL string) []string {
	frag, ok := strings.CutPrefix(schemaURL, SchemaID+"#")
	if !ok {
		return nil
	}
	frag, ok = strings.CutSuffix(frag, "/propertyNames")
	if !ok {
		return nil
	}
	if frag == "" {
		return []string{}
	}
	segs := strings.Split(strings.TrimPrefix(frag, "/"), "/")
	if len(segs)%2 != 0 {
		return nil
	}
	var toks []string
	for i := 0; i < len(segs); i += 2 {
		name, err := url.PathUnescape(segs[i+1])
		if segs[i] != "properties" || err != nil {
			return nil
		}
		toks = append(toks, strings.ReplaceAll(strings.ReplaceAll(name, "~1", "/"), "~0", "~"))
	}
	return toks
}

// checkLocalRefs rejects any $ref that is not a fragment of this document.
// (A relative reference against the opaque URN base would otherwise silently
// resolve to the document itself.)
func checkLocalRefs(v any) error {
	switch v := v.(type) {
	case map[string]any:
		for k, sub := range v {
			if s, ok := sub.(string); ok && k == "$ref" && !strings.HasPrefix(s, "#/") {
				return fmt.Errorf("%w: %q", errNoLoader, s)
			}
			if err := checkLocalRefs(sub); err != nil {
				return err
			}
		}
	case []any:
		for _, sub := range v {
			if err := checkLocalRefs(sub); err != nil {
				return err
			}
		}
	}
	return nil
}

func kindCode(k jsonschema.ErrorKind) string {
	switch k.(type) {
	case *kind.Type:
		return CodeSchemaType
	case *kind.Const:
		return CodeSchemaConst
	case *kind.Enum:
		return CodeSchemaEnum
	case *kind.Pattern:
		return CodeSchemaPattern
	case *kind.MinLength:
		return CodeSchemaMinLength
	case *kind.MaxLength:
		return CodeSchemaMaxLength
	case *kind.Minimum:
		return CodeSchemaMinimum
	case *kind.Maximum:
		return CodeSchemaMaximum
	case *kind.MinItems:
		return CodeSchemaMinItems
	case *kind.MaxItems:
		return CodeSchemaMaxItems
	case *kind.UniqueItems:
		return CodeSchemaUniqueItems
	case *kind.MinProperties:
		return CodeSchemaMinProperties
	case *kind.MaxProperties:
		return CodeSchemaMaxProperties
	}
	return CodeSchemaViolation
}

// kindMessage describes a failure using only schema values, never the
// (untrusted, possibly huge) instance value.
func kindMessage(k jsonschema.ErrorKind) string {
	switch k := k.(type) {
	case *kind.Type:
		return fmt.Sprintf("expected %s, got %s", strings.Join(k.Want, " or "), k.Got)
	case *kind.Const:
		return "must be " + schemaValue(k.Want)
	case *kind.Enum:
		return "must be one of " + schemaValue(k.Want)
	case *kind.Pattern:
		// Quoted: some patterns contain control and bidi characters.
		return "does not match pattern " + strconv.QuoteToASCII(k.Want)
	case *kind.MinLength:
		return fmt.Sprintf("length %d is less than %d", k.Got, k.Want)
	case *kind.MaxLength:
		return fmt.Sprintf("length %d is more than %d", k.Got, k.Want)
	case *kind.Minimum:
		return "must be >= " + k.Want.RatString()
	case *kind.Maximum:
		return "must be <= " + k.Want.RatString()
	case *kind.MinItems:
		return fmt.Sprintf("has %d items, fewer than %d", k.Got, k.Want)
	case *kind.MaxItems:
		return fmt.Sprintf("has %d items, more than %d", k.Got, k.Want)
	case *kind.UniqueItems:
		return fmt.Sprintf("items %d and %d are equal", k.Duplicates[0], k.Duplicates[1])
	case *kind.MinProperties:
		return fmt.Sprintf("has %d properties, fewer than %d", k.Got, k.Want)
	case *kind.MaxProperties:
		return fmt.Sprintf("has %d properties, more than %d", k.Got, k.Want)
	}
	return "violates " + strings.Join(k.KeywordPath(), "/")
}

func schemaValue(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "the schema value"
	}
	return string(b)
}
