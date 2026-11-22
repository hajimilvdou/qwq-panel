// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// apiDir is the authoritative contract directory. It exists in the repository
// but not when the SDK is used from the module cache; tests that need it skip.
const apiDir = "../../api/manifest/v1"

func needAPI(t testing.TB) {
	t.Helper()
	if _, err := os.Stat(apiDir); err != nil {
		t.Skipf("%s not available: %v", apiDir, err)
	}
}

type fixtureCase struct {
	Name      string          `json:"name"`
	Expect    string          `json:"expect"`
	Code      string          `json:"code"`
	Pointer   *string         `json:"pointer"`
	Note      string          `json:"note"`
	Base      string          `json:"base"`
	Patch     json.RawMessage `json:"patch"`
	Edit      *fixtureEdit    `json:"edit"`
	Raw       *string         `json:"raw"`
	RawB64    *string         `json:"raw_b64"`
	RawRepeat []struct {
		S string `json:"s"`
		N int    `json:"n"`
	} `json:"raw_repeat"`
}

type fixtureEdit struct {
	Replace [][2]string `json:"replace"`
	Append  string      `json:"append"`
	PadTo   int         `json:"pad_to"`
}

func loadCases(t testing.TB) []fixtureCase {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(apiDir, "testdata", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, derr := decodeStrict(b); derr != nil { // the fixture itself has no duplicate keys
		t.Fatalf("cases.json: %v", derr)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var doc struct {
		Description string        `json:"description"`
		Cases       []fixtureCase `json:"cases"`
	}
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("cases.json: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range doc.Cases {
		if seen[c.Name] {
			t.Fatalf("duplicate case name %q", c.Name)
		}
		seen[c.Name] = true
	}
	return doc.Cases
}

var baseName = regexp.MustCompile(`^[a-z0-9._-]+\.json$`)

// buildInput mirrors build_input in tools/manifest_check.py.
func buildInput(c fixtureCase) ([]byte, error) {
	n := 0
	for _, set := range []bool{c.Patch != nil, c.Edit != nil, c.Raw != nil, c.RawB64 != nil, c.RawRepeat != nil} {
		if set {
			n++
		}
	}
	if n != 1 || (c.Base != "") != (c.Patch != nil || c.Edit != nil) {
		return nil, errors.New("exactly one input source required; base only with patch or edit")
	}
	switch {
	case c.Raw != nil:
		return []byte(*c.Raw), nil
	case c.RawB64 != nil:
		return base64.StdEncoding.Strict().DecodeString(*c.RawB64)
	case c.RawRepeat != nil:
		var b strings.Builder
		for _, p := range c.RawRepeat {
			b.WriteString(strings.Repeat(p.S, p.N))
		}
		return []byte(b.String()), nil
	}
	if !baseName.MatchString(c.Base) {
		return nil, fmt.Errorf("bad base %q", c.Base)
	}
	base, err := os.ReadFile(filepath.Join(apiDir, "examples", c.Base))
	if err != nil {
		return nil, err
	}
	if c.Patch != nil {
		doc, derr := decodeStrict(base)
		if derr != nil {
			return nil, derr
		}
		if doc, err = applyPatch(doc, c.Patch); err != nil {
			return nil, err
		}
		return json.Marshal(doc)
	}
	text := string(base)
	for _, r := range c.Edit.Replace {
		if strings.Count(text, r[0]) != 1 {
			return nil, fmt.Errorf("%q must occur exactly once", r[0])
		}
		text = strings.Replace(text, r[0], r[1], 1)
	}
	text += c.Edit.Append
	if c.Edit.PadTo > 0 {
		if len(text) > c.Edit.PadTo {
			return nil, errors.New("base is longer than pad_to")
		}
		text += strings.Repeat(" ", c.Edit.PadTo-len(text))
	}
	return []byte(text), nil
}

// applyPatch implements RFC 6902 add, replace and remove on a decodeStrict tree.
func applyPatch(doc any, raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	var ops []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}
	if err := dec.Decode(&ops); err != nil {
		return nil, err
	}
	for _, op := range ops {
		if !strings.HasPrefix(op.Path, "/") {
			return nil, fmt.Errorf("bad patch path %q", op.Path)
		}
		var toks []string
		for _, t := range strings.Split(op.Path[1:], "/") {
			toks = append(toks, strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~"))
		}
		var err error
		if doc, err = patchAt(doc, toks, op.Op, op.Value); err != nil {
			return nil, fmt.Errorf("%s %s: %w", op.Op, op.Path, err)
		}
	}
	return doc, nil
}

func patchAt(node any, toks []string, op string, value any) (any, error) {
	last := len(toks) == 1
	switch n := node.(type) {
	case map[string]any:
		k := toks[0]
		if !last {
			child, ok := n[k]
			if !ok {
				return nil, fmt.Errorf("missing %q", k)
			}
			v, err := patchAt(child, toks[1:], op, value)
			n[k] = v
			return n, err
		}
		_, exists := n[k]
		switch {
		case op == "add":
			n[k] = value
		case !exists:
			return nil, fmt.Errorf("missing %q", k)
		case op == "replace":
			n[k] = value
		case op == "remove":
			delete(n, k)
		default:
			return nil, fmt.Errorf("unsupported op %q", op)
		}
		return n, nil
	case []any:
		if last && op == "add" && toks[0] == "-" {
			return append(n, value), nil
		}
		i, err := strconv.Atoi(toks[0])
		limit := len(n)
		if last && op == "add" {
			limit++
		}
		if err != nil || i < 0 || i >= limit {
			return nil, fmt.Errorf("bad index %q", toks[0])
		}
		if !last {
			v, err := patchAt(n[i], toks[1:], op, value)
			n[i] = v
			return n, err
		}
		switch op {
		case "add":
			return append(n[:i], append([]any{value}, n[i:]...)...), nil
		case "replace":
			n[i] = value
			return n, nil
		case "remove":
			return append(n[:i], n[i+1:]...), nil
		}
		return nil, fmt.Errorf("unsupported op %q", op)
	}
	return nil, errors.New("path goes through a scalar")
}

// TestFixtureCases runs api/manifest/v1/testdata/cases.json, the fixture shared
// with tools/manifest_check.py.
func TestFixtureCases(t *testing.T) {
	needAPI(t)
	for _, c := range loadCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			raw, err := buildInput(c)
			if err != nil {
				t.Fatalf("building input: %v", err)
			}
			m, err := Parse(raw)
			switch c.Expect {
			case "accept":
				if err != nil {
					t.Fatalf("want accept, got %v", err)
				}
				if m == nil {
					t.Fatal("nil manifest without error")
				}
			case "reject":
				var e *Error
				if !errors.As(err, &e) {
					t.Fatalf("want *Error, got %v", err)
				}
				if c.Code == "" {
					return
				}
				for _, v := range e.Violations {
					if v.Code == c.Code && (c.Pointer == nil || v.Pointer == *c.Pointer) {
						return
					}
				}
				want := "(any)"
				if c.Pointer != nil {
					want = strconv.Quote(*c.Pointer)
				}
				t.Fatalf("want %s at %s, got %+v", c.Code, want, e.Violations)
			default:
				t.Fatalf("bad expect %q", c.Expect)
			}
		})
	}
}

func TestExamplesParse(t *testing.T) {
	needAPI(t)
	paths, err := filepath.Glob(filepath.Join(apiDir, "examples", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no examples: %v", err)
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(raw); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
