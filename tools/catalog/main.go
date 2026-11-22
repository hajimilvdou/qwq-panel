// SPDX-License-Identifier: AGPL-3.0-only

// Command catalog generates the host half of the action catalog (ADR-0006 D4)
// from api/public/v1/openapi.yaml: every operation with x-qwq-action becomes a
// catalog entry whose args_schema flattens path parameters, the
// expected_revision query parameter and the request body members into one
// object. The output is a Go source file committed to the repository, so the
// host never parses YAML at run time.
//
//	go run . -in ../../api/public/v1/openapi.yaml -out ../../internal/catalog/host_gen.go
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

type doc = map[string]any

func main() {
	in := flag.String("in", "", "openapi.yaml")
	out := flag.String("out", "", "output Go file")
	flag.Parse()
	if *in == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	src, err := os.ReadFile(*in)
	if err != nil {
		fatal(err)
	}
	code, err := generate(src)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, code, 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "catalog:", err)
	os.Exit(1)
}

// action is one generated entry; the JSON tags match catalog.HostAction.
type action struct {
	ID           string          `json:"id"`
	Summary      string          `json:"summary"`
	Effect       string          `json:"effect"`
	Risk         string          `json:"risk"`
	Mode         string          `json:"mode"`
	Idempotent   bool            `json:"idempotent"`
	Plannable    bool            `json:"plannable"`
	Undo         string          `json:"undo,omitempty"`
	UIRoute      string          `json:"ui_route,omitempty"`
	Permission   string          `json:"permission"`
	TimeoutMS    int             `json:"timeout_ms"`
	Reachability bool            `json:"reachability,omitempty"`
	Method       string          `json:"method"`
	Path         string          `json:"path"`
	ArgsSchema   json.RawMessage `json:"args_schema"`
	ResultSchema json.RawMessage `json:"result_schema,omitempty"`
}

// reachabilityKey is the operation-level extension that marks a host action
// which can cut the administrator off from the server or the panel (ADR-0016).
const reachabilityKey = "x-qwq-reachability"

var (
	idPattern = regexp.MustCompile(`^host\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	methods   = []string{"get", "put", "post", "patch", "delete"}
)

func generate(src []byte) ([]byte, error) {
	var root doc
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	root = normalize(root).(doc)
	paths, _ := root["paths"].(doc)
	if paths == nil {
		return nil, errors.New("no paths")
	}
	var acts []action
	seen := map[string]bool{}
	for _, p := range sortedKeys(paths) {
		item, _ := paths[p].(doc)
		for _, m := range methods {
			op, ok := item[m].(doc)
			if !ok {
				continue
			}
			x, ok := op["x-qwq-action"].(doc)
			if !ok {
				if _, marked := op[reachabilityKey]; marked {
					return nil, fmt.Errorf("%s %s: %s needs x-qwq-action", strings.ToUpper(m), p, reachabilityKey)
				}
				continue
			}
			a, err := build(root, item, op, x, strings.ToUpper(m), p)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", strings.ToUpper(m), p, err)
			}
			if seen[a.ID] {
				return nil, fmt.Errorf("duplicate action id %s", a.ID)
			}
			seen[a.ID] = true
			acts = append(acts, a)
		}
	}
	for _, a := range acts {
		if a.Undo != "" && !seen[a.Undo] {
			return nil, fmt.Errorf("%s: undo %s is not a host action", a.ID, a.Undo)
		}
	}
	sort.Slice(acts, func(i, j int) bool { return acts[i].ID < acts[j].ID })
	return render(acts)
}

func build(root, item, op, x doc, method, path string) (action, error) {
	a := action{Method: method, Path: path}
	str := func(k string) string { s, _ := x[k].(string); return s }
	a.ID, a.Summary, a.Effect, a.Risk, a.Mode = str("id"), str("summary"), str("effect"), str("risk"), str("mode")
	a.Undo, a.UIRoute, a.Permission = str("undo"), str("ui_route"), str("permission")
	a.Idempotent, _ = x["idempotent"].(bool)
	a.Plannable, _ = x["plannable"].(bool)
	if t, ok := x["timeout_ms"].(int); ok {
		a.TimeoutMS = t
	}
	switch {
	case !idPattern.MatchString(a.ID):
		return a, fmt.Errorf("bad id %q", a.ID)
	case a.Summary == "" || len(a.Summary) > 120:
		return a, errors.New("summary must be 1-120 bytes")
	case !in(a.Effect, "read", "write", "destructive"), !in(a.Risk, "low", "medium", "high"), !in(a.Mode, "invoke", "job"):
		return a, errors.New("bad effect, risk or mode")
	case a.Effect == "destructive" && a.Risk != "high":
		return a, errors.New("destructive actions must be risk high")
	case a.Effect == "read" && !a.Idempotent:
		return a, errors.New("read actions must be idempotent")
	case a.Permission == "" || a.TimeoutMS < 1 || a.TimeoutMS > 300000:
		return a, errors.New("permission and timeout_ms (1..300000) are required")
	}
	// The same rule the plugin manifest applies to operations[].reachability:
	// a lockout action changes something and is declared high risk.
	if raw, marked := op[reachabilityKey]; marked {
		flag, isBool := raw.(bool)
		switch {
		case !isBool:
			return a, fmt.Errorf("%s must be a boolean", reachabilityKey)
		case flag && (a.Effect == "read" || a.Risk != "high"):
			return a, fmt.Errorf("%s actions must change something and be risk high", reachabilityKey)
		}
		a.Reachability = flag
	}

	defs := doc{} // args only; the result schema collects its own
	props := doc{}
	var required []string
	add := func(name string, schema any, req bool) error {
		if _, dup := props[name]; dup {
			return fmt.Errorf("argument %q defined twice", name)
		}
		props[name] = schema
		if req {
			required = append(required, name)
		}
		return nil
	}

	// Path parameters (path item and operation level), and the expected_revision query parameter.
	var params []any
	if ps, ok := item["parameters"].([]any); ok {
		params = append(params, ps...)
	}
	if ps, ok := op["parameters"].([]any); ok {
		params = append(params, ps...)
	}
	for _, raw := range params {
		pm, err := resolve(root, raw)
		if err != nil {
			return a, err
		}
		name, _ := pm["name"].(string)
		where, _ := pm["in"].(string)
		if where == "path" || (where == "query" && name == "expected_revision") {
			s, err := schemaOf(root, pm["schema"], defs)
			if err != nil {
				return a, err
			}
			if d, ok := pm["description"].(string); ok {
				if m, ok := s.(doc); ok && m["$ref"] == nil {
					m["description"] = d
				}
			}
			req, _ := pm["required"].(bool)
			if err := add(name, s, req || where == "path"); err != nil {
				return a, err
			}
		}
	}

	// Request body members.
	if rb, ok := op["requestBody"]; ok {
		body, err := resolve(root, rb)
		if err != nil {
			return a, err
		}
		content, _ := body["content"].(doc)
		jsonBody, _ := content["application/json"].(doc)
		if jsonBody != nil {
			obj, err := flatten(root, jsonBody["schema"])
			if err != nil {
				return a, fmt.Errorf("request body: %w", err)
			}
			req := map[string]bool{}
			for _, r := range obj.required {
				req[r] = true
			}
			for _, name := range sortedKeys(obj.props) {
				s, err := schemaOf(root, obj.props[name], defs)
				if err != nil {
					return a, err
				}
				if err := add(name, s, req[name]); err != nil {
					return a, err
				}
			}
		}
	}
	sort.Strings(required)
	args := doc{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"type":                 "object",
		"additionalProperties": false,
		"properties":           props,
	}
	if len(required) > 0 {
		args["required"] = required
	}

	// Result: the JSON schema of the first 2xx response, with its own $defs.
	var result any
	resultDefs := doc{}
	if rs, ok := op["responses"].(doc); ok {
		for _, code := range sortedKeys(rs) {
			if !strings.HasPrefix(code, "2") {
				continue
			}
			r, err := resolve(root, rs[code])
			if err != nil {
				return a, err
			}
			content, _ := r["content"].(doc)
			if j, ok := content["application/json"].(doc); ok {
				s, err := schemaOf(root, j["schema"], resultDefs)
				if err != nil {
					return a, err
				}
				result = s
			}
			break
		}
	}
	if len(defs) > 0 {
		args["$defs"] = defs
	}
	var err error
	if a.ArgsSchema, err = json.Marshal(args); err != nil {
		return a, err
	}
	if result != nil {
		rs := doc{"$schema": "https://json-schema.org/draft/2020-12/schema"}
		if m, ok := result.(doc); ok {
			for k, v := range m {
				rs[k] = v
			}
		}
		if len(resultDefs) > 0 {
			rs["$defs"] = resultDefs
		}
		if a.ResultSchema, err = json.Marshal(rs); err != nil {
			return a, err
		}
	}
	return a, nil
}

type object struct {
	props    doc
	required []string
}

// flatten turns a request body schema ($ref, plain object, or allOf of
// objects) into one property set.
func flatten(root doc, s any) (object, error) {
	o := object{props: doc{}}
	m, err := resolve(root, s)
	if err != nil {
		return o, err
	}
	if _, ok := m["oneOf"]; ok {
		return o, errors.New("oneOf bodies cannot be flattened")
	}
	if _, ok := m["anyOf"]; ok {
		return o, errors.New("anyOf bodies cannot be flattened")
	}
	if all, ok := m["allOf"].([]any); ok {
		for _, part := range all {
			p, err := flatten(root, part)
			if err != nil {
				return o, err
			}
			for k, v := range p.props {
				if _, dup := o.props[k]; dup {
					return o, fmt.Errorf("member %q defined twice in allOf", k)
				}
				o.props[k] = v
			}
			o.required = append(o.required, p.required...)
		}
	}
	if ps, ok := m["properties"].(doc); ok {
		for k, v := range ps {
			if _, dup := o.props[k]; dup {
				return o, fmt.Errorf("member %q defined twice", k)
			}
			o.props[k] = v
		}
	}
	if rs, ok := m["required"].([]any); ok {
		for _, r := range rs {
			if s, ok := r.(string); ok {
				o.required = append(o.required, s)
			}
		}
	}
	return o, nil
}

// schemaOf copies s, rewriting references to components/schemas into $defs
// and copying the referenced schemas (transitively) into defs.
func schemaOf(root doc, s any, defs doc) (any, error) {
	switch v := s.(type) {
	case doc:
		if ref, ok := v["$ref"].(string); ok {
			name, ok := strings.CutPrefix(ref, "#/components/schemas/")
			if !ok {
				return nil, fmt.Errorf("unsupported $ref %s", ref)
			}
			if _, done := defs[name]; !done {
				defs[name] = nil // placeholder breaks cycles
				target, err := lookup(root, ref)
				if err != nil {
					return nil, err
				}
				c, err := schemaOf(root, target, defs)
				if err != nil {
					return nil, err
				}
				defs[name] = c
			}
			out := doc{"$ref": "#/$defs/" + name}
			for k, x := range v { // siblings of $ref are allowed in 2020-12
				if k != "$ref" && !strings.HasPrefix(k, "x-") {
					out[k] = x
				}
			}
			return out, nil
		}
		out := doc{}
		for k, x := range v {
			if strings.HasPrefix(k, "x-") {
				continue
			}
			c, err := schemaOf(root, x, defs)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			c, err := schemaOf(root, x, defs)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	default:
		return v, nil
	}
}

func resolve(root doc, v any) (doc, error) {
	m, ok := v.(doc)
	if !ok {
		return nil, errors.New("expected an object")
	}
	for i := 0; i < 16; i++ {
		ref, ok := m["$ref"].(string)
		if !ok {
			return m, nil
		}
		t, err := lookup(root, ref)
		if err != nil {
			return nil, err
		}
		if m, ok = t.(doc); !ok {
			return nil, fmt.Errorf("%s is not an object", ref)
		}
	}
	return nil, errors.New("$ref chain too long")
}

func lookup(root doc, ref string) (any, error) {
	p, ok := strings.CutPrefix(ref, "#/")
	if !ok {
		return nil, fmt.Errorf("only local references are supported: %s", ref)
	}
	var cur any = root
	for _, seg := range strings.Split(p, "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		m, ok := cur.(doc)
		if !ok {
			return nil, fmt.Errorf("bad reference %s", ref)
		}
		if cur, ok = m[seg]; !ok {
			return nil, fmt.Errorf("unresolved reference %s", ref)
		}
	}
	return cur, nil
}

// normalize converts yaml.v3's map[string]interface{} trees and keeps ints as int.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := doc{}
		for k, e := range x {
			out[k] = normalize(e)
		}
		return out
	case map[any]any:
		out := doc{}
		for k, e := range x {
			out[fmt.Sprint(k)] = normalize(e)
		}
		return out
	case []any:
		for i := range x {
			x[i] = normalize(x[i])
		}
		return x
	default:
		return v
	}
}

func render(acts []action) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("// SPDX-License-Identifier: AGPL-3.0-only\n\n")
	b.WriteString("// Code generated by tools/catalog from api/public/v1/openapi.yaml. DO NOT EDIT.\n\n")
	b.WriteString("package catalog\n\n")
	b.WriteString("// hostActionsJSON is the host half of the action catalog (ADR-0006 D4).\n")
	b.WriteString("const hostActionsJSON = ")
	j, err := json.Marshal(acts)
	if err != nil {
		return nil, err
	}
	if bytes.ContainsRune(j, '`') {
		b.WriteString(fmt.Sprintf("%q", j))
	} else {
		b.WriteString("`" + string(j) + "`")
	}
	b.WriteString("\n")
	return format.Source(b.Bytes())
}

func sortedKeys(m doc) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func in(s string, set ...string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}
