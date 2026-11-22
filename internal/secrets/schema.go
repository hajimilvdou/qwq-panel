// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ExtractOptions configure ExtractSecrets.
type ExtractOptions struct {
	// Owner owns the created references, e.g. plugins/core.xray/instances/inst_…
	// or config. DeleteOwner uses it to clean up after an uninstall.
	Owner string
	// Purpose is stored with every reference, e.g. plugin.config.
	Purpose string
	// AllowExistingReferences 仅供已授权的配置编辑边界使用；引用必须位于敏感
	// schema 字段，并在同一写事务内匹配当前 owner/purpose。默认拒绝客户端引用。
	AllowExistingReferences bool
}

// Extracted is one reference produced by ExtractSecrets. It never carries the
// value: the pointer locates it in the input document, the reference names the
// stored ciphertext.
type Extracted struct {
	// Pointer is the RFC 6901 pointer of the replaced member in the input
	// document, e.g. /auth/password or /servers/0/token.
	Pointer string
	// Ref is the reference now stored at that position.
	Ref Ref
	// Purpose is the purpose recorded with the reference.
	Purpose string
}

// SchemaError reports a config schema that the host cannot inspect for secret
// fields. The host refuses such a schema instead of guessing: a keyword it does
// not understand could hide a writeOnly field, and storing that value in
// plaintext is exactly what this package exists to prevent.
type SchemaError struct {
	// Pointer is the RFC 6901 pointer of the offending schema node.
	Pointer string
	// Keyword is the JSON Schema keyword that is unsupported, when known.
	Keyword string
	// Reason explains the problem.
	Reason string
}

// Error implements error.
func (e *SchemaError) Error() string {
	if e.Keyword != "" {
		return fmt.Sprintf("config schema at %q: keyword %q is not supported: %s", e.Pointer, e.Keyword, e.Reason)
	}
	return fmt.Sprintf("config schema at %q: %s", e.Pointer, e.Reason)
}

// maxSchemaDepth bounds schema recursion; manifests allow 64 levels of nesting
// (ARCH §5.3), and a deeper schema is refused rather than trusted.
const maxSchemaDepth = 64

// unsupportedKeywords are JSON Schema keywords that can declare subschemas for
// values. The host does not interpret them, so it cannot tell whether they mark
// a field as secret; a schema using one is refused.
var unsupportedKeywords = []string{
	"patternProperties", "dependentSchemas", "propertyNames",
	"if", "then", "else", "not", "contains",
	"unevaluatedProperties", "unevaluatedItems",
	"$dynamicRef",
}

// ExtractSecrets replaces every value that schema marks as sensitive with a
// secret reference and stores the values.
//
// A value is sensitive when its schema node sets writeOnly: true or x-secret:
// true. The walk understands properties, items, prefixItems,
// additionalProperties, allOf/anyOf/oneOf and local $ref (#/…) references, plus
// boolean schemas; anything else that could declare a subschema is an error
// (SchemaError), never a silent pass-through.
//
// Values are encrypted in one write transaction, so either every reference
// exists or none does. The returned document has each sensitive value replaced
// by {"$secret": "sec_…"} (see RefObject); object member order is normalized by
// encoding/json. The returned references can be passed to ResolveSecrets to get
// the original document back.
//
// Like Seal, it opens its own write transaction and must not be called from
// inside another storage write transaction.
func (s *Store) ExtractSecrets(ctx context.Context, schema, config []byte, opts ExtractOptions) ([]byte, []Extracted, error) {
	if err := validateOwner(opts.Owner); err != nil {
		return nil, nil, err
	}
	if err := validatePurpose(opts.Purpose); err != nil {
		return nil, nil, err
	}
	doc, err := decodeJSON(schema)
	if err != nil {
		return nil, nil, &problem.Error{Code: problem.ValidationFailed, Detail: "The config schema is not valid JSON.", Cause: err}
	}
	instance, err := decodeJSON(config)
	if err != nil {
		return nil, nil, &problem.Error{Code: problem.ValidationFailed, Detail: "The config is not valid JSON.", Cause: err}
	}
	w := &walker{root: doc, seen: make(map[string]bool), out: make(map[string]bool)}
	if err := w.walk(doc, instance, "", "", 0); err != nil {
		return nil, nil, schemaFailure(err)
	}
	existing, err := inputReferences(instance, w.out, opts.AllowExistingReferences)
	if err != nil {
		return nil, nil, err
	}
	if len(w.out) == 0 {
		redacted, err := json.Marshal(instance)
		if err != nil {
			return nil, nil, problem.Wrap(err)
		}
		return redacted, nil, nil
	}
	pending, err := collectSecrets(instance, "", w.out)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		for i := range pending {
			clear(pending[i].value)
		}
	}()
	err = s.db.Update(ctx, func(tx *storage.Tx) error {
		for i := range pending {
			if ref, ok := existing[pending[i].pointer]; ok {
				row, err := scanSecretRow(tx.QueryRowContext(ctx, secretRowQuery, string(ref)))
				if err != nil {
					return err
				}
				if row.owner != opts.Owner || row.purpose != opts.Purpose {
					return errNotFound()
				}
				pending[i].ref = ref
				continue
			}
			ref, err := s.put(ctx, tx, opts.Owner, opts.Purpose, pending[i].value)
			if err != nil {
				return err
			}
			pending[i].ref = ref
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	refs := make(map[string]Ref, len(pending))
	extracted := make([]Extracted, 0, len(pending))
	for _, p := range pending {
		refs[p.pointer] = p.ref
		if _, retained := existing[p.pointer]; !retained {
			extracted = append(extracted, Extracted{Pointer: p.pointer, Ref: p.ref, Purpose: opts.Purpose})
		}
	}
	instance = replaceWithRefs(instance, refs)
	redacted, err := json.Marshal(instance)
	if err != nil {
		return nil, nil, problem.Wrap(err)
	}
	s.log.InfoContext(ctx, "secret fields extracted from config", "owner", opts.Owner, "purpose", opts.Purpose, "fields", len(extracted))
	return redacted, extracted, nil
}

// RedactForExport replaces every sensitive value with "[REDACTED]" and writes no
// secret. It is what config history, exports and logs use: the document keeps
// its shape but no value and no reference to a value.
func RedactForExport(schema, config []byte) ([]byte, error) {
	doc, err := decodeJSON(schema)
	if err != nil {
		return nil, &problem.Error{Code: problem.ValidationFailed, Detail: "The config schema is not valid JSON.", Cause: err}
	}
	instance, err := decodeJSON(config)
	if err != nil {
		return nil, &problem.Error{Code: problem.ValidationFailed, Detail: "The config is not valid JSON.", Cause: err}
	}
	w := &walker{root: doc, seen: make(map[string]bool), out: make(map[string]bool)}
	if err := w.walk(doc, instance, "", "", 0); err != nil {
		return nil, schemaFailure(err)
	}
	instance = replaceWithPlaceholder(instance, w.out)
	redacted, err := json.Marshal(instance)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return redacted, nil
}

// ResolveSecrets replaces every {"$secret": "sec_…"} object in config with the
// value it references, which is what a plugin receives when a config snapshot is
// applied. Owner and permitted purposes are supplied by the host boundary.
// The caller owns the returned plaintext and must clear it after use.
func (s *Store) ResolveSecrets(ctx context.Context, config []byte, owner string, purposes ...string) ([]byte, error) {
	if err := validateOwner(owner); err != nil {
		return nil, err
	}
	if err := validatePurposes(purposes); err != nil {
		return nil, err
	}
	doc, err := decodeJSON(config)
	if err != nil {
		return nil, &problem.Error{Code: problem.ValidationFailed, Detail: "The config is not valid JSON.", Cause: err}
	}
	resolved, err := s.resolveValue(ctx, doc, owner, purposes, 0)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(resolved)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return out, nil
}

// resolveValue walks a decoded document and replaces reference objects.
func (s *Store) resolveValue(ctx context.Context, v any, owner string, purposes []string, depth int) (any, error) {
	if depth > maxSchemaDepth {
		return nil, problem.New(problem.ValidationFailed, "The secret document is too deeply nested.")
	}
	switch node := v.(type) {
	case map[string]any:
		if _, reserved := node[RefKey]; reserved {
			ref, valid := RefFromObject(node)
			if !valid {
				return nil, problem.New(problem.ValidationFailed, "The secret reference object is invalid.")
			}
			plaintext, err := s.RevealOwnedAnyPurpose(ctx, ref, owner, purposes...)
			if err != nil {
				return nil, err
			}
			defer plaintext.Clear()
			raw := plaintext.Bytes()
			defer clear(raw)
			value, err := decodeJSON(raw)
			if err != nil {
				return nil, problem.Wrap(fmt.Errorf("secrets: resolve %s: %w", ref, err))
			}
			return value, nil
		}
		for k, child := range node {
			resolved, err := s.resolveValue(ctx, child, owner, purposes, depth+1)
			if err != nil {
				return nil, err
			}
			node[k] = resolved
		}
		return node, nil
	case []any:
		for i, child := range node {
			resolved, err := s.resolveValue(ctx, child, owner, purposes, depth+1)
			if err != nil {
				return nil, err
			}
			node[i] = resolved
		}
		return node, nil
	}
	return v, nil
}

// schemaFailure turns a schema walk error into the host error the install path
// reports. The detail is deliberately generic; the cause names the keyword and
// pointer for the log.
func schemaFailure(err error) *problem.Error {
	return &problem.Error{
		Code:   problem.ValidationFailed,
		Detail: "The config schema cannot be inspected for secret fields.",
		Cause:  err,
	}
}

// pendingSecret is one sensitive value on its way into the store.
type pendingSecret struct {
	pointer string
	value   []byte
	ref     Ref
}

// collectSecrets marshals the values at the marked pointers, in pointer order so
// extraction is deterministic.
func collectSecrets(v any, pointer string, marked map[string]bool) ([]pendingSecret, error) {
	var out []pendingSecret
	var walk func(any, string) error
	walk = func(v any, pointer string) error {
		if marked[pointer] {
			raw, err := json.Marshal(v)
			if err != nil {
				return problem.Wrap(err)
			}
			if len(raw) > MaxPlaintext {
				return problem.New(problem.ValidationFailed, "A secret value must be at most %d bytes.", MaxPlaintext)
			}
			out = append(out, pendingSecret{pointer: pointer, value: raw})
			return nil
		}
		switch node := v.(type) {
		case map[string]any:
			for k, child := range node {
				if err := walk(child, pointer+"/"+escapeToken(k)); err != nil {
					return err
				}
			}
		case []any:
			for i, child := range node {
				if err := walk(child, pointer+"/"+strconv.Itoa(i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(v, pointer); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pointer < out[j].pointer })
	return out, nil
}

// replaceWithRefs swaps marked values for reference objects. The whole document
// can be marked (a schema that is writeOnly at the root).
func replaceWithRefs(v any, refs map[string]Ref) any {
	if ref, ok := refs[""]; ok {
		return RefObject(ref)
	}
	var walk func(any, string)
	walk = func(v any, pointer string) {
		switch node := v.(type) {
		case map[string]any:
			for k, child := range node {
				p := pointer + "/" + escapeToken(k)
				if ref, ok := refs[p]; ok {
					node[k] = RefObject(ref)
					continue
				}
				walk(child, p)
			}
		case []any:
			for i, child := range node {
				p := pointer + "/" + strconv.Itoa(i)
				if ref, ok := refs[p]; ok {
					node[i] = RefObject(ref)
					continue
				}
				walk(child, p)
			}
		}
	}
	walk(v, "")
	return v
}

// replaceWithPlaceholder swaps marked values for the redaction marker.
func replaceWithPlaceholder(v any, marked map[string]bool) any {
	if marked[""] {
		return redacted
	}
	var walk func(any, string)
	walk = func(v any, pointer string) {
		switch node := v.(type) {
		case map[string]any:
			for k, child := range node {
				p := pointer + "/" + escapeToken(k)
				if marked[p] {
					node[k] = redacted
					continue
				}
				walk(child, p)
			}
		case []any:
			for i, child := range node {
				p := pointer + "/" + strconv.Itoa(i)
				if marked[p] {
					node[i] = redacted
					continue
				}
				walk(child, p)
			}
		}
	}
	walk(v, "")
	return v
}

// walker collects the pointers of sensitive values. It walks the schema and the
// instance together, so array indices and present members are known.
type walker struct {
	// root is the decoded schema document, the target of local $ref resolution.
	root any
	// seen prevents repeated work (and ref cycles) per (schema ref, instance
	// pointer) pair.
	seen map[string]bool
	// out is the set of instance pointers whose value must be replaced.
	out map[string]bool
}

// walk visits one schema node with the value it describes. spath is a pointer
// into the schema (for errors), ipath a pointer into the instance (for output).
func (w *walker) walk(schema, instance any, spath, ipath string, depth int) error {
	if depth > maxSchemaDepth {
		return &SchemaError{Pointer: spath, Reason: "schema nesting is deeper than 64 levels"}
	}
	switch s := schema.(type) {
	case bool:
		return nil
	case map[string]any:
		return w.walkNode(s, instance, spath, ipath, depth)
	default:
		return &SchemaError{Pointer: spath, Reason: "a schema node must be an object or a boolean"}
	}
}

// walkNode handles an object schema node.
func (w *walker) walkNode(s map[string]any, instance any, spath, ipath string, depth int) error {
	// JSON Schema 2020-12 applies $ref together with its sibling keywords.
	if raw, ok := s["$ref"]; ok {
		ref, ok := raw.(string)
		if !ok {
			return &SchemaError{Pointer: spath, Keyword: "$ref", Reason: "expected a string"}
		}
		if !strings.HasPrefix(ref, "#") {
			return &SchemaError{Pointer: spath, Keyword: "$ref", Reason: "only references into the same document (#/…) are supported"}
		}
		target, err := resolvePointer(w.root, ref[1:])
		if err != nil {
			return &SchemaError{Pointer: spath, Keyword: "$ref", Reason: err.Error()}
		}
		key := ref + "\x00" + ipath
		if !w.seen[key] {
			w.seen[key] = true
			if err := w.walk(target, instance, ref[1:], ipath, depth+1); err != nil {
				return err
			}
		}
	}
	for _, kw := range unsupportedKeywords {
		if _, ok := s[kw]; ok {
			return &SchemaError{Pointer: spath, Keyword: kw, Reason: "the host cannot tell whether it declares secret values"}
		}
	}
	secret, err := isSensitive(s, spath)
	if err != nil {
		return err
	}
	if secret {
		w.out[ipath] = true
		return nil
	}

	for _, kw := range [...]string{"allOf", "anyOf", "oneOf"} {
		raw, ok := s[kw]
		if !ok {
			continue
		}
		branches, ok := raw.([]any)
		if !ok {
			return &SchemaError{Pointer: spath, Keyword: kw, Reason: "expected an array of schemas"}
		}
		for i, branch := range branches {
			bp := spath + "/" + kw + "/" + strconv.Itoa(i)
			if err := w.walk(branch, instance, bp, ipath, depth+1); err != nil {
				return err
			}
		}
	}

	props := map[string]any(nil)
	if raw, ok := s["properties"]; ok {
		m, ok := raw.(map[string]any)
		if !ok {
			return &SchemaError{Pointer: spath, Keyword: "properties", Reason: "expected an object of schemas"}
		}
		props = m
		if obj, ok := instance.(map[string]any); ok {
			for name, sub := range m {
				value, present := obj[name]
				if !present {
					continue
				}
				if err := w.walk(sub, value, spath+"/properties/"+escapeToken(name), ipath+"/"+escapeToken(name), depth+1); err != nil {
					return err
				}
			}
		}
	}

	if raw, ok := s["additionalProperties"]; ok {
		switch ap := raw.(type) {
		case bool:
			// true: unconstrained; false: validation rejects the value.
		case map[string]any:
			obj, ok := instance.(map[string]any)
			if !ok {
				break
			}
			for name, value := range obj {
				if _, declared := props[name]; declared {
					continue
				}
				if err := w.walk(ap, value, spath+"/additionalProperties", ipath+"/"+escapeToken(name), depth+1); err != nil {
					return err
				}
			}
		default:
			return &SchemaError{Pointer: spath, Keyword: "additionalProperties", Reason: "expected a schema or a boolean"}
		}
	}

	var prefix []any
	if raw, ok := s["prefixItems"]; ok {
		arr, ok := raw.([]any)
		if !ok {
			return &SchemaError{Pointer: spath, Keyword: "prefixItems", Reason: "expected an array of schemas"}
		}
		prefix = arr
	}
	items, hasItems := s["items"]
	if hasItems {
		switch items.(type) {
		case bool, map[string]any:
		default:
			return &SchemaError{Pointer: spath, Keyword: "items", Reason: "expected a schema or a boolean"}
		}
	}
	arr, ok := instance.([]any)
	if !ok {
		return nil
	}
	for i, sub := range prefix {
		if i >= len(arr) {
			break
		}
		if err := w.walk(sub, arr[i], spath+"/prefixItems/"+strconv.Itoa(i), ipath+"/"+strconv.Itoa(i), depth+1); err != nil {
			return err
		}
	}
	if sub, ok := items.(map[string]any); ok {
		for i := len(prefix); i < len(arr); i++ {
			if err := w.walk(sub, arr[i], spath+"/items", ipath+"/"+strconv.Itoa(i), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// isSensitive reports whether a schema node marks its value as secret.
func isSensitive(s map[string]any, spath string) (bool, error) {
	for _, kw := range [...]string{"writeOnly", "x-secret"} {
		raw, ok := s[kw]
		if !ok {
			continue
		}
		flag, ok := raw.(bool)
		if !ok {
			return false, &SchemaError{Pointer: spath, Keyword: kw, Reason: "expected true or false"}
		}
		if flag {
			return true, nil
		}
	}
	return false, nil
}

// resolvePointer resolves an RFC 6901 pointer into the schema document.
func resolvePointer(root any, pointer string) (any, error) {
	if pointer == "" {
		return root, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, errors.New("not a JSON pointer")
	}
	node := root
	for _, token := range strings.Split(pointer[1:], "/") {
		token = unescapeToken(token)
		switch n := node.(type) {
		case map[string]any:
			next, ok := n[token]
			if !ok {
				return nil, errors.New("the reference does not resolve")
			}
			node = next
		case []any:
			i, err := strconv.Atoi(token)
			if err != nil || i < 0 || i >= len(n) {
				return nil, errors.New("the reference does not resolve")
			}
			node = n[i]
		default:
			return nil, errors.New("the reference does not resolve")
		}
	}
	return node, nil
}

// escapeToken escapes one JSON pointer token (RFC 6901 §3).
func escapeToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// unescapeToken reverses escapeToken.
func unescapeToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
}

// decodeJSON decodes exactly one JSON value, keeping numbers as json.Number so
// a large integer is not rounded through float64.
func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the JSON value")
	}
	return v, nil
}
