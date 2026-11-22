// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Violation codes of a VALIDATION_FAILED response (FieldViolation.code).
const (
	codeRequired     = "REQUIRED"
	codeInvalidJSON  = "INVALID_JSON"
	codeDuplicateKey = "DUPLICATE_KEY"
	codeUnknownField = "UNKNOWN_FIELD"
	codeTypeMismatch = "TYPE_MISMATCH"
)

// rawMessageType is json.RawMessage: it accepts any JSON value verbatim.
var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

// unmarshalerType is json.Unmarshaler.
var unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// DecodeJSON decodes a JSON request body into dst, a non-nil pointer.
//
// The body is bounded (by the route middleware and again here), its nesting
// depth is checked before parsing, unknown members and type mismatches become
// VALIDATION_FAILED with a JSON Pointer to the offending member, and trailing
// data is rejected. A body is never decoded into two different types.
func (g *Gateway) DecodeJSON(r *http.Request, dst any) error {
	return decodeJSON(r, g.limits.MaxPluginBodyBytes, g.limits.MaxJSONDepth, dst)
}

func decodeJSON(r *http.Request, maxBytes int64, maxDepth int, dst any) error {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return problem.Wrap(errors.New("gateway: DecodeJSON requires a non-nil pointer"))
	}
	if r.Body == nil {
		return bodyRequired()
	}

	data, err := readBody(r.Body, maxBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return bodyRequired()
	}

	// ======================== 单遍字段/深度状态机，先于形状与 DTO 解码 ========================
	if err := validateJSONMembers(data, maxDepth); err != nil {
		return err
	}

	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return badRequest("body", "/", codeInvalidJSON, "The request body is not valid JSON.")
	}
	if violations := validateShape(raw, rv.Type(), ""); len(violations) > 0 {
		sort.Slice(violations, func(i, j int) bool { return violations[i].Pointer < violations[j].Pointer })
		return problem.Validation(violations...)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return decodeFailed(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return badRequest("body", "/", codeInvalidJSON, "The request body has data after the JSON value.")
	}
	return nil
}

// readBody reads at most maxBytes+1 bytes and reports the overrun as
// PAYLOAD_TOO_LARGE naming the limit.
func readBody(body io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, payloadTooLarge("max_body_bytes", maxErr.Limit)
		}
		return nil, problem.Wrap(fmt.Errorf("gateway: read body: %w", err))
	}
	if int64(len(data)) > maxBytes {
		return nil, payloadTooLarge("max_body_bytes", maxBytes)
	}
	return data, nil
}

func bodyRequired() error {
	return badRequest("body", "/", codeRequired, "A JSON request body is required.")
}

// jsonDepth 仅在输入拒绝时复核原结构/深度错误优先级；合法请求不再单独预扫。
// 它不构造 JSON 值，即使畸形输入也保持原有的有界内存路径。
func jsonDepth(b []byte) (int, error) {
	depth, maxDepth := 0, 0
	inString, escaped := false, false
	for _, c := range b {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch c {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return 0, errors.New("gateway: unbalanced JSON")
			}
		}
	}
	if depth != 0 || inString {
		return 0, errors.New("gateway: unbalanced JSON")
	}
	return maxDepth, nil
}

// structInfo caches the JSON member names of a request type. The cache is
// bounded by the number of request types in the binary.
type structInfo struct {
	fields map[string]reflect.Type
	ok     bool // false: do not validate this struct (embedded or opaque)
}

var structCache sync.Map // reflect.Type -> structInfo

func requestFields(t reflect.Type) structInfo {
	if cached, ok := structCache.Load(t); ok {
		return cached.(structInfo)
	}
	info := structInfo{fields: make(map[string]reflect.Type, t.NumField()), ok: true}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			// Promoted fields change the JSON shape; let the decoder decide
			// instead of risking a false UNKNOWN_FIELD.
			info.ok = false
			break
		}
		if f.PkgPath != "" {
			continue // unexported
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		info.fields[name] = f.Type
	}
	structCache.Store(t, info)
	return info
}

// validateShape walks the decoded JSON value against the destination type and
// reports unknown members and type mismatches with their JSON Pointers.
func validateShape(v any, t reflect.Type, ptr string) []problem.Violation {
	if t == nil {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		if v == nil {
			return nil
		}
		t = t.Elem()
	}
	if t == rawMessageType || t.Implements(unmarshalerType) ||
		(t.Kind() != reflect.Interface && reflect.PointerTo(t).Implements(unmarshalerType)) {
		return nil
	}
	switch t.Kind() {
	case reflect.Interface:
		return nil
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return typeMismatch(ptr, "an object")
		}
		info := requestFields(t)
		if !info.ok {
			return nil
		}
		var out []problem.Violation
		for k, val := range m {
			child := joinPointer(ptr, k)
			ft, known := info.fields[k]
			if !known {
				out = append(out, fieldViolation("body", child, codeUnknownField,
					"The field is not part of this request."))
				continue
			}
			out = append(out, validateShape(val, ft, child)...)
		}
		return out
	case reflect.Slice, reflect.Array:
		if v == nil && t.Kind() == reflect.Slice {
			return nil
		}
		arr, ok := v.([]any)
		if !ok {
			return typeMismatch(ptr, "an array")
		}
		var out []problem.Violation
		for i, item := range arr {
			out = append(out, validateShape(item, t.Elem(), fmt.Sprintf("%s/%d", ptr, i))...)
		}
		return out
	case reflect.Map:
		if v == nil {
			return nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return typeMismatch(ptr, "an object")
		}
		var out []problem.Violation
		for k, val := range m {
			out = append(out, validateShape(val, t.Elem(), joinPointer(ptr, k))...)
		}
		return out
	case reflect.String:
		if _, ok := v.(string); !ok {
			return typeMismatch(ptr, "a string")
		}
	case reflect.Bool:
		if _, ok := v.(bool); !ok {
			return typeMismatch(ptr, "a boolean")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, ok := v.(float64)
		if !ok || n != math.Trunc(n) {
			return typeMismatch(ptr, "an integer")
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, ok := v.(float64)
		if !ok || n < 0 || n != math.Trunc(n) {
			return typeMismatch(ptr, "a non-negative integer")
		}
	case reflect.Float32, reflect.Float64:
		if _, ok := v.(float64); !ok {
			return typeMismatch(ptr, "a number")
		}
	}
	return nil
}

func typeMismatch(ptr, want string) []problem.Violation {
	return []problem.Violation{fieldViolation("body", ptr, codeTypeMismatch, "Expected "+want+".")}
}

// decodeFailed maps encoding/json errors to a problem document. Field paths in
// UnmarshalTypeError already use JSON member names, so they become pointers
// directly.
func decodeFailed(err error) error {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return payloadTooLarge("max_body_bytes", maxErr.Limit)
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return badRequest("body", jsonFieldPointer(typeErr.Field), codeTypeMismatch,
			"The value has the wrong type.")
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return badRequest("body", "/", codeInvalidJSON, "The request body is not valid JSON.")
	}
	if name, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		name = strings.Trim(name, `"`)
		return badRequest("body", joinPointer("", name), codeUnknownField,
			"The field is not part of this request.")
	}
	return badRequest("body", "/", codeInvalidJSON, "The request body could not be decoded.")
}

// jsonFieldPointer converts an UnmarshalTypeError field path ("a.b.c") into a
// JSON Pointer.
func jsonFieldPointer(field string) string {
	if field == "" {
		return "/"
	}
	ptr := ""
	for _, seg := range strings.Split(field, ".") {
		ptr = joinPointer(ptr, seg)
	}
	return ptr
}

// joinPointer appends one RFC 6901 segment.
func joinPointer(ptr, key string) string {
	return ptr + "/" + escapePointer(key)
}

func escapePointer(key string) string {
	if !strings.ContainsAny(key, "~/") {
		return key
	}
	key = strings.ReplaceAll(key, "~", "~0")
	return strings.ReplaceAll(key, "/", "~1")
}

func unescapePointer(key string) (string, bool) {
	if !strings.Contains(key, "~") {
		return key, true
	}
	var b strings.Builder
	b.Grow(len(key))
	for i := 0; i < len(key); i++ {
		if key[i] != '~' {
			b.WriteByte(key[i])
			continue
		}
		if i+1 >= len(key) {
			return "", false
		}
		switch key[i+1] {
		case '0':
			b.WriteByte('~')
		case '1':
			b.WriteByte('/')
		default:
			return "", false
		}
		i++
	}
	return b.String(), true
}
