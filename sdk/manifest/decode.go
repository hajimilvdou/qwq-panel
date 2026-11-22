// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// MaxSize is the largest accepted manifest.json in bytes (ARCH §5.3).
	MaxSize = 256 << 10
	// MaxDepth is the deepest accepted nesting of objects and arrays; the top
	// level object is depth 1. The schema itself needs 4.
	MaxDepth = 64
	// MaxSafeInteger bounds every number (RFC 7493 §2.2, 2^53-1), so numbers
	// are exact in float64, int64 and every JSON implementation.
	MaxSafeInteger = 1<<53 - 1
)

// decodeStrict parses one JSON document into map[string]any, []any, string,
// json.Number (canonical integer text), bool and nil.
//
// Beyond RFC 8259 it rejects: invalid UTF-8, duplicate keys (compared after
// unescaping), unpaired surrogate escapes, nesting deeper than MaxDepth,
// numbers that are not integers within ±MaxSafeInteger, and trailing data.
// The parser is a hand-written recursive descent bounded by MaxDepth;
// encoding/json is not used because it silently replaces lone surrogates and
// keeps the last of duplicate keys.
func decodeStrict(data []byte) (any, *Error) {
	if !utf8.Valid(data) {
		off := 0
		for off < len(data) {
			r, n := utf8.DecodeRune(data[off:])
			if r == utf8.RuneError && n <= 1 {
				break
			}
			off += n
		}
		return nil, single("", CodeInvalidUTF8, fmt.Sprintf("not valid UTF-8 at byte offset %d", off))
	}
	d := &decoder{data: data}
	d.skipWS()
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	d.skipWS()
	if d.pos != len(d.data) {
		return nil, single("", CodeTrailingData, fmt.Sprintf("unexpected data after the top-level value at byte offset %d", d.pos))
	}
	return v, nil
}

type decoder struct {
	data  []byte
	pos   int
	path  []string
	depth int
}

func (d *decoder) ptr() string { return pointer(d.path) }

func (d *decoder) syntax(what string) *Error {
	if d.pos >= len(d.data) {
		return single(d.ptr(), CodeInvalidJSON, "unexpected end of input")
	}
	return single(d.ptr(), CodeInvalidJSON, fmt.Sprintf("%s at byte offset %d", what, d.pos))
}

func (d *decoder) skipWS() {
	for d.pos < len(d.data) {
		switch d.data[d.pos] {
		case ' ', '\t', '\n', '\r':
			d.pos++
		default:
			return
		}
	}
}

func (d *decoder) literal(word string, v any) (any, *Error) {
	if !bytes.HasPrefix(d.data[d.pos:], []byte(word)) {
		return nil, d.syntax("invalid literal")
	}
	d.pos += len(word)
	return v, nil
}

func (d *decoder) value() (any, *Error) {
	if d.pos >= len(d.data) {
		return nil, d.syntax("")
	}
	switch c := d.data[d.pos]; {
	case c == '{':
		return d.object()
	case c == '[':
		return d.array()
	case c == '"':
		return d.str()
	case c == 't':
		return d.literal("true", true)
	case c == 'f':
		return d.literal("false", false)
	case c == 'n':
		return d.literal("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return d.number()
	default:
		return nil, d.syntax("unexpected character")
	}
}

func (d *decoder) enter() *Error {
	d.depth++
	if d.depth > MaxDepth {
		return single(d.ptr(), CodeTooDeep, fmt.Sprintf("nesting deeper than %d levels", MaxDepth))
	}
	return nil
}

func (d *decoder) object() (any, *Error) {
	if err := d.enter(); err != nil {
		return nil, err
	}
	d.pos++ // '{'
	obj := map[string]any{}
	d.skipWS()
	if d.pos < len(d.data) && d.data[d.pos] == '}' {
		d.pos++
		d.depth--
		return obj, nil
	}
	for {
		d.skipWS()
		if d.pos >= len(d.data) || d.data[d.pos] != '"' {
			return nil, d.syntax("expected a string key")
		}
		k, err := d.str()
		if err != nil {
			return nil, err
		}
		key := k.(string)
		if _, dup := obj[key]; dup {
			d.path = append(d.path, key)
			p := d.ptr()
			d.path = d.path[:len(d.path)-1]
			return nil, single(p, CodeDuplicateKey, "duplicate key "+excerpt(key))
		}
		d.skipWS()
		if d.pos >= len(d.data) || d.data[d.pos] != ':' {
			return nil, d.syntax("expected ':'")
		}
		d.pos++
		d.skipWS()
		d.path = append(d.path, key)
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		d.path = d.path[:len(d.path)-1]
		obj[key] = v
		d.skipWS()
		if d.pos < len(d.data) && d.data[d.pos] == ',' {
			d.pos++
			continue
		}
		if d.pos < len(d.data) && d.data[d.pos] == '}' {
			d.pos++
			d.depth--
			return obj, nil
		}
		return nil, d.syntax("expected ',' or '}'")
	}
}

func (d *decoder) array() (any, *Error) {
	if err := d.enter(); err != nil {
		return nil, err
	}
	d.pos++ // '['
	arr := []any{}
	d.skipWS()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
		d.depth--
		return arr, nil
	}
	for {
		d.skipWS()
		d.path = append(d.path, strconv.Itoa(len(arr)))
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		d.path = d.path[:len(d.path)-1]
		arr = append(arr, v)
		d.skipWS()
		if d.pos < len(d.data) && d.data[d.pos] == ',' {
			d.pos++
			continue
		}
		if d.pos < len(d.data) && d.data[d.pos] == ']' {
			d.pos++
			d.depth--
			return arr, nil
		}
		return nil, d.syntax("expected ',' or ']'")
	}
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// str parses a string starting at '"'. The input is already valid UTF-8.
func (d *decoder) str() (any, *Error) {
	d.pos++ // opening quote
	start := d.pos
	for d.pos < len(d.data) {
		c := d.data[d.pos]
		if c == '"' {
			s := string(d.data[start:d.pos])
			d.pos++
			return s, nil
		}
		if c == '\\' {
			break
		}
		if c < 0x20 {
			return nil, d.syntax("control character in string")
		}
		d.pos++
	}
	b := append([]byte(nil), d.data[start:d.pos]...)
	for d.pos < len(d.data) {
		c := d.data[d.pos]
		switch {
		case c == '"':
			d.pos++
			return string(b), nil
		case c < 0x20:
			return nil, d.syntax("control character in string")
		case c != '\\':
			b = append(b, c)
			d.pos++
			continue
		}
		if d.pos+1 >= len(d.data) {
			d.pos = len(d.data)
			return nil, d.syntax("")
		}
		esc := d.data[d.pos+1]
		d.pos += 2
		switch esc {
		case '"', '\\', '/':
			b = append(b, esc)
		case 'b':
			b = append(b, '\b')
		case 'f':
			b = append(b, '\f')
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 't':
			b = append(b, '\t')
		case 'u':
			r, ok := hex4(d.data[d.pos:])
			if !ok {
				return nil, d.syntax("invalid \\u escape")
			}
			d.pos += 4
			if utf16.IsSurrogate(r) {
				r2, ok2 := rune(0), false
				if r < 0xDC00 && d.pos+1 < len(d.data) && d.data[d.pos] == '\\' && d.data[d.pos+1] == 'u' {
					if r2, ok2 = hex4(d.data[d.pos+2:]); !ok2 {
						d.pos += 2
						return nil, d.syntax("invalid \\u escape")
					}
				}
				if !ok2 || r2 < 0xDC00 || r2 > 0xDFFF {
					return nil, single(d.ptr(), CodeLoneSurrogate, "unpaired UTF-16 surrogate escape in string")
				}
				d.pos += 6
				r = utf16.DecodeRune(r, r2)
			}
			b = utf8.AppendRune(b, r)
		default:
			d.pos--
			return nil, d.syntax("invalid escape")
		}
	}
	return nil, d.syntax("")
}

func (d *decoder) number() (any, *Error) {
	start := d.pos
	if d.data[d.pos] == '-' {
		d.pos++
	}
	digits := func() int {
		n := 0
		for d.pos < len(d.data) && d.data[d.pos] >= '0' && d.data[d.pos] <= '9' {
			d.pos++
			n++
		}
		return n
	}
	switch {
	case d.pos < len(d.data) && d.data[d.pos] == '0':
		d.pos++
	case digits() == 0:
		return nil, d.syntax("invalid number")
	}
	if d.pos < len(d.data) && d.data[d.pos] == '.' {
		d.pos++
		if digits() == 0 {
			return nil, d.syntax("invalid number")
		}
	}
	if d.pos < len(d.data) && (d.data[d.pos] == 'e' || d.data[d.pos] == 'E') {
		d.pos++
		if d.pos < len(d.data) && (d.data[d.pos] == '+' || d.data[d.pos] == '-') {
			d.pos++
		}
		if digits() == 0 {
			return nil, d.syntax("invalid number")
		}
	}
	canon, code := classifyNumber(string(d.data[start:d.pos]))
	switch code {
	case CodeNumberNotInteger:
		return nil, single(d.ptr(), code, "numbers in a manifest must be integers")
	case CodeNumberOutOfRange:
		return nil, single(d.ptr(), code, fmt.Sprintf("number outside ±%d", int64(MaxSafeInteger)))
	}
	return json.Number(canon), nil
}

// classifyNumber takes a token that already matches the RFC 8259 number
// grammar. It returns the canonical decimal integer text ("-0" becomes "0",
// "1.0e1" becomes "10") or one of CodeNumberNotInteger, CodeNumberOutOfRange.
// It works on the digit string only, so huge exponents cost nothing.
// tools/manifest_check.py implements the same algorithm (classify_number).
func classifyNumber(tok string) (string, string) {
	neg := strings.HasPrefix(tok, "-")
	tok = strings.TrimPrefix(tok, "-")
	mant, exp := tok, ""
	if i := strings.IndexAny(tok, "eE"); i >= 0 {
		mant, exp = tok[:i], tok[i+1:]
	}
	intPart, frac := mant, ""
	if i := strings.IndexByte(mant, '.'); i >= 0 {
		intPart, frac = mant[:i], mant[i+1:]
	}
	digits := strings.TrimLeft(intPart+frac, "0")
	if digits == "" {
		return "0", ""
	}
	trimmed := strings.TrimRight(digits, "0")
	// value = trimmed * 10^shift
	shift := int64(len(digits)-len(trimmed)) - int64(len(frac))
	expNeg := strings.HasPrefix(exp, "-")
	exp = strings.TrimLeft(strings.TrimLeft(exp, "+-"), "0")
	if len(exp) > 7 { // |exponent| >= 10^7: far outside any integer we accept
		if expNeg {
			return "", CodeNumberNotInteger
		}
		return "", CodeNumberOutOfRange
	}
	if exp != "" {
		e, _ := strconv.ParseInt(exp, 10, 64)
		if expNeg {
			e = -e
		}
		shift += e
	}
	if shift < 0 {
		return "", CodeNumberNotInteger
	}
	if int64(len(trimmed))+shift > 16 {
		return "", CodeNumberOutOfRange
	}
	v, _ := strconv.ParseInt(trimmed+strings.Repeat("0", int(shift)), 10, 64)
	if v > MaxSafeInteger {
		return "", CodeNumberOutOfRange
	}
	if neg {
		v = -v
	}
	return strconv.FormatInt(v, 10), ""
}
