// SPDX-License-Identifier: Apache-2.0

// Package manifest parses and validates plugin package manifests
// (api/manifest/v1/manifest.schema.json, ARCH §5.3).
//
// Parse runs, in order, stopping at the first failing stage:
//
//  1. size: at most MaxSize bytes;
//  2. strict decode: valid UTF-8, RFC 8259 syntax, no duplicate keys at any
//     depth (compared after unescaping), no unpaired surrogate escapes, depth
//     at most MaxDepth, every number an integer within ±MaxSafeInteger, a
//     top-level object and nothing after it;
//  3. JSON Schema (Draft 2020-12, RE2 patterns, embedded schema only), which
//     also rejects unknown fields;
//  4. typed decode into Manifest with DisallowUnknownFields (second line of
//     defence; unreachable unless the struct and the schema disagree);
//  5. installer rules that the schema cannot express.
//
// Failures are reported as *Error with RFC 6901 pointers and stable codes.
// The shared fixture api/manifest/v1/testdata/cases.json pins the behaviour
// and is also run by tools/manifest_check.py.
//
// Packages are signed: hosts must use VerifyAndParse, which verifies the
// detached signature over the raw bytes before parsing (ARCH §6.2).
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Parse strictly decodes and validates raw manifest.json bytes. On failure
// the error is an *Error.
func Parse(raw []byte) (*Manifest, error) {
	if len(raw) > MaxSize {
		return nil, single("", CodeTooLarge, fmt.Sprintf("manifest is %d bytes, more than %d", len(raw), MaxSize))
	}
	tree, derr := decodeStrict(raw)
	if derr != nil {
		return nil, derr
	}
	if _, ok := tree.(map[string]any); !ok {
		return nil, single("", CodeNotObject, "top-level value must be an object")
	}
	if e := newError(validateSchema(tree)); e != nil {
		return nil, e
	}
	m, terr := decodeTyped(tree)
	if terr != nil {
		return nil, terr
	}
	if e := newError(installerRules(m)); e != nil {
		return nil, e
	}
	return m, nil
}

// decodeTyped re-encodes the validated tree and decodes it into Manifest.
// Going through the tree (not raw) means numbers are already canonical
// integers ("1.0" became "1"), which encoding/json requires for int64.
func decodeTyped(tree any) (*Manifest, *Error) {
	b, err := json.Marshal(tree)
	if err != nil {
		return nil, single("", CodeDecodeFailed, "re-encoding failed")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		// The message may name a field; quote and clip it like any input.
		return nil, single("", CodeDecodeFailed, "typed decode failed: "+excerpt(err.Error()))
	}
	return &m, nil
}
