// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactRefsPreservesPublicDataAndPrivateInput(t *testing.T) {
	input := json.RawMessage(`{"count":9007199254740993,"items":[{"password":{"$secret":"private-reference"}},null,true,"visible"],"empty":{}}`)
	original := bytes.Clone(input)
	out := RedactRefs(input)
	if !bytes.Equal(input, original) {
		t.Fatal("redaction modified private execution arguments")
	}
	if bytes.Contains(out, []byte("$secret")) || bytes.Contains(out, []byte("private-reference")) {
		t.Fatal("public JSON retained an internal reference")
	}
	if !bytes.Contains(out, []byte("9007199254740993")) || !bytes.Contains(out, []byte(`"visible"`)) {
		t.Fatal("public data or integer precision changed")
	}
	if !bytes.Equal(out, RedactRefs(out)) || !json.Valid(out) {
		t.Fatal("redaction is not stable valid JSON")
	}
}

func TestRedactRefsFailsClosed(t *testing.T) {
	for name, input := range map[string]string{
		"root reference":    `{"$secret":"private-reference"}`,
		"extra member":      `{"$secret":"private-reference","extra":"hidden"}`,
		"invalid reference": `{"$secret":123}`,
		"escaped key":       `{"\u0024secret":"private-reference"}`,
		"broken JSON":       `{"$secret":"private-reference"`,
		"trailing JSON":     `{} {"$secret":"private-reference"}`,
		"excessive depth":   strings.Repeat("[", maxSchemaDepth+2) + `{"$secret":"private-reference"}` + strings.Repeat("]", maxSchemaDepth+2),
	} {
		t.Run(name, func(t *testing.T) {
			if out := RedactRefs(json.RawMessage(input)); string(out) != `"[REDACTED]"` {
				t.Fatal("unsafe input did not fail closed")
			}
		})
	}
	if RedactRefs(nil) != nil {
		t.Fatal("an absent optional JSON field became present")
	}
	if string(RedactRefs(json.RawMessage("null"))) != "null" {
		t.Fatal("JSON null changed")
	}
}

func TestRedactRefsPreservesReplayBytesAndRemovesShadowedReferences(t *testing.T) {
	ordinary := json.RawMessage(" {\"z\":1,\"a\":2} \n")
	if !bytes.Equal(RedactRefs(ordinary), ordinary) {
		t.Fatal("a response without references changed its exact replay bytes")
	}
	for _, input := range []string{
		`{"args":{"password":{"$secret":"private-reference"}},"args":{}}`,
		`{"args":{"password":{"\u0024secret":"private-reference"}},"args":{}}`,
	} {
		out := RedactRefs(json.RawMessage(input))
		if !json.Valid(out) || bytes.Contains(out, []byte("private-reference")) {
			t.Fatal("a shadowed reference escaped through the original replay body")
		}
	}
}

func TestRedactArgumentsPreservesObjectContract(t *testing.T) {
	for _, raw := range []string{`{"$secret":"private-reference"}`, `{`, `["private-reference"]`, `null`} {
		var object map[string]any
		if out := RedactArguments(json.RawMessage(raw)); json.Unmarshal(out, &object) != nil || object["$redacted"] != true {
			t.Fatal("opaque public arguments violated the object contract")
		}
	}
	ordinary := json.RawMessage(`{"user":"alice","password":{"$secret":"private-reference"}}`)
	var object map[string]any
	if json.Unmarshal(RedactArguments(ordinary), &object) != nil || object["user"] != "alice" || object["password"] != "[REDACTED]" {
		t.Fatal("redacting argument objects changed ordinary fields")
	}
}
