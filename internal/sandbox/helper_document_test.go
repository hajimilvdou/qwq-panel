// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import "testing"

func TestDecodeHelperDocumentMultilineAndDuplicate(t *testing.T) {
	var doc struct {
		Name string `json:"name"`
	}
	if err := DecodeHelperDocument([]byte("{\n  \"name\": \"test\"\n}\n"), &doc); err != nil || doc.Name != "test" {
		t.Fatal("complete multiline JSON was not decoded")
	}
	for _, raw := range []string{`{"name":"a","name":"b"}`, `{"name":"a","unknown":true}`, `{"name":"a"} {}`} {
		if err := DecodeHelperDocument([]byte(raw), &doc); err == nil {
			t.Fatal("invalid complete document accepted")
		}
	}
}
