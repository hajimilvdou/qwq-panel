// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"encoding/json"
	"testing"
)

func TestSensitiveArgumentReferenceRequiresExactMarkedMember(t *testing.T) {
	ref := Ref("sec_00000000000000000000000001")
	schema := []byte(`{
		"type":"object",
		"$defs":{"credential":{"type":"string","writeOnly":true}},
		"properties":{
			"password":{"type":"string","writeOnly":true},
			"reference":{"$ref":"#/$defs/credential"},
			"composed":{"allOf":[{"type":"string"},{"x-secret":true}]},
			"plain":{},
			"items":{"type":"array","items":{"type":"object","properties":{"key":{"type":"string","x-secret":true}}}}
		}
	}`)
	for _, test := range []struct {
		name, args string
		want       bool
	}{
		{"marked", `{"password":{"$secret":"sec_00000000000000000000000001"}}`, true},
		{"local schema reference", `{"reference":{"$secret":"sec_00000000000000000000000001"}}`, true},
		{"composed marker", `{"composed":{"$secret":"sec_00000000000000000000000001"}}`, true},
		{"array member", `{"items":[{"key":{"$secret":"sec_00000000000000000000000001"}}]}`, true},
		{"string reference", `{"password":"sec_00000000000000000000000001"}`, false},
		{"unmarked", `{"plain":{"$secret":"sec_00000000000000000000000001"}}`, false},
		{"extra field", `{"password":{"$secret":"sec_00000000000000000000000001","owner":"foreign"}}`, false},
		{"different member", `{"password":{"$secret":"sec_00000000000000000000000002"}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			found, err := SensitiveArgumentReference(schema, []byte(test.args), ref)
			if found != test.want || (test.want && err != nil) {
				t.Fatal("the original sensitive reference membership was not enforced")
			}
		})
	}
	if found, err := SensitiveArgumentReference(nil, json.RawMessage(`{"password":{"$secret":"sec_00000000000000000000000001"}}`), ref); found || err != nil {
		t.Fatal("an undeclared secret schema authorized a reference")
	}
}
