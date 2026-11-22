// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/qwq-panel/qwq/internal/secrets"
)

// TestHostSecretRevealerPreservesExtractedJSON 使用真实 SQLite 和加密存储固定 ABI。
// 宿主只返回存储的 JSON 值；字符串、对象和数组的解释留给对应业务消费者。
func TestHostSecretRevealerPreservesExtractedJSON(t *testing.T) {
	ctx := t.Context()
	db := testDB(t)
	store := testSecrets(t, db)
	revealer := &hostSecretRevealer{
		operations: configSecretDispatch{reader: runningFor("alpha", "op_1")}, secrets: store,
		pluginID: "alpha", instanceID: "default", nodeID: "local",
	}
	schema := []byte(`{"type":"object","properties":{"value":{"x-secret":true}}}`)
	for name, input := range map[string]string{
		"string": `"contract-test-value"`, "escaped string": `"line\nslash\\quote\""`,
		"object": `{"nested":"contract-test-value"}`, "array": `["value",1]`, "null": `null`,
	} {
		t.Run(name, func(t *testing.T) {
			_, extracted, err := store.ExtractSecrets(ctx, schema, []byte(`{"value":`+input+`}`), secrets.ExtractOptions{
				Owner: "plugins/alpha", Purpose: pluginSecretPurpose,
			})
			if err != nil || len(extracted) != 1 {
				t.Fatal("real config secret extraction failed")
			}
			value, err := revealer.Reveal(ctx, string(extracted[0].Ref), "op_1", []string{"config"})
			defer clear(value)
			if err != nil {
				t.Fatal("owned dispatched config secret reveal failed")
			}
			var decoded any
			if json.Unmarshal([]byte(input), &decoded) != nil {
				t.Fatal("invalid test JSON")
			}
			expected, err := json.Marshal(decoded)
			defer clear(expected)
			if err != nil || !bytes.Equal(value, expected) {
				t.Fatal("host changed the stored JSON secret representation")
			}
		})
	}
}
