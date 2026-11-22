// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"errors"
	"testing"
)

// ======================== 假引用与三协议快照 ========================
// 引用只用于契约测试，不对应宿主秘密；TCP/UDP 可使用相同外部端口。
const fixtureJSON = `{
  "schema_version":"2","enabled":true,
  "profiles":[
    {"id":"v-main","enabled":true,"listen":"127.0.0.1","port":18443,"protocol":"vless",
     "users":[{"id":"alice","uuid":{"$secret":"sec_00000000000000000000000001"}}],
     "vless":{"transport":"raw","flow":"xtls-rprx-vision",
       "security":{"mode":"reality","target":"example.test:443","server_names":["example.test"],
       "private_key":{"$secret":"sec_00000000000000000000000000"},"short_ids":["ab"]}}},
    {"id":"h-main","enabled":true,"listen":"127.0.0.1","port":18443,"protocol":"hysteria2",
     "users":[{"id":"bob","auth":{"$secret":"sec_00000000000000000000000002"}}],
     "hysteria2":{"tls":{"binding_ref":"certbind_00000000000000000000000000","server_name":"proxy.example.test"}}},
    {"id":"s-main","enabled":true,"listen":"127.0.0.1","port":18444,"protocol":"shadowsocks2022",
     "users":[{"id":"carol","psk":{"$secret":"sec_00000000000000000000000004"}}],
     "shadowsocks2022":{"method":"2022-blake3-aes-128-gcm",
       "server_key":{"$secret":"sec_00000000000000000000000003"},"obfs":{"mode":"none"}}}
  ],
  "outbound":{"type":"direct"}
}`

func validIntent(t *testing.T) *Intent {
	t.Helper()
	intent, err := Decode([]byte(fixtureJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(intent); err != nil {
		t.Fatal(err)
	}
	return intent
}

func requireViolation(t *testing.T, err error, pointer, code string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "INVALID_INTENT" {
		t.Fatalf("需要 INVALID_INTENT，实际：%v", err)
	}
	for _, violation := range failure.Violations {
		if violation.Pointer == pointer && violation.Code == code {
			return
		}
	}
	t.Fatalf("缺少 %s/%s：%+v", pointer, code, failure.Violations)
}

func boolValue(value bool) *bool { return &value }
