// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ======================== 假引用测试夹具 ========================
// 所有引用只用于结构校验，不对应数据库秘密，也不包含私钥或 UUID 明文。
const testJSON = `{
  "schema_version":"1","enabled":true,
  "inbound":{"id":"main","listen":"0.0.0.0","port":10443,
    "protocol":"vless","transport":"raw","flow":"xtls-rprx-vision",
    "security":{"mode":"reality","target":"example.com:443",
      "server_names":["example.com"],"private_key":{"$secret":"sec_00000000000000000000000000"},
      "short_ids":["0123456789abcdef"]},
    "users":[{"id":"alice","uuid":{"$secret":"sec_00000000000000000000000001"}}]},
  "outbound":{"type":"direct"}
}`

func assertPointer(t *testing.T, err error, pointer string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "INVALID_INTENT" {
		t.Fatalf("需要 INVALID_INTENT，实际错误：%v", err)
	}
	for _, violation := range failure.Violations {
		if violation.Pointer == pointer {
			return
		}
	}
	t.Fatalf("未定位到 %q：%+v", pointer, failure.Violations)
}

func TestDecodeStrict(t *testing.T) {
	cases := []struct{ name, old, replacement, pointer string }{
		{"顶层未知字段", `"enabled":true`, `"enabled":true,"extra":1`, "/extra"},
		{"大小写不等价", `"enabled":true`, `"Enabled":true`, "/Enabled"},
		{"入站未知字段", `"id":"main"`, `"id":"main","clients":[]`, "/inbound/clients"},
		{"安全未知字段", `"mode":"reality"`, `"mode":"reality","dest":"unused"`, "/inbound/security/dest"},
		{"用户未知字段", `"id":"alice"`, `"id":"alice","email":"unused"`, "/inbound/users/0/email"},
		{"引用未知字段", `"$secret":"sec_00000000000000000000000001"`, `"$secret":"sec_00000000000000000000000001","extra":true`, "/inbound/users/0/uuid/extra"},
		{"出站未知字段", `"type":"direct"`, `"type":"direct","address":"unused"`, "/outbound/address"},
		{"顶层重复键", `"enabled":true`, `"enabled":true,"enabled":false`, "/enabled"},
		{"转义重复键", `"enabled":true`, `"enabled":true,"enab\u006ced":false`, "/enabled"},
		{"入站重复键", `"id":"main"`, `"id":"main","id":"other"`, "/inbound/id"},
		{"安全重复键", `"mode":"reality"`, `"mode":"reality","mode":"reality"`, "/inbound/security/mode"},
		{"用户重复键", `"id":"alice"`, `"id":"alice","id":"bob"`, "/inbound/users/0/id"},
		{"引用重复键", `"$secret":"sec_00000000000000000000000001"`, `"$secret":"sec_00000000000000000000000001","$secret":"unused"`, "/inbound/users/0/uuid/$secret"},
		{"出站重复键", `"type":"direct"`, `"type":"direct","type":"direct"`, "/outbound/type"},
		{"指针转义", `"enabled":true`, `"enabled":true,"a~/b":false`, "/a~0~1b"},
		{"布尔类型错误", `"enabled":true`, `"enabled":"true"`, "/enabled"},
		{"空布尔", `"enabled":true`, `"enabled":null`, "/enabled"},
		{"空入站", `"inbound":{`, `"inbound":null,"unused":{`, "/inbound"},
		{"非整数端口", `"port":10443`, `"port":10443.5`, "/inbound/port"},
		{"用户明文秘密", `{"$secret":"sec_00000000000000000000000001"}`, `"CANARY_SECRET"`, "/inbound/users/0/uuid"},
		{"私钥明文秘密", `{"$secret":"sec_00000000000000000000000000"}`, `"CANARY_SECRET"`, "/inbound/security/private_key"},
		{"原生入站数组", `"inbound":{`, `"inbound":[],"unused":{`, "/inbound"},
		{"base 拒绝扩展", `"enabled":true`, `"enabled":true,"xray":{"mark":{"version":"1"}}`, "/xray"},
		{"base 拒绝 mark", `"id":"alice"`, `"id":"alice","mark":20736`, "/inbound/users/0/mark"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(strings.Replace(testJSON, tc.old, tc.replacement, 1)))
			assertPointer(t, err, tc.pointer)
			if strings.Contains(fmt.Sprint(err), "CANARY_SECRET") {
				t.Fatal("错误泄漏了输入值")
			}
		})
	}
}

func TestDecodeDocumentBounds(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(testJSON + `{}`), []byte(testJSON + ` true`), []byte(`{`),
		[]byte(`[]`), []byte(`null`), []byte(strings.Repeat(" ", MaxSize+1)),
		append([]byte(`{"schema_version":"`), 0xff),
	} {
		_, err := Decode(data)
		assertPointer(t, err, "")
	}
	intent, err := Decode([]byte(testJSON + " \n\t"))
	if err != nil || Validate(intent) != nil {
		t.Fatalf("合法尾随空白被拒绝：%v", err)
	}
}

func TestSecretFormattingRedacts(t *testing.T) {
	intent, err := Decode([]byte(testJSON))
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		for _, value := range []any{intent, *intent, intent.Inbound.Security.PrivateKey, intent.Inbound.Users[0]} {
			if strings.Contains(fmt.Sprintf(format, value), "sec_") {
				t.Errorf("格式 %s 泄漏了秘密引用", format)
			}
		}
	}
}

func TestDecodeRequiredEnabled(t *testing.T) {
	missing, err := Decode([]byte(strings.Replace(testJSON, `,"enabled":true`, "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	assertPointer(t, Validate(missing), "/enabled")
	disabled, err := Decode([]byte(strings.Replace(testJSON, `"enabled":true`, `"enabled":false`, 1)))
	if err != nil || disabled.Enabled == nil || *disabled.Enabled {
		t.Fatalf("显式 false 未被保留：%v", err)
	}
	if err := Validate(disabled); err != nil {
		t.Fatal(err)
	}
}

// ======================== v1 冻结错误语义 ========================
// 内部解码器复用后仍返回原领域类型、代码、路径与中文规则。
func TestDecodeFrozenFailureCodes(t *testing.T) {
	cases := []struct{ data, pointer, code, message string }{
		{`{"Enabled":false}`, "/Enabled", "UNKNOWN_FIELD", "契约未声明此字段"},
		{`{"enabled":true,"enab\u006ced":false}`, "/enabled", "DUPLICATE_KEY", "对象字段不能重复"},
		{`{"enabled":null}`, "/enabled", "TYPE", "字段不能为 null"},
		{`{"inbound":{"port":9223372036854775808}}`, "/inbound/port", "TYPE", "字段必须是可表示的整数"},
		{`{} {}`, "", "TRAILING_JSON", "配置必须恰好包含一个 JSON 对象"},
	}
	for _, tc := range cases {
		_, err := Decode([]byte(tc.data))
		var failure *Error
		if !errors.As(err, &failure) || failure.Code != "INVALID_INTENT" || len(failure.Violations) != 1 {
			t.Fatalf("v1 错误结构改变：%v", err)
		}
		got := failure.Violations[0]
		if got.Pointer != tc.pointer || got.Code != tc.code || got.Message != tc.message {
			t.Fatalf("v1 错误语义改变：%+v", got)
		}
	}
}
