// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeRejectsUnknownDuplicateAndNull(t *testing.T) {
	cases := []struct{ name, old, replacement, pointer, code string }{
		{"未知顶层", `"enabled":true`, `"enabled":true,"extra":1`, "/extra", "UNKNOWN_FIELD"},
		{"大小写回退", `"profiles":[`, `"Profiles":[`, "/Profiles", "UNKNOWN_FIELD"},
		{"转义重复键", `"enabled":true`, `"enabled":true,"enab\u006ced":false`, "/enabled", "DUPLICATE_KEY"},
		{"profile 重复键", `"id":"v-main"`, `"id":"v-main","id":"other"`, "/profiles/0/id", "DUPLICATE_KEY"},
		{"profile 未知键", `"id":"v-main"`, `"id":"v-main","command":"CANARY"`, "/profiles/0/command", "UNKNOWN_FIELD"},
		{"用户大小写", `"uuid":{`, `"UUID":{`, "/profiles/0/users/0/UUID", "UNKNOWN_FIELD"},
		{"TLS 路径注入", `"tls":{`, `"tls":{"certificate_file":"CANARY",`, "/profiles/1/hysteria2/tls/certificate_file", "UNKNOWN_FIELD"},
		{"任意认证 URL", `"hysteria2":{`, `"hysteria2":{"auth_url":"CANARY",`, "/profiles/1/hysteria2/auth_url", "UNKNOWN_FIELD"},
		{"任意 obfs argv", `"obfs":{"mode":"none"}`, `"obfs":{"mode":"none","args":[]}`, "/profiles/2/shadowsocks2022/obfs/args", "UNKNOWN_FIELD"},
		{"引用重复键", `"$secret":"sec_00000000000000000000000001"`, `"$secret":"sec_00000000000000000000000001","$secret":"CANARY"`, "/profiles/0/users/0/uuid/$secret", "DUPLICATE_KEY"},
		{"空布尔", `"enabled":true`, `"enabled":null`, "/enabled", "TYPE"},
		{"空联合", `"vless":{`, `"vless":null,"unused":{`, "/profiles/0/vless", "TYPE"},
		{"空 profiles", `"profiles":[`, `"profiles":null,"unused":[`, "/profiles", "TYPE"},
		{"非整数端口", `"port":18443`, `"port":18443.0`, "/profiles/0/port", "TYPE"},
		{"明文服务端秘密", `"server_key":{"$secret":"sec_00000000000000000000000003"}`, `"server_key":"CANARY"`, "/profiles/2/shadowsocks2022/server_key", "TYPE"},
		{"指针转义", `"enabled":true`, `"enabled":true,"a~/b":false`, "/a~0~1b", "UNKNOWN_FIELD"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(fixtureJSON, tc.old) {
				t.Fatal("替换目标不存在")
			}
			intent, err := Decode([]byte(strings.Replace(fixtureJSON, tc.old, tc.replacement, 1)))
			requireViolation(t, err, tc.pointer, tc.code)
			if intent != nil || strings.Contains(fmt.Sprint(err), "CANARY") {
				t.Fatal("返回了部分候选或错误泄漏输入值")
			}
		})
	}
}

func TestDecodeDocumentBounds(t *testing.T) {
	for _, tc := range []struct {
		data []byte
		code string
	}{
		{[]byte(fixtureJSON + " {}"), "TRAILING_JSON"},
		{[]byte(fixtureJSON + " true"), "TRAILING_JSON"},
		{[]byte(fixtureJSON + " invalid"), "TRAILING_JSON"},
		{[]byte("null"), "TYPE"},
		{[]byte("[]"), "TYPE"},
		{[]byte("{"), "JSON"},
		{[]byte{0xff}, "UTF8"},
		{[]byte(strings.Repeat(" ", MaxSize+1)), "SIZE"},
	} {
		_, err := Decode(tc.data)
		requireViolation(t, err, "", tc.code)
	}
	intent, err := Decode([]byte(fixtureJSON + " \n\t"))
	if err != nil || Validate(intent) != nil {
		t.Fatal("合法尾随空白未通过")
	}
}

func TestDecodeRequiredEnabledAndRoundTrip(t *testing.T) {
	for _, tc := range []struct{ old, replacement, pointer string }{
		{`"schema_version":"2","enabled":true,`, `"schema_version":"2",`, "/enabled"},
		{`"id":"v-main","enabled":true,`, `"id":"v-main",`, "/profiles/0/enabled"},
	} {
		intent, err := Decode([]byte(strings.Replace(fixtureJSON, tc.old, tc.replacement, 1)))
		if err != nil {
			t.Fatal(err)
		}
		requireViolation(t, Validate(intent), tc.pointer, "REQUIRED")
	}
	intent := validIntent(t)
	intent.Enabled = boolValue(false)
	intent.Profiles[0].Enabled = boolValue(false)
	data, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil || Validate(got) != nil || !reflect.DeepEqual(intent, got) {
		t.Fatal("可选联合、false 或引用的 JSON 往返改变了快照")
	}
}

func TestDecodeArrayBoundDoesNotTruncate(t *testing.T) {
	intent := validIntent(t)
	intent.Profiles = intent.Profiles[:1]
	ref := *intent.Profiles[0].Users[0].UUID
	intent.Profiles[0].Users = make([]User, MaxUsers+1)
	for index := range intent.Profiles[0].Users {
		intent.Profiles[0].Users[index] = User{ID: fmt.Sprintf("user%d", index), UUID: &ref}
	}
	data, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	requireViolation(t, err, "/profiles/0/users", "SIZE")
	if got != nil {
		t.Fatal("超长数组被截断后当作成功候选")
	}
}

func TestFormattingRedactsReferences(t *testing.T) {
	intent := validIntent(t)
	for _, format := range []string{"%v", "%+v", "%#v"} {
		values := []any{intent, *intent, intent.Profiles[0], intent.Profiles[1], intent.Profiles[2]}
		for _, profile := range intent.Profiles {
			values = append(values, profile.Users[0])
		}
		for _, value := range values {
			if strings.Contains(fmt.Sprintf(format, value), "sec_") {
				t.Fatalf("格式 %s 泄漏秘密引用", format)
			}
		}
	}
}

func FuzzDecodeDeterministic(f *testing.F) {
	for _, seed := range []string{fixtureJSON, `{}`, `null`, `{"enabled":true,"enab\u006ced":false}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		first, firstErr := Decode(data)
		second, secondErr := Decode(data)
		if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(firstErr, secondErr) {
			t.Fatal("同一文档的解码不确定")
		}
		if first != nil && !reflect.DeepEqual(Validate(first), Validate(first)) {
			t.Fatal("语义校验不确定")
		}
	})
}
