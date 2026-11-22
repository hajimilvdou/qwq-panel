// SPDX-License-Identifier: Apache-2.0

package strictjson

import (
	"strings"
	"testing"
)

// ======================== 固定类型测试夹具 ========================
type fixture struct {
	Enabled *bool    `json:"enabled,omitempty"`
	Port    int      `json:"port"`
	Names   []string `json:"names"`
	Child   *fixture `json:"child,omitempty"`
	Ignored string   `json:"-"`
}

var testLimits = Limits{MaxBytes: 1 << 20, MaxItems: 2, MaxDepth: 3}

func TestDecodeExactTagsAndEmptyArray(t *testing.T) {
	var got fixture
	if err := Decode([]byte(`{"enabled":false,"port":1024,"names":[]}`), &got, testLimits); err != nil {
		t.Fatal(err)
	}
	if got.Enabled == nil || *got.Enabled || got.Port != 1024 || got.Names == nil {
		t.Fatal("显式 false、整数或空数组未保留")
	}
	var missing fixture
	if err := Decode([]byte(`{}`), &missing, testLimits); err != nil || missing.Enabled != nil {
		t.Fatal("缺失指针应保留 nil")
	}
}

func TestDecodeRejectsAmbiguousAndUnboundedInput(t *testing.T) {
	cases := []struct{ input, pointer, code string }{
		{`{"Enabled":false}`, "/Enabled", "UNKNOWN_FIELD"},
		{`{"ignored":"value"}`, "/ignored", "UNKNOWN_FIELD"},
		{`{"enabled":false,"enab\u006ced":true}`, "/enabled", "DUPLICATE_KEY"},
		{`{"enabled":null}`, "/enabled", "TYPE"},
		{`{"port":1024.0}`, "/port", "TYPE"},
		{`{"port":9223372036854775808}`, "/port", "TYPE"},
		{`{"names":["a","b","c"]}`, "/names", "SIZE"},
		{`{"child":{"child":{"child":{"port":1024}}}}`, "/child/child/child/port", "DEPTH"},
		{`{"a~/b":false}`, "/a~0~1b", "UNKNOWN_FIELD"},
		{`{} {}`, "", "TRAILING_JSON"},
		{`{} invalid`, "", "TRAILING_JSON"},
		{`[]`, "", "TYPE"},
		{`null`, "", "TYPE"},
		{`{`, "", "JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			var dst fixture
			err := Decode([]byte(tc.input), &dst, testLimits)
			if err == nil || err.Pointer != tc.pointer || err.Code != tc.code {
				t.Fatalf("错误定位不符：%+v", err)
			}
		})
	}
	var dst fixture
	if err := Decode([]byte(strings.Repeat(" ", testLimits.MaxBytes+1)), &dst, testLimits); err == nil || err.Code != "SIZE" {
		t.Fatal("未限制输入字节数")
	}
	if err := Decode([]byte{0xff}, &dst, testLimits); err == nil || err.Code != "UTF8" {
		t.Fatal("无效 UTF-8 未拒绝")
	}
}

func TestDecodeRejectsUnsupportedTargets(t *testing.T) {
	for _, dst := range []any{nil, fixture{}, (*fixture)(nil), new(map[string]string)} {
		if err := Decode([]byte(`{}`), dst, testLimits); err == nil || err.Code != "TYPE" {
			t.Fatal("自由目标或 nil 未拒绝")
		}
	}
	type unsupported struct {
		Value any `json:"value"`
	}
	if err := Decode([]byte(`{"value":"CANARY"}`), &unsupported{}, testLimits); err == nil || err.Pointer != "/value" || strings.Contains(err.Error(), "CANARY") {
		t.Fatal("接口字段或错误脱敏未受控")
	}
}
