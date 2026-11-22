// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 相同对象字段、转义名称与原限制的实际解码回归 ========================

func TestJSONMembersRejectDuplicateNamesAtEveryDepth(t *testing.T) {
	for _, test := range []struct{ name, body, pointer string }{
		{"top", `{"policy_id":"first","policy_id":"other"}`, "/policy_id"},
		{"escaped", `{"policy_id":"first","policy\u005fid":"other"}`, "/policy_id"},
		{"array", `{"items":[{"scope":1,"scope":2}]}`, "/items/0/scope"},
		{"pointer", `{"a/b":{"~key":1,"\u007ekey":2}}`, "/a~1b/~0key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			var decoded any
			err := decodeJSON(request, 1<<20, 64, &decoded)
			var invalid *problem.Error
			if !errors.As(err, &invalid) || invalid.Code != problem.ValidationFailed || len(invalid.Violations) != 1 ||
				invalid.Violations[0].Code != codeDuplicateKey || invalid.Violations[0].Pointer != test.pointer {
				t.Fatalf("重复字段没有在预期路径拒绝: %v", err)
			}
			if decoded != nil {
				t.Fatal("重复字段拒绝前已经写入 DTO")
			}
		})
	}
}

func TestJSONMembersPreserveValidValuesAndObjectBoundaries(t *testing.T) {
	for _, body := range []string{
		`{"items":[{"name":"first"},{"name":"second"}],"ratio":1.25,"value":null,"enabled":true}`,
		`{"left":{"name":"first"},"right":{"name":"second"},"text":"{ [ escaped \\\" ] }"}`,
		`[1,2.5,false,null,{"name":"value"}]`, `"scalar"`, `null`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		var decoded any
		if err := decodeJSON(request, 1<<20, 64, &decoded); err != nil {
			t.Fatalf("合法 JSON 行为被改变: %v", err)
		}
	}
}

func TestJSONMembersKeepSyntaxBytesAndDepthLimits(t *testing.T) {
	for _, test := range []struct {
		name, body string
		bytes      int64
		depth      int
		code       problem.Code
	}{
		{"trailing", `{"name":"value"}{}`, 1024, 64, problem.ValidationFailed},
		{"syntax", `{"name":}`, 1024, 64, problem.ValidationFailed},
		{"bytes", `{"name":"value"}`, 4, 64, problem.PayloadTooLarge},
		{"depth", `[[[[0]]]]`, 1024, 3, problem.PayloadTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			var decoded any
			if err := decodeJSON(request, test.bytes, test.depth, &decoded); !problem.HasCode(err, test.code) {
				t.Fatalf("原输入边界失效: %v", err)
			}
		})
	}
}
