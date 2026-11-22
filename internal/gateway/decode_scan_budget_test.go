// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 原错误优先级：深度/结构检查不能被早期重复字段旁路 ========================

func TestJSONScanKeepsOriginalLimitPrecedence(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		code problem.Code
	}{
		{"duplicate-before-deep", `{"a":1,"a":2,"deep":[[[[0]]]]}`, problem.PayloadTooLarge},
		{"balanced-syntax-before-deep", `[[[[,]]]]`, problem.PayloadTooLarge},
		{"unclosed-deep", `[[[[0`, problem.ValidationFailed},
		{"unclosed-after-duplicate", `{"a":1,"a":2`, problem.ValidationFailed},
		{"quoted-brackets", `{"text":"[[[[[[[["}`, ""},
		{"sibling-depth", `{"left":[0],"right":[1]}`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := &http.Request{Body: io.NopCloser(bytes.NewBufferString(test.body))}
			var result json.RawMessage
			err := decodeJSON(request, 1024, 3, &result)
			if test.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !problem.HasCode(err, test.code) || len(result) != 0 {
				t.Fatalf("limit precedence = %v, result bytes %d, want %s before DTO writes", err, len(result), test.code)
			}
		})
	}
}

// ======================== 规范化名称与池复用：各请求和同级对象不能共享已见字段 ========================

func TestJSONMembersCanonicalUnicodeNames(t *testing.T) {
	for _, body := range []string{
		`{"\ud800":1,"\ufffd":2}`,
		`{"\ud83d\ude00":1,"😀":2}`,
		"{\"\xff\":1,\"\xfe\":2}",
	} {
		request := &http.Request{Body: io.NopCloser(strings.NewReader(body))}
		var result json.RawMessage
		err := decodeJSON(request, 1024, 64, &result)
		var invalid *problem.Error
		if !errors.As(err, &invalid) || invalid.Code != problem.ValidationFailed || len(invalid.Violations) != 1 ||
			invalid.Violations[0].Code != codeDuplicateKey || len(result) != 0 {
			t.Fatalf("canonical duplicate accepted: %v", err)
		}
	}
	for _, body := range []string{`{"\ud800":1}`, `{"\ud83d\ude00":1}`, "{\"\xff\":1}"} {
		request := &http.Request{Body: io.NopCloser(strings.NewReader(body))}
		var result json.RawMessage
		if err := decodeJSON(request, 1024, 64, &result); err != nil {
			t.Fatalf("original accepted Unicode value changed: %v", err)
		}
	}
}

func TestJSONMembersConcurrentRequestBoundaries(t *testing.T) {
	var workers sync.WaitGroup
	failures := make(chan error, 32)
	for worker := range 32 {
		workers.Go(func() {
			for round := range 20 {
				body := `{"left":{"name":"first"},"items":[{"name":"second"},{"name":"third"}]}`
				duplicate := (worker+round)%3 == 0
				if duplicate {
					body = `{"left":{"name":"first","name":"duplicate"}}`
				}
				request := &http.Request{Body: io.NopCloser(strings.NewReader(body))}
				var result json.RawMessage
				err := decodeJSON(request, 1024, 64, &result)
				if (!duplicate && err != nil) || (duplicate && (!problem.HasCode(err, problem.ValidationFailed) || len(result) != 0)) {
					failures <- fmt.Errorf("worker %d round %d: %v", worker, round, err)
					return
				}
			}
		})
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

// FuzzJSONMembersMatchLegacy 用原标准 Token 解码链作为独立行为参照。
// 比较真实拒绝码和 JSON Pointer，覆盖字节状态机容易漏掉的名称与层级组合。
func FuzzJSONMembersMatchLegacy(f *testing.F) {
	for _, body := range []string{
		`{}`, `[]`, `"scalar"`, `{"":"value","items":[{},[],null,1]}`,
		`{"a/b":{"~key":1,"\u007ekey":2}}`, `{"a":1,"a":2,"deep":[[[[0]]]]}`,
		`{"left":{"name":"first"},"right":{"name":"second"}}`, `{"\ud800":1,"\ufffd":2}`,
		"{\"\xff\":1,\"\xfe\":2}", `[[[[,]]]]`, `{"a":1,"a":2`,
	} {
		f.Add([]byte(body), uint8(3))
	}
	f.Fuzz(func(t *testing.T, body []byte, depth uint8) {
		if len(body) > 64<<10 {
			return
		}
		limit := int(depth % 33)
		actual, reference := validateJSONMembers(body, limit), validateInvalidJSONMembers(body, limit)
		if (actual == nil) != (reference == nil) {
			t.Fatalf("scan acceptance differs: actual %v, reference %v", actual, reference)
		}
		if actual != nil {
			got, want := problem.From(actual), problem.From(reference)
			if got.Code != want.Code || !reflect.DeepEqual(got.Violations, want.Violations) {
				t.Fatalf("scan rejection differs: actual %+v, reference %+v", got, want)
			}
		}
	})
}

// ======================== 真实插件 DTO 解码：记录吞吐和分配，不预设优化百分比 ========================

func BenchmarkDecodePluginJSON(b *testing.B) {
	for _, items := range []int{8, 64, 512} {
		b.Run(fmt.Sprintf("items-%d", items), func(b *testing.B) {
			rows := make([]map[string]any, items)
			for index := range rows {
				rows[index] = map[string]any{
					"name": fmt.Sprintf("item-%d", index), "enabled": true,
					"settings": map[string]any{"ratio": 1.25, "mode": "direct", "tags": []string{"local", "panel"}},
				}
			}
			body, err := json.Marshal(map[string]any{"id": "com.example.config", "config": map[string]any{"items": rows}})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for b.Loop() {
				var destination struct {
					ID     string          `json:"id"`
					Config json.RawMessage `json:"config"`
				}
				request := &http.Request{Body: io.NopCloser(bytes.NewReader(body))}
				if err := decodeJSON(request, 1<<20, 64, &destination); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
