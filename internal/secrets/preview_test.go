// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"bytes"
	"errors"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 写入前只在内存投影字符串秘密 ========================

func TestValidateWithSecretReferencesPreservesExistingRefsAndClearsProjection(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"fresh":{"x-secret":true},"existing":{"writeOnly":true},"public":{"type":"string"}}}`)
	config := []byte(`{"fresh":"preview-only-value","existing":{"$secret":"sec_00000000000000000000000001"},"public":"visible"}`)
	before := bytes.Clone(config)
	var captured []byte
	called := 0
	err := ValidateWithSecretReferences(schema, config, func(projected []byte) error {
		called++
		captured = projected
		if bytes.Contains(projected, []byte("preview-only-value")) {
			t.Fatal("预演向验证器展开了原始秘密")
		}
		doc, err := decodeJSON(projected)
		if err != nil {
			return err
		}
		object := doc.(map[string]any)
		if _, valid := RefFromObject(object["fresh"]); !valid {
			t.Fatal("预演没有生成仅用于形状校验的引用")
		}
		ref, valid := RefFromObject(object["existing"])
		if !valid || string(ref) != "sec_00000000000000000000000001" || object["public"] != "visible" {
			t.Fatal("预演改变了已有引用或公开字段")
		}
		return nil
	})
	if err != nil || called != 1 || !bytes.Equal(config, before) {
		t.Fatalf("纯预演失败或修改原文档: %v", err)
	}
	if len(captured) == 0 || !bytes.Equal(captured, make([]byte, len(captured))) {
		t.Fatal("验证器返回后保留了可用投影缓冲")
	}
}

func TestValidateWithSecretReferencesRejectsWrongSecretShapesAndMissingValidator(t *testing.T) {
	schema := []byte(`{"properties":{"credential":{"x-secret":true}}}`)
	for _, value := range []string{`null`, `false`, `123`, `[]`, `{}`, `{"$secret":"invalid"}`, `""`} {
		called := false
		err := ValidateWithSecretReferences(schema, []byte(`{"credential":`+value+`}`), func([]byte) error { called = true; return nil })
		if !problem.HasCode(err, problem.ValidationFailed) || called {
			t.Fatalf("无效秘密形状进入候选验证器: %v", err)
		}
	}
	if err := ValidateWithSecretReferences(schema, []byte(`{"credential":"fixture"}`), nil); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("缺校验器时预演仍成功: %v", err)
	}
}

func TestValidateWithSecretReferencesPropagatesSchemaAndValidationErrors(t *testing.T) {
	sentinel := errors.New("candidate validation rejected")
	if err := ValidateWithSecretReferences([]byte(`{"properties":{"credential":{"x-secret":true}}}`), []byte(`{"credential":"fixture"}`), func([]byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal("预演吞掉了完整候选验证失败")
	}
	for _, schema := range []string{`{"$ref":"https://example.test/schema.json"}`, `{"properties":{"credential":{"x-secret":"true"}}}`} {
		called := false
		err := ValidateWithSecretReferences([]byte(schema), []byte(`{"credential":"fixture"}`), func([]byte) error { called = true; return nil })
		if !problem.HasCode(err, problem.ValidationFailed) || called {
			t.Fatalf("不支持的秘密 schema 静默通过: %v", err)
		}
	}
}
