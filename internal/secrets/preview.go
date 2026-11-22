// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 字符串秘密的纯候选校验，不创建持久引用 ========================

// ValidateWithSecretReferences 复用 schema walker，将新字符串秘密投影成语法
// 引用后调用完整候选校验器。已有引用保持身份；不访问 Store、DB 或熵源。
// 调用边界须先检查原文的大小、重复字段和完整业务形状；投影只能供校验使用。
func ValidateWithSecretReferences(schema, config []byte, validate func([]byte) error) error {
	if validate == nil || len(schema) == 0 || len(schema) > 1<<20 || len(config) == 0 || len(config) > 1<<20 {
		return problem.New(problem.ValidationFailed, "秘密预演需要有界 schema、配置和完整校验器。")
	}
	doc, err := decodeJSON(schema)
	if err != nil {
		return problem.New(problem.ValidationFailed, "秘密预演的 schema 无效。")
	}
	instance, err := decodeJSON(config)
	if err != nil {
		return problem.New(problem.ValidationFailed, "秘密预演的配置文档无效。")
	}
	w := &walker{root: doc, seen: make(map[string]bool), out: make(map[string]bool)}
	if err := w.walk(doc, instance, "", "", 0); err != nil {
		return schemaFailure(err)
	}
	pending, err := collectSecrets(instance, "", w.out)
	if err != nil {
		return err
	}
	defer func() {
		for i := range pending {
			clear(pending[i].value)
		}
	}()
	refs := make(map[string]Ref, len(pending))
	for _, item := range pending {
		value, err := decodeJSON(item.value)
		if err != nil {
			return problem.New(problem.ValidationFailed, "秘密预演的敏感字段无效。")
		}
		if existing, valid := RefFromObject(value); valid {
			refs[item.pointer] = existing
			continue
		}
		plain, valid := value.(string)
		if !valid || plain == "" {
			return problem.New(problem.ValidationFailed, "配置秘密必须是非空字符串或有效的既有引用。")
		}
		// 固定 ID 仅满足语法校验，不存在新建/查找秘密或授予消费权限的行为。
		refs[item.pointer] = Ref("sec_00000000000000000000000000")
	}
	projected, err := json.Marshal(replaceWithRefs(instance, refs))
	if err != nil {
		return problem.New(problem.ValidationFailed, "配置候选无法编码。")
	}
	defer clear(projected)
	return validate(projected)
}
