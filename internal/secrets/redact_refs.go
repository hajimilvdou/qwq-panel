// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"bytes"
	"encoding/json"
	"io"
)

// ======================== 公开 JSON 的引用边界 ========================

// RedactRefs 递归隐藏内部秘密引用，保留普通字段和数字精度。
// 畸形 JSON、超深文档或包含保留键的畸形对象均关闭输出，避免回退到原文。
// 输入仅用于读取；私有执行参数和存储引用不会被修改。
func RedactRefs(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	value, err := decodeJSON(raw)
	if err != nil {
		return json.RawMessage(`"[REDACTED]"`)
	}
	value, ok := redactReferenceValue(value, 0)
	if !ok {
		return json.RawMessage(`"[REDACTED]"`)
	}
	if !hasReferenceToken(raw) {
		// 不含引用的幂等正文保留原字节；独立拷贝避免和私有参数共享可写切片。
		return bytes.Clone(raw)
	}
	out, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`"[REDACTED]"`)
	}
	return out
}

// RedactArguments 保持公共 args 的 object 契约；全对象敏感或损坏时只给出标记。
// 预览 before/after 允许任意 JSON，仍使用 RedactRefs 的普通占位字符串。
func RedactArguments(raw json.RawMessage) json.RawMessage {
	masked := RedactRefs(raw)
	if len(masked) > 0 && bytes.TrimSpace(masked)[0] != '{' {
		return json.RawMessage(`{"$redacted":true}`)
	}
	return masked
}

// hasReferenceToken 检查原始 token，防止重复 JSON 字段覆盖早先引用后回退到原文。
// 字符串恰为保留键时也走重新编码；只影响字节排列，不隐藏普通字符串值。
func hasReferenceToken(raw []byte) bool {
	if !bytes.Contains(raw, []byte(RefKey)) && !bytes.Contains(raw, []byte(`\u`)) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return false
		}
		if err != nil {
			return true
		}
		if text, ok := token.(string); ok && text == RefKey {
			return true
		}
	}
}

func redactReferenceValue(value any, depth int) (any, bool) {
	if depth > maxSchemaDepth {
		return nil, false
	}
	switch node := value.(type) {
	case map[string]any:
		if _, reserved := node[RefKey]; reserved {
			return redacted, true
		}
		for key, child := range node {
			masked, ok := redactReferenceValue(child, depth+1)
			if !ok {
				return nil, false
			}
			node[key] = masked
		}
	case []any:
		for index, child := range node {
			masked, ok := redactReferenceValue(child, depth+1)
			if !ok {
				return nil, false
			}
			node[index] = masked
		}
	}
	return value, true
}
