// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"strconv"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 外部引用与受控配置编辑 ========================

// RejectClientReferences 拒绝外部 operation/plan 入参预埋宿主秘密引用。
// 已存储 plan 的执行直接复用宿主保护后的参数，不经过这个客户端入口。
func RejectClientReferences(raw []byte) error {
	value, err := decodeJSON(raw)
	if err != nil {
		return problem.New(problem.ValidationFailed, "The arguments are not valid JSON.")
	}
	_, err = inputReferences(value, nil, false)
	return err
}

// inputReferences 只接受敏感字段上的完整引用对象；所有验证先于秘密落库。
// 是否保留引用由宿主入口显式选择，已有引用的归属随后在写事务内重查。
func inputReferences(value any, marked map[string]bool, allowExisting bool) (map[string]Ref, error) {
	refs := make(map[string]Ref)
	var walk func(any, string, int) error
	walk = func(value any, pointer string, depth int) error {
		if depth > maxSchemaDepth {
			return problem.New(problem.ValidationFailed, "The secret document is too deeply nested.")
		}
		switch node := value.(type) {
		case map[string]any:
			if _, reserved := node[RefKey]; reserved {
				ref, valid := RefFromObject(node)
				if !allowExisting || !marked[pointer] || !valid {
					return problem.Validation(problem.Violation{Pointer: pointer, Code: "RESERVED_SECRET_REFERENCE", Message: "Secret references are reserved for saved sensitive configuration fields."})
				}
				refs[pointer] = ref
				return nil
			}
			for key, child := range node {
				if err := walk(child, pointer+"/"+escapeToken(key), depth+1); err != nil {
					return err
				}
			}
		case []any:
			for index, child := range node {
				if err := walk(child, pointer+"/"+strconv.Itoa(index), depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(value, "", 0); err != nil {
		return nil, err
	}
	return refs, nil
}
