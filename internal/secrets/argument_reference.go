// SPDX-License-Identifier: AGPL-3.0-only

package secrets

// ======================== 原参数的敏感字段引用 ========================

// SensitiveArgumentReference 复用 schema walker 与受控引用校验；只接受原 schema
// 标记字段里的完整引用对象，不把普通字符串或未标记字段当成秘密授权。
func SensitiveArgumentReference(schema, args []byte, reference Ref) (bool, error) {
	if err := checkRef(reference); err != nil {
		return false, err
	}
	if len(schema) == 0 {
		return false, nil
	}
	doc, err := decodeJSON(schema)
	if err != nil {
		return false, schemaFailure(err)
	}
	value, err := decodeJSON(args)
	if err != nil {
		return false, schemaFailure(err)
	}
	w := &walker{root: doc, seen: make(map[string]bool), out: make(map[string]bool)}
	if err := w.walk(doc, value, "", "", 0); err != nil {
		return false, schemaFailure(err)
	}
	refs, err := inputReferences(value, w.out, true)
	if err != nil {
		return false, err
	}
	for _, ref := range refs {
		if ref == reference {
			return true, nil
		}
	}
	return false, nil
}
