// SPDX-License-Identifier: Apache-2.0

package coreapi

import "github.com/qwq-panel/qwq/sdk/internal/strictjson"

// Decode 只接受 v2 的严格字段形状；版本与协议互斥规则由 Validate 检查。
// 缺失 enabled 保留 nil，其他协议不能通过未知字段或大小写回退混入。
func Decode(data []byte) (*Intent, error) {
	var intent Intent
	if err := strictjson.Decode(data, &intent, strictjson.Limits{MaxBytes: MaxSize, MaxItems: MaxUsers, MaxDepth: 16}); err != nil {
		return nil, invalid(err.Pointer, err.Code, err.Message)
	}
	return &intent, nil
}

func invalid(path, code, message string) *Error {
	return &Error{Code: "INVALID_INTENT", Violations: []Violation{{Pointer: path, Code: code, Message: message}}}
}
