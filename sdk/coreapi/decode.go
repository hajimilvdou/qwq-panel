// SPDX-License-Identifier: Apache-2.0

package coreapi

import "github.com/qwq-panel/qwq/sdk/internal/strictjson"

// Decode 解析一份强类型 Intent，拒绝未知字段、重复键、null 和尾随 JSON。
// 字段名必须与 JSON tag 精确匹配；错误消息不会回显不可信输入。
// Decode 不替代 Validate，尤其不会把缺失 enabled 解释为停用。
func Decode(data []byte) (*Intent, error) {
	var intent Intent
	if err := strictjson.Decode(data, &intent, strictjson.Limits{MaxBytes: MaxSize, MaxItems: MaxUsers, MaxDepth: 16}); err != nil {
		return nil, invalid(err.Pointer, err.Code, err.Message)
	}
	return &intent, nil
}

func pointer(parent, key string) string { return strictjson.Pointer(parent, key) }
