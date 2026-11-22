// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/secrets"
)

// ======================== 公共序列化与私有执行参数分离 ========================

// MarshalJSON 隐藏计划参数里的内部引用；执行与 SQL 存储继续使用原 Args。
func (p Plan) MarshalJSON() ([]byte, error) {
	type publicPlan Plan
	out := publicPlan(p)
	out.Args = secrets.RedactArguments(p.Args)
	return json.Marshal(out)
}

// MarshalJSON 让审批正文、列表和幂等回放共用同一引用脱敏边界。
func (f ApprovalFacts) MarshalJSON() ([]byte, error) {
	type publicFacts ApprovalFacts
	out := publicFacts(f)
	out.Args = secrets.RedactArguments(f.Args)
	return json.Marshal(out)
}

// MarshalJSON 防止插件预览把引用复制到 before/after 后经审批或计划泄露。
func (c PlannedChange) MarshalJSON() ([]byte, error) {
	type publicChange PlannedChange
	out := publicChange(c)
	out.Before = secrets.RedactRefs(c.Before)
	out.After = secrets.RedactRefs(c.After)
	return json.Marshal(out)
}
