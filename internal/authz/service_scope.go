// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"encoding/json"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 通用权限元数据；业务范围留在模块私有策略 ========================

const maxServiceScopeBytes = 64 << 10

// ServiceScope 收紧角色允许的动作、节点、精确资源及有效期，不支持通配。
// 四项同时成立才允许调用；缺失维度不能按宿主级请求跳过检查。
type ServiceScope struct {
	Actions   []string  `json:"actions"`
	NodeIDs   []string  `json:"node_ids"`
	Subjects  []string  `json:"subjects"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (ServiceScope) String() string   { return "authz.ServiceScope{[REDACTED]}" }
func (ServiceScope) GoString() string { return "authz.ServiceScope{[REDACTED]}" }

func invalidServiceScope(field string) error {
	pointer := "/scope"
	if field != "" {
		pointer += "/" + field
	}
	return problem.Validation(problem.Violation{Pointer: pointer, Code: "invalid",
		Message: "服务账号必须提供有界、精确的作用域与到期时间。"})
}

func validServiceValues(values []string, count, width int, accept func(string) bool) bool {
	if len(values) == 0 || len(values) > count {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if len(value) == 0 || len(value) > width || seen[value] || !accept(value) {
			return false
		}
		seen[value] = true
	}
	return true
}

func exactServicePath(value string) bool {
	if !actionPatternRe.MatchString(value) || strings.ContainsAny(value, "*\\") ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// Validate 检查持久权限形状；当前到期状态由每次认证和授权独立判断。
func (s ServiceScope) Validate() error {
	if !validServiceValues(s.Actions, 32, 200, exactServicePath) {
		return invalidServiceScope("actions")
	}
	if !validServiceValues(s.NodeIDs, 32, 64, nodeIDRe.MatchString) {
		return invalidServiceScope("node_ids")
	}
	if !validServiceValues(s.Subjects, 64, 512, exactServicePath) {
		return invalidServiceScope("subjects")
	}
	if s.ExpiresAt.IsZero() {
		return invalidServiceScope("expires_at")
	}
	return nil
}

// Allows 只匹配完整目标，不给空动作/节点/资源追加默认权限。
func (s ServiceScope) Allows(now time.Time, res Resource) bool {
	return s.Validate() == nil && now.Before(s.ExpiresAt) &&
		slices.Contains(s.Actions, res.Action) && slices.Contains(s.NodeIDs, res.NodeID) &&
		slices.Contains(s.Subjects, res.Subject)
}

func encodeServiceScope(scope *ServiceScope, now time.Time) (any, error) {
	if scope == nil {
		return nil, nil
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if !now.Before(scope.ExpiresAt) {
		return nil, invalidServiceScope("expires_at")
	}
	raw, err := json.Marshal(scope)
	if err != nil || len(raw) > maxServiceScopeBytes {
		return nil, invalidServiceScope("")
	}
	return string(raw), nil
}

// ======================== 严格持久解码；非空坏数据绝不退化为旧账号 ========================

func decodeServiceScope(raw string) (*ServiceScope, error) {
	if len(raw) == 0 || len(raw) > maxServiceScopeBytes {
		return nil, invalidServiceScope("")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, invalidServiceScope("")
	}
	scope := new(ServiceScope)
	seen := make(map[string]bool, 4)
	for decoder.More() {
		token, err := decoder.Token()
		field, ok := token.(string)
		if err != nil || !ok || seen[field] {
			return nil, invalidServiceScope("")
		}
		seen[field] = true
		switch field {
		case "actions":
			err = decoder.Decode(&scope.Actions)
		case "node_ids":
			err = decoder.Decode(&scope.NodeIDs)
		case "subjects":
			err = decoder.Decode(&scope.Subjects)
		case "expires_at":
			err = decoder.Decode(&scope.ExpiresAt)
		default:
			return nil, invalidServiceScope("")
		}
		if err != nil {
			return nil, invalidServiceScope(field)
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, invalidServiceScope("")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, invalidServiceScope("")
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	return scope, nil
}
