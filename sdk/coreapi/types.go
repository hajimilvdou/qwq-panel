// SPDX-License-Identifier: Apache-2.0

package coreapi

import "fmt"

// ======================== 契约与资源上限 ========================
const (
	// MaxSize 与宿主 plugin_configs 的 1 MiB 快照上限一致。
	MaxSize = 1 << 20
	// MaxUsers 是单入站允许的用户数量。
	MaxUsers = 256
	// MaxNames 是 server_names / short_ids 的数量上限。
	MaxNames = 8
	// MaxDNSNameLength 是 DNS 名的文本长度上限。
	MaxDNSNameLength = 253
)

// Intent 是完整期望快照。Enabled 指针区分必填字段缺失与显式 false。
type Intent struct {
	SchemaVersion string    `json:"schema_version"`
	Enabled       *bool     `json:"enabled"`
	Inbound       *Inbound  `json:"inbound"`
	Outbound      *Outbound `json:"outbound"`
}

// Inbound 定义唯一入站；稳定 ID 与原生 tag 分离。
type Inbound struct {
	ID        string   `json:"id"`
	Listen    string   `json:"listen"`
	Port      int      `json:"port"`
	Protocol  string   `json:"protocol"`
	Transport string   `json:"transport"`
	Flow      string   `json:"flow"`
	Security  *Reality `json:"security"`
	Users     []User   `json:"users"`
}

// Reality 只保存目标、SNI、short ID 和私钥引用，不保存私钥明文。
type Reality struct {
	Mode        string    `json:"mode"`
	Target      string    `json:"target"`
	ServerNames []string  `json:"server_names"`
	PrivateKey  SecretRef `json:"private_key"`
	ShortIDs    []string  `json:"short_ids"`
}

// User 以稳定面板 ID 标识用户；UUID 仅接受宿主秘密引用。
type User struct {
	ID   string    `json:"id"`
	UUID SecretRef `json:"uuid"`
}

// Outbound 首版仅允许 direct，不暴露原生路由或任意上游。
type Outbound struct {
	Type string `json:"type"`
}

// SecretRef 是宿主提取后的严格引用对象。ID 不携带授权，且格式化时脱敏。
type SecretRef struct {
	ID string `json:"$secret"`
}

// String 防止普通格式化意外记录秘密引用。
func (SecretRef) String() string { return "[REDACTED]" }

// GoString 同样保护 %#v 的调试格式。
func (SecretRef) GoString() string { return "coreapi.SecretRef{[REDACTED]}" }

// String 仅报告契约名称，不输出完整配置或引用。
func (Intent) String() string { return "CoreIntent(v1)" }

// GoString 防止结构化调试输出展开完整配置。
func (Intent) GoString() string { return "coreapi.Intent{[REDACTED]}" }

// Violation 定位 RFC 6901 字段，消息只包含规则，不回显输入值。
type Violation struct {
	Pointer string `json:"pointer"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error 是稳定的 INVALID_INTENT 领域错误。
type Error struct {
	Code       string      `json:"code"`
	Violations []Violation `json:"violations"`
}

// Error 不展开输入内容；调用方可按需显示字段级 Violations。
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("coreapi: %s (%d 个字段错误)", e.Code, len(e.Violations))
}

func invalid(pointer, code, message string) *Error {
	return &Error{Code: "INVALID_INTENT", Violations: []Violation{{pointer, code, message}}}
}
