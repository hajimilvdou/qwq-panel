// SPDX-License-Identifier: AGPL-3.0-only

// Package dns 管理授权 zone 的记录与 DNS-01 对账，提供商凭据只由宿主代用。
package dns

import (
	"context"
	"time"
)

// ======================== 受控提供商边界 ========================

type ProviderKind string

const (
	Cloudflare ProviderKind = "cloudflare"
	Aliyun     ProviderKind = "aliyun"
)

type RecordType string

const (
	A     RecordType = "A"
	AAAA  RecordType = "AAAA"
	CNAME RecordType = "CNAME"
	TXT   RecordType = "TXT"
)

// Supported 明确限制首期允许修改的记录类型。
func (t RecordType) Supported() bool { return t == A || t == AAAA || t == CNAME || t == TXT }

// Scope 来自宿主确认的资源注册表，不信任插件自报的 zone 名称或凭据版本。
type Scope struct {
	ProviderID string       `json:"provider_id"`
	Kind       ProviderKind `json:"kind"`
	ZoneID     string       `json:"zone_id"`
	ZoneName   string       `json:"zone_name"`
	Revision   string       `json:"scope_revision"`
}

// Caller 只能由宿主身份链构造，日志不展开 operation 或 owner 标识。
type Caller struct {
	OwnerID     string `json:"owner_id"`
	OperationID string `json:"operation_id"`
}

func (Caller) String() string   { return "dns.Caller{[REDACTED]}" }
func (Caller) GoString() string { return "dns.Caller{[REDACTED]}" }

type Access string

const (
	Read      Access = "read"
	Manage    Access = "manage"
	Reconcile Access = "reconcile"
	Challenge Access = "challenge"
	Cleanup   Access = "cleanup"
)

// Authorizer 每次调用都重新检查精确资源范围与撤权；缺失实现不能默认放行。
// Cleanup 可在原 operation 取消后清理已确认的本 owner attempt，但不能扩大权限。
type Authorizer interface {
	Authorize(context.Context, Caller, Scope, Access) error
}

// RecoveryAuthorizations 将普通记录对账固定到新 operation 已接受的原 attempt。
// 此接口只允许查询并保存收据，不提供外部 DNS Manage 或 CA cleanup 许可。
type RecoveryAuthorizations interface {
	AuthorizeRecoveryAttempt(context.Context, Caller, Scope, string) error
}

// Record 是规范化提供商记录；Revision 是该记录完整内容的指纹。
// 非首期类型只用于检测 CNAME 冲突，不提供增删改 operation。
type Record struct {
	ID        string     `json:"id,omitempty"`
	Type      RecordType `json:"type"`
	Name      string     `json:"name"`
	Value     string     `json:"value"`
	TTL       uint32     `json:"ttl"`
	Proxied   bool       `json:"proxied"`
	Revision  string     `json:"revision,omitempty"`
	ManagedBy string     `json:"managed_by,omitempty"`
	// ProviderRevision 纳入完整指纹，保护 comment/tags/priority/status 等远端元数据。
	// 此字段由真实适配器计算，公开写请求不能指定。
	ProviderRevision string `json:"provider_revision,omitempty"`
}

// Provider 仅在宿主受控后端实现；实例必须绑定固定提供商与凭据。
// 查询返回完整 zone 的记录以保护同名非首期类型；写操作不自动重试。
type Provider interface {
	List(context.Context, Scope) ([]Record, error)
	Create(context.Context, Scope, Record) (Record, error)
	Update(context.Context, Scope, Record, Record) (Record, error)
	Delete(context.Context, Scope, Record) error
}

// Providers 按已确认资源选择固定适配器，不接受 URL、任意 API 主机或请求模板。
type Providers interface {
	For(context.Context, Scope) (Provider, error)
}

type Snapshot struct {
	Scope       Scope     `json:"scope"`
	Records     []Record  `json:"records"`
	Revision    string    `json:"revision"`
	CollectedAt time.Time `json:"collected_at"`
}

type Action string

const (
	Create Action = "create"
	Update Action = "update"
	Delete Action = "delete"
)

type Change struct {
	Action                 Action `json:"action"`
	Record                 Record `json:"record"`
	ExpectedRecordRevision string `json:"expected_record_revision,omitempty"`
}

// Request 的 expected_revision 绑定提供商完整快照；attempt_id 绑定一次提交。
type Request struct {
	Caller           Caller `json:"caller"`
	Scope            Scope  `json:"scope"`
	AttemptID        string `json:"attempt_id"`
	ExpectedRevision string `json:"expected_revision"`
	Change           Change `json:"change"`
	CertificateID    string `json:"certificate_id,omitempty"`
}

type Plan struct {
	Before   *Record  `json:"before,omitempty"`
	After    *Record  `json:"after,omitempty"`
	Revision string   `json:"revision"`
	Warnings []string `json:"warnings"`
}

type AttemptState string

const (
	Submitted AttemptState = "submitted"
	Applied   AttemptState = "applied"
	Unknown   AttemptState = "unknown"
	Cleaned   AttemptState = "cleaned"
	Rejected  AttemptState = "rejected"
)

// Receipt 是公开执行结果；不包含 challenge 值、凭据引用或底层响应。
type Receipt struct {
	AttemptID string       `json:"attempt_id"`
	State     AttemptState `json:"state"`
	RecordID  string       `json:"record_id,omitempty"`
	Revision  string       `json:"revision,omitempty"`
	ErrorCode string       `json:"error_code,omitempty"`
}

// attempt 是私有写前日志，baseline IDs 用于识别本次新建记录。
type attempt struct {
	Request   Request      `json:"request"`
	Hash      string       `json:"request_hash"`
	Before    *Record      `json:"before,omitempty"`
	Baseline  []string     `json:"baseline_ids"`
	Record    *Record      `json:"owned_record,omitempty"`
	State     AttemptState `json:"state"`
	CreatedAt time.Time    `json:"created_at"`
	ExpiresAt time.Time    `json:"expires_at"`
	Challenge bool         `json:"challenge"`
	Marker    string       `json:"marker"`
	ErrorCode string       `json:"error_code,omitempty"`
	Cleaning  bool         `json:"cleaning"`
}

func (attempt) String() string   { return "dns.attempt{[REDACTED]}" }
func (attempt) GoString() string { return "dns.attempt{[REDACTED]}" }

// journal 将当前提交与有界收据保存在同一 CAS 键中。
type journal struct {
	Active   *attempt  `json:"active,omitempty"`
	Receipts []attempt `json:"receipts"`
}
