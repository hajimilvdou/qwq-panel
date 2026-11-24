// SPDX-License-Identifier: AGPL-3.0-only

// Package certificates 管理证书资源与精确 generation，材料与消费者权限由宿主确认。
package certificates

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 业务资源与受控能力接口 ========================

const MissingRevision = "absent"

// Caller 来自宿主身份链，不接受插件自报的 owner 或续期策略身份。
type Caller struct {
	OwnerID        string `json:"owner_id"`
	OperationID    string `json:"operation_id"`
	PolicyID       string `json:"policy_id,omitempty"`
	PolicyRevision string `json:"policy_revision,omitempty"`
}

func (Caller) String() string   { return "certificates.Caller{[REDACTED]}" }
func (Caller) GoString() string { return "certificates.Caller{[REDACTED]}" }

// Spec 的 SAN 集合与用途在续期时保持不变。
type Spec struct {
	SANs    []string               `json:"sans"`
	Purpose tlsmgr.MaterialPurpose `json:"purpose"`
}

type CA string

const (
	LetsEncrypt        CA = "letsencrypt"
	LetsEncryptStaging CA = "letsencrypt_staging"
)

// IssuanceScope 不接受 CA URL；DNS-01 模式下 provider 资源与凭据版本由宿主注册表校验，HTTP-01 模式下无需 DNS 提供商。
type IssuanceScope struct {
	Spec          Spec      `json:"spec"`
	Provider      dns.Scope `json:"provider"`
	CA            CA        `json:"ca"`
	ChallengeType string    `json:"challenge_type,omitempty"`
}

// IsHTTP01 返回当前签发范围是否使用免 DNS Token 的 HTTP-01（经内置 web.ingress 80 端口验证）模式。
func (s IssuanceScope) IsHTTP01() bool {
	return s.ChallengeType == "http-01"
}

// Consumer 没有文件路径或 secret owner 字段，宿主按这些资源身份确认绑定。
type Consumer struct {
	PluginID  string `json:"plugin_id"`
	ProfileID string `json:"profile_id"`
	NodeID    string `json:"node_id"`
	SNI       string `json:"sni"`
	Purpose   string `json:"purpose"`
	Test      bool   `json:"test"`
}

type Access string

const (
	Read             Access = "read"
	Issue            Access = "issue"
	Import           Access = "import"
	TestIssue        Access = "test_issue"
	Bind             Access = "bind"
	Unbind           Access = "unbind"
	Remove           Access = "remove"
	ConfigureRenewal Access = "configure_renewal"
	RenewExisting    Access = "renew_existing"
)

// Authorization 保留精确范围，实际授权不能来自当前参数中的自报布尔值。
type Authorization struct {
	Caller        Caller
	CertificateID string
	Generation    uint64
	BindingID     string
	AttemptID     string
	Spec          Spec
	Issuance      *IssuanceScope
	Consumer      *Consumer
	Access        Access
}

// Authorizer 每个关键步骤重新校验派发 operation、owner、资源范围和撤权。
type Authorizer interface {
	Authorize(context.Context, Authorization) error
}

// MaterialRef 仅持久化在私有状态中，公开 DTO 永远不包含此字段。
type MaterialRef string

func (MaterialRef) String() string   { return "[REDACTED]" }
func (MaterialRef) GoString() string { return "certificates.MaterialRef{[REDACTED]}" }

// Materials 是宿主的 owner/certificate 受限材料服务，不是通用 RevealSecret。
// Import 只能读取该 operation 提取的私钥引用；Ensure 操作须按 attempt 幂等。
type Materials interface {
	Find(context.Context, Caller, string, string) (Issued, error)
	Inspect(context.Context, Caller, string, MaterialRef, Spec, tlsmgr.TrustClass) (tlsmgr.CertificateMetadata, error)
	Import(context.Context, Caller, string, string, []byte, string, Spec, tlsmgr.TrustClass) (MaterialRef, error)
	GenerateTest(context.Context, Caller, string, string, Spec) (MaterialRef, error)
	Remove(context.Context, Caller, string, MaterialRef) error
}

type Issued struct {
	Material MaterialRef
	Trust    tlsmgr.TrustClass
}

func (Issued) String() string   { return "certificates.Issued{[REDACTED]}" }
func (Issued) GoString() string { return "certificates.Issued{[REDACTED]}" }

// Authority 只支持受控 DNS-01，内部持有账户/私钥与 attempt 对账。
// Reconcile 只恢复同一 attempt，不可盲目创建新订单；Cancel 只清理该 attempt。
type Authority interface {
	Issue(context.Context, Caller, string, string, IssuanceScope, Progress) (Issued, error)
	Reconcile(context.Context, Caller, string, string, IssuanceScope, Progress) (Issued, error)
	Cancel(context.Context, Caller, string, string, IssuanceScope) error
}

// Progress 只发送阶段名与百分比，不能带密钥、challenge 值或内部响应。
type Progress func(stage string, percent uint32) error

// HostBinding 是宿主确认的消费许可，policy_revision 必须在部署时仍有效。
type HostBinding struct {
	ID             string   `json:"id"`
	CertificateID  string   `json:"certificate_id"`
	Generation     uint64   `json:"generation"`
	Consumer       Consumer `json:"consumer"`
	PolicyRevision string   `json:"policy_revision"`
}

type Deployment struct {
	State            string `json:"state"`
	ActiveGeneration uint64 `json:"active_generation"`
	Healthy          bool   `json:"healthy"`
}

// Reference 由宿主当前、回滚或待部署快照提供，不仅依赖业务插件自报绑定。
type Reference struct {
	Generation uint64
	Consumer   Consumer
	Kind       string
}

// Bindings 只把授权 generation 落到消费者私有固定目录并执行真实健康检查。
// 失败必须返回确认回滚或 unknown，不能仅以进程启动代替健康结果。
type Bindings interface {
	LockForRemoval(context.Context, Caller, string, uint64) (func(), error)
	References(context.Context, Caller, string) ([]Reference, error)
	Confirm(context.Context, Caller, string, uint64, Consumer) (HostBinding, error)
	Deploy(context.Context, Caller, HostBinding, MaterialRef) (Deployment, error)
	Reconcile(context.Context, Caller, HostBinding) (Deployment, error)
	Remove(context.Context, Caller, HostBinding) error
}

type Source string

const (
	ACME       Source = "acme"
	Imported   Source = "imported"
	SelfSigned Source = "self_signed_test"
)

// Generation 是公开历史，不含私有材料引用。
type Generation struct {
	Number    uint64                     `json:"number"`
	Metadata  tlsmgr.CertificateMetadata `json:"metadata"`
	Source    Source                     `json:"source"`
	CreatedAt time.Time                  `json:"created_at"`
}

type Binding struct {
	Host               HostBinding `json:"host"`
	RunningGeneration  uint64      `json:"running_generation"`
	PreviousGeneration uint64      `json:"previous_generation,omitempty"`
	Verified           bool        `json:"verified"`
	LastError          string      `json:"last_error,omitempty"`
}

// View 的证书 ready 与消费者 ready 分开，签发成功不代表部署成功。
type View struct {
	ID                string       `json:"id"`
	Spec              Spec         `json:"spec"`
	Revision          string       `json:"revision"`
	CurrentGeneration uint64       `json:"current_generation"`
	Generations       []Generation `json:"generations"`
	Bindings          []Binding    `json:"bindings"`
	Ready             bool         `json:"ready"`
	ConsumersReady    bool         `json:"consumers_ready"`
	Pending           string       `json:"pending,omitempty"`
	LastError         string       `json:"last_error,omitempty"`
}

type IssueRequest struct {
	Caller           Caller
	CertificateID    string
	AttemptID        string
	ExpectedRevision string
	Scope            IssuanceScope
}

type ImportRequest struct {
	Caller           Caller
	CertificateID    string
	AttemptID        string
	ExpectedRevision string
	Spec             Spec
	ChainPEM         []byte
	PrivateKeyRef    string
	Trust            tlsmgr.TrustClass
}

func (ImportRequest) String() string   { return "certificates.ImportRequest{[REDACTED]}" }
func (ImportRequest) GoString() string { return "certificates.ImportRequest{[REDACTED]}" }

type TestRequest struct {
	Caller           Caller
	CertificateID    string
	AttemptID        string
	ExpectedRevision string
	Spec             Spec
}

type BindRequest struct {
	Caller           Caller
	CertificateID    string
	AttemptID        string
	ExpectedRevision string
	Generation       uint64
	Consumer         Consumer
}

type Result struct {
	View  View   `json:"certificate"`
	Stage string `json:"stage"`
}

// ======================== 私有持久状态 ========================

type generationState struct {
	Generation
	Material MaterialRef `json:"material_ref"`
}

type pending struct {
	ID               string            `json:"id"`
	Hash             string            `json:"hash"`
	Kind             string            `json:"kind"`
	Caller           Caller            `json:"caller"`
	Spec             Spec              `json:"spec"`
	Scope            *IssuanceScope    `json:"scope,omitempty"`
	Material         MaterialRef       `json:"material_ref,omitempty"`
	Trust            tlsmgr.TrustClass `json:"trust,omitempty"`
	Binding          *HostBinding      `json:"binding,omitempty"`
	StartedAt        time.Time         `json:"started_at"`
	RemoveGeneration uint64            `json:"remove_generation,omitempty"`
}

func (pending) String() string   { return "certificates.pending{[REDACTED]}" }
func (pending) GoString() string { return "certificates.pending{[REDACTED]}" }

type receiptState struct {
	ID         string       `json:"id"`
	Hash       string       `json:"hash"`
	Generation uint64       `json:"generation,omitempty"`
	Stage      string       `json:"stage"`
	ErrorCode  string       `json:"error_code,omitempty"`
	RetryAt    time.Time    `json:"retry_at,omitempty"`
	Binding    *HostBinding `json:"binding,omitempty"`
}

type resource struct {
	ID                string            `json:"id"`
	OwnerID           string            `json:"owner_id"`
	Spec              Spec              `json:"spec"`
	CurrentGeneration uint64            `json:"current_generation"`
	Generations       []generationState `json:"generations"`
	Bindings          []Binding         `json:"bindings"`
	Pending           *pending          `json:"pending,omitempty"`
	Receipts          []receiptState    `json:"receipts"`
	LastError         string            `json:"last_error,omitempty"`
}
