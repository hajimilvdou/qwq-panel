// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"errors"
	"log/slog"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// ======================== 消费者证书窄协议：仅传递声明式绑定与有界材料，不携带路径或权限 ========================

const (
	// HelperOpConsumerCertStage 暂存并校验一条消费者证书材料。
	HelperOpConsumerCertStage = "consumer-cert-stage"
	// HelperOpConsumerCertActivate CAS 切换消费者证书的当前生效证明。
	HelperOpConsumerCertActivate = "consumer-cert-activate"
	// HelperOpConsumerCertCurrent 读取指定绑定当前的消费者证书证明。
	HelperOpConsumerCertCurrent = "consumer-cert-current"
	// HelperOpConsumerCertRemove 移除指定绑定对应的消费者证书材料与状态。
	HelperOpConsumerCertRemove = "consumer-cert-remove"

	// MaxConsumerCertMessage 限制单条消费者证书协议请求或响应的原始字节数。
	MaxConsumerCertMessage = 128 << 10
	// MaxConsumerCertChainBase64 限制 fullchain PEM 经 base64 编码后的最大长度。
	MaxConsumerCertChainBase64 = 68 << 10
	// MaxConsumerCertKeyBase64 限制私钥 PEM 经 base64 编码后的最大长度。
	MaxConsumerCertKeyBase64 = 24 << 10
)

// ErrConsumerCertDocument 拒绝非法消费者证书协议文档，错误不回显私密内容或路径。
var ErrConsumerCertDocument = errors.New("sandbox: invalid consumer certificate helper document")

var (
	consumerCertIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	consumerCertHex64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ConsumerCertConsumer 描述接收消费者证书的目标插件与用途上下文。
type ConsumerCertConsumer struct {
	PluginID  string `json:"plugin_id"`
	ProfileID string `json:"profile_id"`
	NodeID    string `json:"node_id"`
	SNI       string `json:"sni"`
	Purpose   string `json:"purpose"`
	Test      bool   `json:"test"`
}

// ConsumerCertBinding 描述一条不可变的消费者证书绑定代次。
type ConsumerCertBinding struct {
	ID             string               `json:"id"`
	CertificateID  string               `json:"certificate_id"`
	Generation     uint64               `json:"generation"`
	Consumer       ConsumerCertConsumer `json:"consumer"`
	PolicyRevision string               `json:"policy_revision"`
}

// ConsumerCertProof 是落盘证书链与私钥的摘要证明。
type ConsumerCertProof struct {
	Binding          ConsumerCertBinding `json:"binding"`
	FullchainSHA256  string              `json:"fullchain_sha256"`
	PrivateKeySHA256 string              `json:"private_key_sha256"`
}

// String 隐藏证明摘要与绑定细节，防止日志意外泄露。
func (ConsumerCertProof) String() string { return "sandbox.ConsumerCertProof{[REDACTED]}" }

// GoString 隐藏证明摘要与绑定细节。
func (ConsumerCertProof) GoString() string { return "sandbox.ConsumerCertProof{[REDACTED]}" }

// LogValue 供 slog 输出脱敏占位值，不展开摘要或绑定字段。
func (ConsumerCertProof) LogValue() slog.Value {
	return slog.StringValue("sandbox.ConsumerCertProof{[REDACTED]}")
}

// ConsumerCertStageRequest 请求 root helper 暂存消费者证书链与私钥。
type ConsumerCertStageRequest struct {
	Op               string              `json:"op"`
	PluginID         string              `json:"plugin_id"`
	Binding          ConsumerCertBinding `json:"binding"`
	FullchainBase64  string              `json:"fullchain_base64"`
	PrivateKeyBase64 string              `json:"private_key_base64"`
}

// String 隐藏证书链与私钥的 base64 原文。
func (ConsumerCertStageRequest) String() string {
	return "sandbox.ConsumerCertStageRequest{[REDACTED]}"
}

// GoString 隐藏证书链与私钥的 base64 原文。
func (ConsumerCertStageRequest) GoString() string {
	return "sandbox.ConsumerCertStageRequest{[REDACTED]}"
}

// LogValue 供 slog 输出脱敏占位值，不展开 PEM base64 原文。
func (ConsumerCertStageRequest) LogValue() slog.Value {
	return slog.StringValue("sandbox.ConsumerCertStageRequest{[REDACTED]}")
}

// ConsumerCertActivateRequest 请求按 CAS 语意激活目标消费者证书证明。
type ConsumerCertActivateRequest struct {
	Op       string             `json:"op"`
	PluginID string             `json:"plugin_id"`
	Expected *ConsumerCertProof `json:"expected,omitempty"`
	Wanted   ConsumerCertProof  `json:"wanted"`
}

// ConsumerCertCurrentRequest 查询绑定当前的消费者证书生效证明。
type ConsumerCertCurrentRequest struct {
	Op        string `json:"op"`
	PluginID  string `json:"plugin_id"`
	BindingID string `json:"binding_id"`
}

// ConsumerCertRemoveRequest 删除指定绑定的消费者证书材料与当前指向。
type ConsumerCertRemoveRequest struct {
	Op        string `json:"op"`
	PluginID  string `json:"plugin_id"`
	BindingID string `json:"binding_id"`
}

// ConsumerCertResponseStatus 承载所有消费者证书响应的统一状态与不确定标记。
type ConsumerCertResponseStatus struct {
	OK        bool   `json:"ok"`
	UID       int    `json:"uid"`
	Code      string `json:"code,omitempty"`
	Error     string `json:"error,omitempty"`
	Uncertain bool   `json:"uncertain,omitempty"`
}

// ConsumerCertStageResponse 返回已暂存材料的落盘证明。
type ConsumerCertStageResponse struct {
	ConsumerCertResponseStatus
	Proof *ConsumerCertProof `json:"proof,omitempty"`
}

// ConsumerCertActivateResponse 返回切换前的旧证明；当激活失败且状态不确定时可保留旧证明以供回滚对账。
type ConsumerCertActivateResponse struct {
	ConsumerCertResponseStatus
	Previous *ConsumerCertProof `json:"previous,omitempty"`
}

// ConsumerCertCurrentResponse 返回当前生效证明；尚未激活时 Current 可为空。
type ConsumerCertCurrentResponse struct {
	ConsumerCertResponseStatus
	Current *ConsumerCertProof `json:"current,omitempty"`
}

// ConsumerCertRemoveResponse 汇报指定绑定是否实际移除了持久化状态。
type ConsumerCertRemoveResponse struct {
	ConsumerCertResponseStatus
	Removed bool `json:"removed,omitempty"`
}

// ======================== 字段边界与一致性校验 ========================

// Validate 校验消费者上下文的插件 ID、标签和 SNI 边界。
func (c ConsumerCertConsumer) Validate() error {
	if ValidateID(c.PluginID) != nil ||
		!validConsumerCertLabel(c.ProfileID) ||
		!validConsumerCertLabel(c.NodeID) ||
		!validConsumerCertSNI(c.SNI) ||
		!validConsumerCertLabel(c.Purpose) {
		return ErrConsumerCertDocument
	}
	return nil
}

// Validate 校验绑定标识、非零代次、消费者上下文和策略修订号。
func (b ConsumerCertBinding) Validate() error {
	if !validConsumerCertID(b.ID) ||
		!validConsumerCertID(b.CertificateID) ||
		b.Generation == 0 ||
		b.Consumer.Validate() != nil ||
		!validConsumerCertID(b.PolicyRevision) {
		return ErrConsumerCertDocument
	}
	return nil
}

// Validate 校验绑定字段及两条 64 位小写十六进制 SHA-256 摘要。
func (p ConsumerCertProof) Validate() error {
	if p.Binding.Validate() != nil ||
		!consumerCertHex64Pattern.MatchString(p.FullchainSHA256) ||
		!consumerCertHex64Pattern.MatchString(p.PrivateKeySHA256) {
		return ErrConsumerCertDocument
	}
	return nil
}

// Validate 校验暂存请求的动作、插件一致性与 base64 材料长度上限。
func (r ConsumerCertStageRequest) Validate() error {
	if r.Op != HelperOpConsumerCertStage ||
		ValidateID(r.PluginID) != nil ||
		r.Binding.Validate() != nil ||
		r.PluginID != r.Binding.Consumer.PluginID ||
		len(r.FullchainBase64) == 0 || len(r.FullchainBase64) > MaxConsumerCertChainBase64 ||
		len(r.PrivateKeyBase64) == 0 || len(r.PrivateKeyBase64) > MaxConsumerCertKeyBase64 {
		return ErrConsumerCertDocument
	}
	return nil
}

// Validate 校验激活请求的动作、目标证明与可选 CAS 期望证明的插件及绑定一致性。
func (r ConsumerCertActivateRequest) Validate() error {
	if r.Op != HelperOpConsumerCertActivate ||
		ValidateID(r.PluginID) != nil ||
		r.Wanted.Validate() != nil ||
		r.PluginID != r.Wanted.Binding.Consumer.PluginID {
		return ErrConsumerCertDocument
	}
	if r.Expected != nil {
		if r.Expected.Validate() != nil ||
			r.Expected.Binding.ID != r.Wanted.Binding.ID ||
			r.Expected.Binding.Consumer.PluginID != r.PluginID {
			return ErrConsumerCertDocument
		}
	}
	return nil
}

// Validate 校验查询当前证明请求的动作、插件 ID 与单段绑定 ID。
func (r ConsumerCertCurrentRequest) Validate() error {
	if r.Op != HelperOpConsumerCertCurrent || ValidateID(r.PluginID) != nil || !validConsumerCertID(r.BindingID) {
		return ErrConsumerCertDocument
	}
	return nil
}

// Validate 校验移除请求的动作、插件 ID 与单段绑定 ID。
func (r ConsumerCertRemoveRequest) Validate() error {
	if r.Op != HelperOpConsumerCertRemove || ValidateID(r.PluginID) != nil || !validConsumerCertID(r.BindingID) {
		return ErrConsumerCertDocument
	}
	return nil
}

func (status ConsumerCertResponseStatus) validate() error {
	if status.UID != 0 {
		return ErrConsumerCertDocument
	}
	if status.OK {
		if status.Code != "" || status.Error != "" || status.Uncertain {
			return ErrConsumerCertDocument
		}
		return nil
	}
	if status.Code == "" || status.Error == "" {
		return ErrConsumerCertDocument
	}
	return nil
}

func validConsumerCertID(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	return consumerCertIDPattern.MatchString(value)
}

func validConsumerCertLabel(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

func validConsumerCertSNI(value string) bool {
	if value == "" || len(value) > 253 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}
