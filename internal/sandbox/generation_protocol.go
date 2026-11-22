// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/ids"
)

// ======================== 宿主私有协议：不把路径、signal 或权限声明放进请求 ========================

const (
	// HelperOpGenerationObserve 只观察合法插件的真实强代次。
	HelperOpGenerationObserve = "generation-observe"
	// HelperOpGenerationStop 停止已绑定的唯一 target_ref。
	HelperOpGenerationStop = "generation-stop"
	// HelperOpGenerationRetire 只退休准确完成引用，不接受删除路径或TTL。
	HelperOpGenerationRetire = "generation-retire"
	// MaxGenerationMessage 同时限制请求、响应与未来记录文档。
	MaxGenerationMessage = 16 << 10
)

// ErrGenerationDocument 拒绝坏形状/绑定，错误不回显私有原文。
var ErrGenerationDocument = errors.New("sandbox: invalid generation helper document")

// GenerationObserveRequest 只选择合法插件；观察不能携带停止目标或操作 ID。
type GenerationObserveRequest struct {
	Op string `json:"op"`
	ID string `json:"id"`
}

// GenerationStopRequest 的全局 target_ref 永久绑定同一 plugin/operation/proof。
type GenerationStopRequest struct {
	Op          string       `json:"op"`
	ID          string       `json:"id"`
	OperationID string       `json:"operation_id"`
	TargetRef   string       `json:"target_ref"`
	Expected    ProcessProof `json:"expected"`
}

// GenerationRetireRequest 只引用准确完成 witness；不声明 terminal/TTL/任意删除路径。
type GenerationRetireRequest struct {
	Op            string `json:"op"`
	ID            string `json:"id"`
	OperationID   string `json:"operation_id"`
	TargetRef     string `json:"target_ref"`
	ProofDigest   string `json:"proof_digest"`
	ReceiptDigest string `json:"receipt_digest"`
}

// GenerationRecordRef 是私有引用，公开 journal/DTO 只能使用其摘要。
type GenerationRecordRef struct {
	ID            string `json:"id"`
	OperationID   string `json:"operation_id"`
	TargetRef     string `json:"target_ref"`
	ProofDigest   string `json:"proof_digest"`
	ReceiptDigest string `json:"receipt_digest"`
}

// GenerationCompletion 描述已确认的原完成；结构校验不能替代实际后端落盘。
type GenerationCompletion struct {
	Reference   GenerationRecordRef `json:"reference"`
	Observation StopObservation     `json:"observation"`
	CompletedAt string              `json:"completed_at"`
}

// GenerationResponseStatus 的 uid 必须来自真实 root helper，不能仅据 JSON 认证对端。
type GenerationResponseStatus struct {
	OK    bool   `json:"ok"`
	UID   int    `json:"uid"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

// GenerationObserveResponse 成功时必须携带完整 active proof。
type GenerationObserveResponse struct {
	GenerationResponseStatus
	Observed *ProcessProof `json:"observed,omitempty"`
}

// GenerationStopResponse 成功时必须携带绑定原请求的完整完成 witness。
type GenerationStopResponse struct {
	GenerationResponseStatus
	Stopped *GenerationCompletion `json:"stopped,omitempty"`
}

// GenerationRetireResponse 只确认同一完成引用被退休，不改变停止完成的含义。
type GenerationRetireResponse struct {
	GenerationResponseStatus
	Retired *GenerationRecordRef `json:"retired,omitempty"`
}

// Validate 核观察动作与合法插件，不提供停止字段的默认值。
func (request GenerationObserveRequest) Validate() error {
	if request.Op != HelperOpGenerationObserve || ValidateID(request.ID) != nil {
		return ErrGenerationDocument
	}
	return nil
}

// Validate 核全局引用及完整原proof；关键零值均拒绝。
func (request GenerationStopRequest) Validate() error {
	if request.Op != HelperOpGenerationStop || validateGenerationReference(request.ID, request.OperationID, request.TargetRef) != nil ||
		request.Expected.Validate(request.ID) != nil || len(request.Expected.Cgroup) > 4096 {
		return ErrGenerationDocument
	}
	return nil
}

// Validate 核准确的root完成摘要，不能以自报终态替代见证。
func (request GenerationRetireRequest) Validate() error {
	if request.Op != HelperOpGenerationRetire || request.Reference().Validate() != nil {
		return ErrGenerationDocument
	}
	return nil
}

// Reference 返回请求引用的副本；不能把 caller 的可变结构留在后台。
func (request GenerationRetireRequest) Reference() GenerationRecordRef {
	return GenerationRecordRef{ID: request.ID, OperationID: request.OperationID, TargetRef: request.TargetRef,
		ProofDigest: request.ProofDigest, ReceiptDigest: request.ReceiptDigest}
}

// Validate 核私有引用命名空间和两个规范摘要。
func (reference GenerationRecordRef) Validate() error {
	if validateGenerationReference(reference.ID, reference.OperationID, reference.TargetRef) != nil ||
		!digestPattern.MatchString(reference.ProofDigest) || !digestPattern.MatchString(reference.ReceiptDigest) {
		return ErrGenerationDocument
	}
	return nil
}

func validateGenerationReference(pluginID, operationID, targetRef string) error {
	if ValidateID(pluginID) != nil || ids.Check(operationID, ids.Operation) != nil || ids.Check(targetRef, ids.Generation) != nil {
		return ErrGenerationDocument
	}
	return nil
}

func (status GenerationResponseStatus) validate() error {
	if status.UID != 0 || status.OK && (status.Code != "" || status.Error != "") ||
		!status.OK && (status.Code == "" || status.Error == "") {
		return ErrGenerationDocument
	}
	return nil
}

// Validate 确认完成字段、私有引用和 canonical digest 一致，不从路径消失推断成功。
func (completion GenerationCompletion) Validate() error {
	reference := completion.Reference
	if reference.Validate() != nil || completion.Observation.ValidateCompleted(reference.ID, completion.Observation.Proof) != nil {
		return ErrGenerationDocument
	}
	proofDigest, err := GenerationProofDigest(reference.ID, completion.Observation.Proof)
	if err != nil || reference.ProofDigest != proofDigest {
		return ErrGenerationDocument
	}
	digest, err := generationCompletionDigest(completion)
	if err != nil || reference.ReceiptDigest != digest {
		return ErrGenerationDocument
	}
	return nil
}

// ValidateFor 核当次请求的每个不可变引用，完成 witness 不能跨 operation/target 使用。
func (completion GenerationCompletion) ValidateFor(request GenerationStopRequest) error {
	if request.Validate() != nil || completion.Validate() != nil || completion.Reference.ID != request.ID ||
		completion.Reference.OperationID != request.OperationID || completion.Reference.TargetRef != request.TargetRef ||
		completion.Observation.ValidateCompleted(request.ID, request.Expected) != nil {
		return ErrGenerationDocument
	}
	return nil
}

// GenerationProofDigest 对正式 typed proof 编码，只供内部绑定/完整性使用。
func GenerationProofDigest(pluginID string, proof ProcessProof) (string, error) {
	if proof.Validate(pluginID) != nil || len(proof.Cgroup) > 4096 {
		return "", ErrGenerationDocument
	}
	return generationCanonicalDigest(struct {
		Domain string       `json:"domain"`
		Proof  ProcessProof `json:"proof"`
	}{"qwq.generation.proof.v1", proof})
}

// NewGenerationCompletion 只构造已完成数据；生产后端仍须 durable witness 后才能返回它。
func NewGenerationCompletion(request GenerationStopRequest, observation StopObservation, completedAt time.Time) (GenerationCompletion, error) {
	if request.Validate() != nil || observation.ValidateCompleted(request.ID, request.Expected) != nil || completedAt.IsZero() {
		return GenerationCompletion{}, ErrGenerationDocument
	}
	proofDigest, err := GenerationProofDigest(request.ID, observation.Proof)
	if err != nil {
		return GenerationCompletion{}, err
	}
	completion := GenerationCompletion{Reference: GenerationRecordRef{ID: request.ID, OperationID: request.OperationID,
		TargetRef: request.TargetRef, ProofDigest: proofDigest}, Observation: observation,
		CompletedAt: completedAt.UTC().Format(time.RFC3339Nano)}
	completion.Reference.ReceiptDigest, err = generationCompletionDigest(completion)
	return completion, err
}

func generationCompletionDigest(completion GenerationCompletion) (string, error) {
	at, err := time.Parse(time.RFC3339Nano, completion.CompletedAt)
	if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != completion.CompletedAt {
		return "", ErrGenerationDocument
	}
	reference := completion.Reference
	return generationCanonicalDigest(struct {
		Domain              string `json:"domain"`
		ID                  string `json:"id"`
		OperationID         string `json:"operation_id"`
		TargetRef           string `json:"target_ref"`
		ProofDigest         string `json:"proof_digest"`
		OriginalExited      bool   `json:"original_exited"`
		OriginalCgroupEmpty bool   `json:"original_cgroup_empty"`
		CompletedAt         string `json:"completed_at"`
	}{"qwq.generation.completed.v1", reference.ID, reference.OperationID, reference.TargetRef, reference.ProofDigest,
		completion.Observation.OriginalExited, completion.Observation.OriginalCgroupEmpty, completion.CompletedAt})
}

func generationCanonicalDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", ErrGenerationDocument
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
