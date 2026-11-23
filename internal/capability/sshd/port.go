// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/sandbox"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
)

var errPortVerification = errors.New("sshd: listener verification failed")

// PortMutation 的身份与 HostPorts 由宿主 forwarder 填入，不来自插件参数。
type PortMutation struct {
	Kind             string   `json:"kind"`
	NewPort          uint32   `json:"new_port"`
	Stage            string   `json:"stage"`
	ExpectedRevision string   `json:"expected_revision"`
	TransactionRef   string   `json:"transaction_ref,omitempty"`
	OperationID      string   `json:"operation_id"`
	InstanceID       string   `json:"instance_id"`
	HostPorts        []uint32 `json:"host_preserved_ports"`
}

type transactionRecord struct {
	Kind             string    `json:"kind"`
	Reference        string    `json:"reference"`
	PluginID         string    `json:"plugin_id"`
	InstanceID       string    `json:"instance_id"`
	OperationID      string    `json:"operation_id"`
	NewPort          uint32    `json:"new_port"`
	Before           []byte    `json:"before"`
	BeforePorts      []uint32  `json:"before_ports"`
	ExternalRevision string    `json:"external_revision"`
	OriginalRevision string    `json:"original_revision"`
	ExpectedRevision string    `json:"expected_revision"`
	AppliedRevision  string    `json:"applied_revision"`
	Stage            string    `json:"stage"`
	CreatedAt        time.Time `json:"created_at"`
}

func (s *Service) transaction() (*transactionRecord, []byte, error) {
	raw, exists, err := s.Transactions.Read()
	if err != nil || !exists {
		return nil, raw, err
	}
	var transaction transactionRecord
	if decode(raw, &transaction) != nil || !validRevision(transaction.Reference) || sandbox.ValidateID(transaction.PluginID) != nil || sandbox.ValidateID(transaction.InstanceID) != nil || !validOperationID(transaction.OperationID) || transaction.NewPort > 65535 || transaction.Kind == "port" && transaction.NewPort == 0 || !validRevision(transaction.ExpectedRevision) || !validRevision(transaction.AppliedRevision) || !validRevision(transaction.OriginalRevision) || transaction.CreatedAt.IsZero() || !validTransactionKind(transaction.Kind) || !validTransactionStage(transaction.Stage) || len(transaction.Before) > 64<<10 || !validPorts(transaction.BeforePorts) {
		return nil, raw, errors.New("sshd: transaction is invalid")
	}
	return &transaction, raw, nil
}

func (s *Service) save(transaction *transactionRecord) error {
	raw, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	defer clear(raw)
	return s.Transactions.Commit(raw)
}

func (s *Service) setPort(ctx context.Context, pluginID string, mutation PortMutation) sandbox.CapabilityResponse {
	if mutation.Kind != "port" || !validRevision(mutation.ExpectedRevision) || (mutation.Stage != "ROLLBACK" && mutation.NewPort == 0) || mutation.NewPort > 65535 || !validPortMutationOperationID(mutation.Stage, mutation.OperationID) || sandbox.ValidateID(mutation.InstanceID) != nil || (mutation.Stage != "ADD_NEW" && mutation.Stage != "COMMIT_NEW" && mutation.Stage != "ROLLBACK") {
		return bridge.Failure("VALIDATION_FAILED", "端口事务参数无效")
	}
	before, err := s.Repository.Read(ctx, Match{})
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "SSH 配置不可用")
	}
	if before.Revision != mutation.ExpectedRevision {
		return bridge.Failure("PRECONDITION_FAILED", "SSH 配置已变化")
	}
	if !before.Writable {
		return bridge.Failure("CONFLICT", "自有 drop-in 不在可管理的全局 Include 路径")
	}
	livePorts, err := s.Runtime.Ports(ctx)
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "当前 SSH 监听不可用")
	}
	before.LivePorts = uniquePorts(livePorts)
	if !slices.Equal(before.LivePorts, before.Ports) {
		return bridge.Failure("CONFLICT", "当前监听与配置不一致，请先检查配置来源")
	}
	management, err := s.Runtime.ManagementPorts(ctx)
	if err != nil || len(management) == 0 || len(mutation.HostPorts) == 0 || len(mutation.HostPorts) > 128 {
		return bridge.Failure("UNAVAILABLE", "宿主管理端口事实不可用")
	}
	for _, port := range management {
		if !slices.Contains(mutation.HostPorts, port) {
			return bridge.Failure("PRECONDITION_FAILED", "宿主管理端口已变化")
		}
	}
	if mutation.NewPort != 0 && (slices.Contains(management, mutation.NewPort) || slices.Contains(mutation.HostPorts, mutation.NewPort)) {
		return bridge.Failure("VALIDATION_FAILED", "SSH 端口与管理面冲突")
	}
	policy, err := parseDropIn(before.Content)
	if err != nil {
		return bridge.Failure("CONFLICT", "同名 drop-in 不属于 qwq 或包含额外指令")
	}
	transaction, previousRecord, err := s.transaction()
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "SSH 事务记录不可用")
	}
	if mutation.Stage == "ADD_NEW" {
		if mutation.TransactionRef != "" || slices.Contains(before.Ports, mutation.NewPort) {
			return bridge.Failure("VALIDATION_FAILED", "新端口或事务引用无效")
		}
		if transaction != nil && transaction.Stage != "COMMITTED" {
			return bridge.Failure("CONFLICT", "已有未完成 SSH 端口事务")
		}
		conflict, err := s.Runtime.Conflicts(ctx, mutation.NewPort)
		if err != nil {
			return bridge.Failure("UNAVAILABLE", "TCP 占用不可用")
		}
		if conflict {
			return bridge.Failure("CONFLICT", "新端口已被占用")
		}
		// Port 是累加项。先证明最终单端口能够生效，避免事后修改他人的配置。
		policy.Ports = []uint32{mutation.NewPort}
		final, err := s.Repository.Candidate(ctx, before, renderDropIn(policy), Match{})
		if err != nil {
			return bridge.Failure("VALIDATION_FAILED", "单端口候选未通过原生预检")
		}
		if !slices.Equal(final.Ports, policy.Ports) {
			return bridge.Failure("CONFLICT", "其他配置仍声明 SSH 端口，无法在自有范围摘旧")
		}
		live, err := s.Runtime.Ports(ctx)
		if err != nil || len(live) == 0 {
			return bridge.Failure("UNAVAILABLE", "现有 SSH 监听不可用")
		}
		policy.Ports = uniquePorts(append(append(slices.Clone(before.Ports), live...), mutation.NewPort))
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return bridge.Failure("INTERNAL", "事务引用生成失败")
		}
		transaction = &transactionRecord{Kind: "port", Reference: hex.EncodeToString(nonce[:]), PluginID: pluginID, InstanceID: mutation.InstanceID, OperationID: mutation.OperationID, NewPort: mutation.NewPort, Before: slices.Clone(before.Content), BeforePorts: slices.Clone(before.Ports), ExternalRevision: before.ExternalRevision, OriginalRevision: before.Revision, CreatedAt: s.now()}
	} else {
		effectivePort := mutation.NewPort
		if mutation.Stage == "ROLLBACK" && effectivePort == 0 && transaction != nil {
			effectivePort = transaction.NewPort
		}
		if transaction == nil || !VerifyPortTransactionContinuation(PortTransactionIdentity{
			Kind:           transaction.Kind,
			Reference:      transaction.Reference,
			PluginID:       transaction.PluginID,
			InstanceID:     transaction.InstanceID,
			NewPort:        transaction.NewPort,
			CurrentOpID:    mutation.OperationID,
			CandidateRef:   mutation.TransactionRef,
			CandidateStage: mutation.Stage,
		}, pluginID, mutation.InstanceID, effectivePort) {
			return bridge.Failure("PERMISSION_DENIED", "事务与当前派发身份不匹配")
		}
		if before.ExternalRevision != transaction.ExternalRevision || (before.Revision != transaction.AppliedRevision && before.Revision != transaction.ExpectedRevision) {
			return bridge.Failure("PRECONDITION_FAILED", "事务资源已被其他配置修改")
		}
		if mutation.Stage == "COMMIT_NEW" {
			if transaction.Stage != "ADDED" || s.now().Before(transaction.CreatedAt) || s.now().After(transaction.CreatedAt.Add(30*time.Minute)) {
				return bridge.Failure("PRECONDITION_FAILED", "事务不在可提交阶段或已过期")
			}
			if _, err := s.verify(ctx, []uint32{mutation.NewPort}); err != nil {
				return bridge.Failure("PORT_VERIFY_FAILED", "新端口重新验证失败，保留旧入口")
			}
			// --- 摘旧前证明真实入站放行；回环 banner 不能证明公网可重连 -----------------
			if err := s.Runtime.RequireSSHPort(ctx, mutation.NewPort); err != nil {
				return bridge.Failure("PRECONDITION_FAILED", "防火墙尚未确认放行新 SSH 端口，请先更新保留端口；旧入口保持可用")
			}
			transaction.OperationID = mutation.OperationID
			policy.Ports = []uint32{mutation.NewPort}
		} else {
			return s.rollbackPort(ctx, before, transaction)
		}
	}
	raw := renderDropIn(policy)
	candidate, err := s.Repository.Candidate(ctx, before, raw, Match{})
	if err != nil {
		return bridge.Failure("VALIDATION_FAILED", "SSH 候选配置未通过原生预检")
	}
	if !slices.Equal(candidate.Ports, policy.Ports) {
		return bridge.Failure("CONFLICT", "候选 SSH 端口被外部配置影响")
	}
	transaction.ExpectedRevision, transaction.AppliedRevision = before.Revision, candidate.Revision
	transaction.Stage = "APPLYING"
	if err := s.save(transaction); err != nil {
		return bridge.Failure("UNAVAILABLE", "无法持久化 SSH 事务，未执行")
	}
	after, code := s.replace(ctx, before, candidate, raw)
	if code != "" {
		if code != "RECOVERY_REQUIRED" && s.Transactions.Commit(previousRecord) != nil {
			code = "RECOVERY_REQUIRED"
		}
		return bridge.Failure(code, "SSH 端口变更未完成")
	}
	transaction.Stage = "ADDED"
	if mutation.Stage == "COMMIT_NEW" {
		transaction.Stage = "COMMITTED"
	}
	if err := s.save(transaction); err != nil {
		return bridge.Failure("RECOVERY_REQUIRED", "监听已变化，事务确认失败，请检查状态")
	}
	return bridge.Pack(&sshdv1.SetPortResponse{Revision: after.Revision, ListeningPorts: after.Ports, TransactionRef: transaction.Reference})
}

func (s *Service) rollbackPort(ctx context.Context, before Snapshot, transaction *transactionRecord) sandbox.CapabilityResponse {
	after, code := s.undo(ctx, before, transaction, "", nil)
	if code != "" {
		return bridge.Failure(code, "SSH 回滚未完成")
	}
	return bridge.Pack(&sshdv1.SetPortResponse{Revision: after.Revision, ListeningPorts: after.Ports, TransactionRef: transaction.Reference})
}
