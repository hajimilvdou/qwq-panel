// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/sandbox"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
)

func validTransactionKind(kind string) bool {
	return kind == "port" || kind == "login" || kind == "remove"
}
func validTransactionStage(stage string) bool {
	return stage == "APPLYING" || stage == "ADDED" || stage == "COMMITTED" || stage == "RECOVERING"
}
func validPorts(ports []uint32) bool {
	if len(ports) == 0 || len(ports) > 128 {
		return false
	}
	for _, port := range ports {
		if port == 0 || port > 65535 {
			return false
		}
	}
	return slices.Equal(uniquePorts(ports), ports)
}

func (s *Service) begin(kind, pluginID, instanceID, operationID string, before, candidate Snapshot) (*transactionRecord, []byte, error) {
	previous, raw, err := s.transaction()
	if err != nil {
		return nil, nil, err
	}
	if previous != nil && previous.Stage != "COMMITTED" {
		return nil, nil, errors.New("sshd: incomplete transaction")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	record := &transactionRecord{Kind: kind, Reference: hex.EncodeToString(nonce[:]), PluginID: pluginID, InstanceID: instanceID, OperationID: operationID, Before: slices.Clone(before.Content), BeforePorts: slices.Clone(before.Ports), ExternalRevision: before.ExternalRevision, OriginalRevision: before.Revision, ExpectedRevision: before.Revision, AppliedRevision: candidate.Revision, Stage: "APPLYING", CreatedAt: s.now()}
	if err := s.save(record); err != nil {
		return nil, nil, err
	}
	return record, raw, nil
}

func (s *Service) finishFailure(code string, previous []byte) string {
	if code != "RECOVERY_REQUIRED" && s.Transactions.Commit(previous) != nil {
		return "RECOVERY_REQUIRED"
	}
	return code
}

type RecoveryMutation struct {
	ExpectedRevision string   `json:"expected_revision"`
	TransactionRef   string   `json:"transaction_ref"`
	RecoveryUser     string   `json:"recovery_user,omitempty"`
	HostAddresses    []string `json:"host_addresses,omitempty"`
	OperationID      string   `json:"operation_id"`
	InstanceID       string   `json:"instance_id"`
}

func (s *Service) recoverDropIn(ctx context.Context, pluginID string, mutation RecoveryMutation) sandbox.CapabilityResponse {
	if !validMutation(mutation.ExpectedRevision, mutation.OperationID, mutation.InstanceID) || !validRevision(mutation.TransactionRef) {
		return bridge.Failure("VALIDATION_FAILED", "恢复参数无效")
	}
	record, _, err := s.transaction()
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "事务记录不可用")
	}
	if record == nil || record.Reference != mutation.TransactionRef || record.PluginID != pluginID || record.InstanceID != mutation.InstanceID {
		return bridge.Failure("PERMISSION_DENIED", "恢复事务不属于本插件和实例")
	}
	current, err := s.Repository.Read(ctx, Match{})
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "当前 SSH 配置不可用")
	}
	live, err := s.Runtime.Ports(ctx)
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "当前 SSH 监听不可用")
	}
	current.LivePorts = uniquePorts(live)
	if current.Revision != mutation.ExpectedRevision || current.ExternalRevision != record.ExternalRevision || current.Revision != record.ExpectedRevision && current.Revision != record.AppliedRevision && current.Revision != record.OriginalRevision {
		return bridge.Failure("PRECONDITION_FAILED", "当前配置已偏离事务，拒绝覆盖")
	}
	after, code := s.undo(ctx, current, record, mutation.RecoveryUser, mutation.HostAddresses)
	if code != "" {
		return bridge.Failure(code, "中断事务未能恢复")
	}
	return bridge.Pack(&sshdv1.RecoverDropInResponse{Revision: after.Revision, ListeningPorts: after.Ports})
}

// undo 先恢复双端口并验证原入口，再提交原始快照；强杀后记录仍能按版本恢复。
func (s *Service) undo(ctx context.Context, before Snapshot, record *transactionRecord, user string, addresses []string) (Snapshot, string) {
	original, err := s.Repository.Candidate(ctx, before, record.Before, Match{})
	if err != nil || !slices.Equal(original.Ports, record.BeforePorts) {
		return Snapshot{}, "PRECONDITION_FAILED"
	}
	if code := s.guardLogin(ctx, before, original, record.Before, user, addresses, false); code != "" {
		return Snapshot{}, code
	}
	current := before
	originalReady := true
	for _, port := range original.Ports {
		if !slices.Contains(before.LivePorts, port) {
			originalReady = false
		}
	}
	if !originalReady {
		policy, err := parseDropIn(record.Before)
		if err != nil {
			return Snapshot{}, "PRECONDITION_FAILED"
		}
		policy.Ports = uniquePorts(append(slices.Clone(before.LivePorts), original.Ports...))
		raw := renderDropIn(policy)
		interim, err := s.Repository.Candidate(ctx, before, raw, Match{})
		if err != nil {
			return Snapshot{}, "VALIDATION_FAILED"
		}
		record.ExpectedRevision, record.AppliedRevision, record.Stage = before.Revision, interim.Revision, "RECOVERING"
		if err := s.save(record); err != nil {
			return Snapshot{}, "UNAVAILABLE"
		}
		var code string
		current, code = s.replace(ctx, before, interim, raw)
		if code != "" {
			return Snapshot{}, code
		}
		original, err = s.Repository.Candidate(ctx, current, record.Before, Match{})
		if err != nil {
			return Snapshot{}, "RECOVERY_REQUIRED"
		}
	}
	record.ExpectedRevision, record.AppliedRevision, record.Stage = current.Revision, original.Revision, "RECOVERING"
	if err := s.save(record); err != nil {
		return Snapshot{}, "RECOVERY_REQUIRED"
	}
	after, code := s.replace(ctx, current, original, record.Before)
	if code != "" {
		if current.Revision != before.Revision {
			return Snapshot{}, "RECOVERY_REQUIRED"
		}
		return Snapshot{}, code
	}
	if err := s.Transactions.Commit(nil); err != nil {
		return Snapshot{}, "RECOVERY_REQUIRED"
	}
	return after, ""
}
