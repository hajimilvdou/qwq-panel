// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"crypto/subtle"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/ids"
)

const autonomousOperationPrefix = "auton:"

// PortTransactionIdentity 描述 ADD_NEW 阶段持久化的事务归属锚点。
//
// 事务所有权由 (PluginID, InstanceID) 与 256-bit 密码学随机 TransactionRef 共同证明，
// 不再要求三步交互 Saga（prepare -> commit/rollback）共享同一个已完结的 OperationID；
// 每步仍须携带当前宿主派发的合法写 OperationID（或 ROLLBACK 阶段的后台自治凭证）。
type PortTransactionIdentity struct {
	Kind           string
	Reference      string // 64 hex chars (32 random bytes)
	PluginID       string
	InstanceID     string
	NewPort        uint32
	CurrentOpID    string // 当前步骤正在派发的 OperationID（非空，用于审计追踪）
	CandidateRef   string // 请求传入的 mutation.TransactionRef
	CandidateStage string // COMMIT_NEW | ROLLBACK
}

// VerifyPortTransactionContinuation 常量时间校验双端口事务归属与阶段匹配。
func VerifyPortTransactionContinuation(tx PortTransactionIdentity, callerPluginID, callerInstanceID string, reqNewPort uint32) bool {
	if tx.Kind != "port" {
		return false
	}
	if tx.PluginID == "" || tx.PluginID != callerPluginID {
		return false
	}
	if tx.InstanceID == "" || tx.InstanceID != callerInstanceID {
		return false
	}
	if strings.TrimSpace(tx.CurrentOpID) == "" {
		return false
	}
	if len(tx.Reference) < 32 || len(tx.CandidateRef) != len(tx.Reference) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(tx.Reference), []byte(tx.CandidateRef)) != 1 {
		return false
	}
	if tx.CandidateStage == "COMMIT_NEW" && tx.NewPort != reqNewPort {
		return false
	}
	return true
}

func isAutonomousOperationID(operationID string) bool {
	if !strings.HasPrefix(operationID, autonomousOperationPrefix) {
		return false
	}
	reason := strings.TrimPrefix(operationID, autonomousOperationPrefix)
	if len(reason) == 0 || len(reason) > 48 {
		return false
	}
	for i := 0; i < len(reason); i++ {
		c := reason[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// validPortMutationOperationID 校验端口事务各阶段允许的 OperationID：
// ADD_NEW 与 COMMIT_NEW 必须携带宿主正式派发的 op_ 标识；
// ROLLBACK 除正式 op_ 外，亦允许后台超时自动回滚携带的 auton:<reason> 自治标识。
func validPortMutationOperationID(stage, operationID string) bool {
	if ids.Valid(operationID, ids.Operation) {
		return true
	}
	return stage == "ROLLBACK" && isAutonomousOperationID(operationID)
}
