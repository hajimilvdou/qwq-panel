// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 新授权 operation 恢复原意图 ========================

// RecoverAttempt 只恢复该 owner/certificate/attempt 的保存意图，不改写原请求。
// 当前 operation 必须重新取得精确范围权限；未知 DNS 写入永远不重发。
func (m *Manager) RecoverAttempt(ctx context.Context, caller Caller, scope Scope, certificateID, attemptID string) (Receipt, error) {
	if !names.ID(caller.OwnerID) || !names.ID(caller.OperationID) {
		return Receipt{}, fault.New("PERMISSION_DENIED", "DNS 对账必须属于当前派发 operation")
	}
	if !names.ID(attemptID) || (certificateID != "" && !names.ID(certificateID)) {
		return Receipt{}, fault.New("VALIDATION_FAILED", "DNS 对账资源标识无效")
	}
	access := Reconcile
	if certificateID != "" {
		access = Read
		guard, found := m.authorizer.(ChallengeAuthorizations)
		if !found || guard == nil {
			return Receipt{}, fault.New("BACKEND_REQUIRED", "原 DNS attempt 查询需要 CA 请求授权")
		}
		if err := guard.AuthorizeChallengeSource(ctx, caller, scope, certificateID, attemptID); err != nil {
			return Receipt{}, err
		}
	} else {
		guard, found := m.authorizer.(RecoveryAuthorizations)
		if !found || guard == nil {
			return Receipt{}, fault.New("BACKEND_REQUIRED", "普通 DNS 对账需要当前原 attempt 的授权来源")
		}
		if err := guard.AuthorizeRecoveryAttempt(ctx, caller, scope, attemptID); err != nil {
			return Receipt{}, err
		}
	}
	if err := m.authorize(ctx, caller, scope, access); err != nil {
		return Receipt{}, err
	}
	if err := m.mu.Lock(ctx); err != nil {
		return Receipt{}, err
	}
	defer m.mu.Unlock()
	state, revision, err := m.load(ctx, scope)
	if err != nil {
		return Receipt{}, err
	}
	owned := func(saved attempt) bool {
		return saved.Request.AttemptID == attemptID && saved.Request.Caller.OwnerID == caller.OwnerID && saved.Request.CertificateID == certificateID
	}
	if state.Active != nil && owned(*state.Active) {
		if state.Active.Challenge {
			ctx, err = m.challengeContext(ctx, challengeIntent(caller, state.Active.Request))
			if err != nil {
				return Receipt{}, err
			}
			if err := m.authorize(ctx, caller, scope, Challenge); err != nil {
				return Receipt{}, err
			}
		}
		return m.reconcile(ctx, caller, scope, &state, revision)
	}
	for _, saved := range state.Receipts {
		if owned(saved) {
			if saved.Challenge {
				if _, err := m.challengeContext(ctx, challengeIntent(caller, saved.Request)); err != nil {
					return Receipt{}, err
				}
			}
			if saved.State == Rejected {
				return receipt(saved), fault.New(saved.ErrorCode, "原 DNS 意图已明确拒绝")
			}
			return receipt(saved), nil
		}
	}
	return Receipt{}, fault.New("NOT_FOUND", "没有该 owner/certificate 的 DNS attempt")
}
