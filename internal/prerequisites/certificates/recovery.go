// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"errors"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// Recover 用当前已授权 operation 对账已持久化任务，不复用已结束的派发权限。
// 原 attempt、SAN、CA、provider 和消费绑定均来自保存状态，调用者不能改写。
func (m *Manager) Recover(ctx context.Context, caller Caller, certificateID, expectedRevision string, progress Progress) (result Result, err error) {
	if err := m.authorize(ctx, Authorization{Caller: caller, CertificateID: certificateID, Access: Read}); err != nil {
		return Result{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, revision, found, err := m.load(ctx, caller, certificateID)
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{}, fault.New("NOT_FOUND", "证书不存在")
	}
	if expectedRevision == "" || expectedRevision != revision {
		return Result{}, fault.New("REVISION_CONFLICT", "对账前证书状态已变化")
	}
	if state.Pending == nil {
		return Result{View: m.view(state, revision), Stage: "unchanged"}, nil
	}
	active := state.Pending
	if active.Kind == "bind" {
		return m.reconcileBinding(ctx, caller, &state, revision)
	}
	if active.Kind != "issue" && active.Kind != "import" && active.Kind != "test" {
		return Result{}, fault.New("RECOVERY_REQUIRED", "此任务需要对应的清理对账操作")
	}
	authorization := Authorization{Caller: caller, CertificateID: certificateID, Spec: state.Spec, Issuance: active.Scope, Access: accessFor(startRequest{Caller: caller, Kind: active.Kind})}
	if err := m.authorize(ctx, authorization); err != nil {
		return Result{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, m.callTimeout)
	defer cancel()
	if active.Kind == "issue" {
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), m.cleanupTimeout)
			defer stop()
			if cleanupErr := m.authority.Cancel(cleanup, caller, certificateID, active.ID, *active.Scope); cleanupErr != nil {
				err = errors.Join(err, backendFailure(cleanupErr, "DNS_CLEANUP_FAILED"))
			}
		}()
	}
	return m.obtain(bounded, caller, &state, revision, guardedProgress(progress), func(ctx context.Context, _ bool) (Issued, error) {
		if active.Kind == "issue" {
			return m.authority.Reconcile(ctx, caller, certificateID, active.ID, *active.Scope, guardedProgress(progress))
		}
		return m.materials.Find(ctx, caller, certificateID, active.ID)
	}, true)
}
