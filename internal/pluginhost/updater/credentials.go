// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"strings"

	"github.com/qwq-panel/qwq/internal/storage"
)

const credentialAbortPrefix = "credential_abort/"

// ======================== 与 installer 共用的凭据事务接缝 ========================

func (u *Updater) credentialLifecycle() CredentialLifecycle {
	lifecycle, ok := u.install.(CredentialLifecycle)
	if !ok || !lifecycle.CredentialRotationEnabled() {
		return nil
	}
	return lifecycle
}

func (u *Updater) beginCredentialRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error {
	if lifecycle := u.credentialLifecycle(); lifecycle != nil {
		return lifecycle.BeginCredentialRotationTx(ctx, tx, pluginID)
	}
	return nil
}

func (u *Updater) finishCredentialRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error {
	if lifecycle := u.credentialLifecycle(); lifecycle != nil {
		return lifecycle.FinishCredentialRotationTx(ctx, tx, pluginID)
	}
	return nil
}

// credentialAbortStep 只还原原正常步骤，存储格式不接受新的任意状态机入口。
func credentialAbortStep(value string) (step, bool) {
	if !strings.HasPrefix(value, credentialAbortPrefix) {
		return "", false
	}
	return step(strings.TrimPrefix(value, credentialAbortPrefix)), true
}

// recordCredentialAbort 在任何外部补偿之前保存意图。否则恢复旧进程成功而
// 终态事务失败后，原 commit 步骤可能把已经清理的候选误标 ACTIVE。
func (u *Updater) recordCredentialAbort(ctx context.Context, p *plan, failed step, cause error) error {
	target := credentialAbortPrefix + string(failed)
	if p.saga.Step == target {
		return nil
	}
	before := p.saga.Step
	reason := sagaErrorText(cause)
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE plugin_update_sagas SET step = ?, error = ?, updated_at = ? WHERE saga_id = ? AND state = ?`,
			target, reason, storage.FormatTime(tx.Now()), p.saga.ID, SagaRunning)
		if err != nil {
			return err
		}
		if err := requireOneRow(res); err != nil {
			return err
		}
		return u.recordStepEventTx(ctx, tx, p.saga, before, target, problemDetail(cause))
	})
	if err != nil {
		return err
	}
	p.saga.Step, p.saga.Err = target, reason
	return nil
}
