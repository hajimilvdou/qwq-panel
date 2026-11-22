// SPDX-License-Identifier: AGPL-3.0-only

package privateexport

import (
	"context"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Consume 在审计和秘密删除同一事务内认领一次性交付；网络中断不自动重放。
func (s *Service) Consume(ctx context.Context, act actor.Actor, id string) (secrets.Secret, error) {
	if !act.IsHumanSession() {
		return secrets.Secret{}, notFound()
	}
	var secret secrets.Secret
	err := s.opts.DB.Update(ctx, func(tx *storage.Tx) error {
		entry, err := s.consumer(ctx, tx, act, id)
		if err != nil {
			return err
		}
		if entry.Grant.Status != "READY" || entry.secretRef == "" {
			return notFound()
		}
		secret, err = s.opts.Secrets.RevealOwned(ctx, entry.secretRef, secretOwner(id), secretPurpose)
		if err != nil {
			return err
		}
		if err := audit(ctx, tx, act, "consume", id, entry.operationID, entry.binding.NodeID); err != nil {
			return err
		}
		if err := s.opts.Secrets.Delete(ctx, tx, entry.secretRef); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE private_exports SET status='CONSUMED',secret_ref='',updated_at=? WHERE export_id=?`, storage.FormatTime(s.opts.Clock.Now()), id)
		return err
	})
	if err != nil {
		secret.Clear()
		return secrets.Secret{}, problemResult(err)
	}
	return secret, nil
}

func (s *Service) consumer(ctx context.Context, tx *storage.Tx, act actor.Actor, id string) (record, error) {
	entry, err := s.load(ctx, tx, id)
	if err != nil {
		return record{}, err
	}
	if entry.owner != act.ID || entry.sessionID != act.SessionID {
		return record{}, notFound()
	}
	now := s.opts.Clock.Now()
	if now.Before(entry.createdAt) || !now.Before(entry.Grant.ExpiresAt) {
		return record{}, notFound()
	}
	if err := s.session(ctx, tx, act.ID, act.SessionID); err != nil {
		return record{}, err
	}
	if err := s.opts.Authorize(ctx, act, entry.binding); err != nil {
		return record{}, err
	}
	return entry, nil
}

// Cancel 只取消原人类会话的交付，不自动移除已经导入的 SSH 公钥。
func (s *Service) Cancel(ctx context.Context, act actor.Actor, id string) error {
	if !act.IsHumanSession() {
		return notFound()
	}
	err := s.opts.DB.Update(ctx, func(tx *storage.Tx) error {
		entry, err := s.consumer(ctx, tx, act, id)
		if err != nil {
			return err
		}
		if entry.Grant.Status == "CONSUMED" || entry.Grant.Status == "CANCELED" {
			return notFound()
		}
		if entry.secretRef != "" {
			if err := s.opts.Secrets.Delete(ctx, tx, entry.secretRef); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE private_exports SET status='CANCELED',secret_ref='',updated_at=? WHERE export_id=?`, storage.FormatTime(s.opts.Clock.Now()), id); err != nil {
			return err
		}
		return audit(ctx, tx, act, "cancel", id, entry.operationID, entry.binding.NodeID)
	})
	return problemResult(err)
}
