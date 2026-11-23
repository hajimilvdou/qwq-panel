// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/privateexport"
	"github.com/qwq-panel/qwq/internal/storage"
)

// hostSecurityPruner 复用既有 Sweep 定时器；不为私密交付和 WAL 截断新增常驻循环。
type hostSecurityPruner struct {
	identity operations.Pruner
	exports  *privateexport.Service
	db       *storage.DB
}

func (p hostSecurityPruner) Prune(ctx context.Context, now time.Time) error {
	if p.identity != nil {
		if err := p.identity.Prune(ctx, now); err != nil {
			return err
		}
	}
	if p.exports != nil {
		if _, err := p.exports.Prune(ctx); err != nil {
			return err
		}
	}
	if p.db != nil {
		// OPT-05: 周期性 PASSIVE WAL Checkpoint，防止长期运行后 qwq.db-wal 膨胀且不阻塞并发读写。
		_ = p.db.CheckpointPassive(ctx)
	}
	return nil
}
