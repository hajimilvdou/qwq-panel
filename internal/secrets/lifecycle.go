// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"context"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 失败补偿与显式资源清除 ========================

// DiscardExtracted 只回收本次新建且没有持久资源引用的秘密。
// 写后报错、共享配置历史与并发提交都以事务内引用索引为准；重复清理安全。
func (s *Store) DiscardExtracted(ctx context.Context, extracted []Extracted) error {
	if len(extracted) == 0 {
		return nil
	}
	for _, item := range extracted {
		if err := checkRef(item.Ref); err != nil {
			return err
		}
		if err := validatePurpose(item.Purpose); err != nil {
			return err
		}
	}
	return s.db.Update(ctx, func(tx *storage.Tx) error {
		for _, item := range extracted {
			if _, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE id=? AND purpose=?
				AND NOT EXISTS (SELECT 1 FROM secret_references WHERE secret_id=secrets.id)`,
				string(item.Ref), item.Purpose); err != nil {
				return problem.Wrap(err)
			}
		}
		return nil
	})
}

// DeleteOwner 在调用者事务中显式清除资源所属秘密；默认卸载不调用此入口。
// 此函数无需密钥环，供卸载复用 Store 的同一删除实现。
func DeleteOwner(ctx context.Context, tx *storage.Tx, owner string) (int64, error) {
	if tx == nil {
		return 0, problem.New(problem.ValidationFailed, "A write transaction is required to delete secrets.")
	}
	if err := validateOwner(owner); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE owner=?`, owner)
	if err != nil {
		return 0, problem.Wrap(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, problem.Wrap(err)
	}
	return n, nil
}
