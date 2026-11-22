// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"context"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 同事务人类权限；身份核验由登录服务负责 ========================

// TransactionalPrincipalSource 读取调用方事务中的角色，不打开第二写事务。
type TransactionalPrincipalSource interface {
	PrincipalRoleTx(context.Context, *storage.Tx, string) (string, bool, error)
}

// AuthorizeHumanTx 复用普通 RBAC 规则，读取尚未提交的禁用或角色变更。
// 它只验证权限，不把 actor/session 元数据解释为已认证的登录会话。
func (z *Authorizer) AuthorizeHumanTx(ctx context.Context, tx *storage.Tx, who actor.Actor, permission string) error {
	if z == nil || ctx == nil || tx == nil || who.Kind != actor.Human || who.ID == "" {
		return deny("human permission requires the current transaction")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	perm, err := ParsePermission(permission)
	if err != nil {
		return err
	}
	role, disabled, err := z.principalRoleTx(ctx, tx, who.ID)
	if err != nil {
		return err
	}
	return checkHumanRole(role, disabled, perm)
}

func (z *Authorizer) principalRoleTx(ctx context.Context, tx *storage.Tx, id string) (string, bool, error) {
	source, ok := z.principals.(TransactionalPrincipalSource)
	if !ok || source == nil {
		return "", false, deny("transactional principal source is unavailable")
	}
	role, disabled, err := source.PrincipalRoleTx(ctx, tx, id)
	if err != nil {
		return "", false, z.fail(ctx, "load transactional principal", err)
	}
	return role, disabled, nil
}

// AuthorizeDelegationOwnerTx 用宿主保存的原 owner 事实检查当前对象范围。
// 它不替代全局 RBAC 或登录认证；调用方须先通过 AuthorizeHumanTx。
func (z *Authorizer) AuthorizeDelegationOwnerTx(ctx context.Context, tx *storage.Tx, who actor.Actor, ownerID string) error {
	if z == nil || tx == nil || who.Kind != actor.Human || who.ID == "" || ownerID == "" {
		return deny("stored delegation owner is unavailable")
	}
	return mayManageDelegationOwner(who, ownerID, func() (string, bool, error) {
		return z.principalRoleTx(ctx, tx, who.ID)
	})
}
