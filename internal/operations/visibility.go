// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 原动作授权与公共结果边界 ========================

// originalAction 复用持久化动作事实；目录换版不能改变历史结果的权限归属。
func originalAction(op *Operation) Action {
	action := op.Meta
	action.ID = op.Action
	action.Permission = op.Permission
	action.Effect = op.Effect
	action.Mode = op.Mode
	return action
}

// ResultRedactor 返回本次请求共用的结果脱敏器。发起者保留自己的结果；其他
// 读者必须通过原动作的当前授权。缓存包含动作、对象和节点，避免作用域串用。
// 授权器缺失、权限缺失或查询错误时隐藏结果，不改变持久化的 operation。
func (s *Service) ResultRedactor(ctx context.Context, who actor.Actor) func(*Operation) {
	type scope struct {
		permission, action, node, subject, plugin, effect string
	}
	allowed := make(map[scope]bool)
	return func(op *Operation) {
		if op == nil || len(op.Result) == 0 || samePrincipal(who, op.Actor) {
			return
		}
		action := originalAction(op)
		key := scope{action.Permission, action.ID, op.Target.NodeID, op.Target.Subject, action.PluginID, action.Effect}
		ok, seen := allowed[key]
		if !seen {
			ok = s.authorizer != nil && action.Permission != "" && s.authorize(ctx, who, action, op.Target) == nil
			allowed[key] = ok
		}
		if !ok {
			op.Result = nil
		}
	}
}

// ======================== 取消在幂等回放前重新授权 ========================

// authorizeCancellation 保留 AI 只能取消本人任务的契约；人类和服务账号还需
// 取消权限，跨主体取消额外要求原动作权限。权限查询失败不会触发任何写入。
func (s *Service) authorizeCancellation(ctx context.Context, who actor.Actor, op *Operation) error {
	if !canRead(who, op) {
		return notFound("operation")
	}
	if who.Kind != actor.AIAgent {
		action := Action{ID: "host.operations.cancel", Permission: "host.operations:cancel", Effect: EffectWrite}
		if err := s.authorize(ctx, who, action, op.Target); err != nil {
			return err
		}
	}
	if !samePrincipal(who, op.Actor) {
		action := originalAction(op)
		if s.authorizer == nil || action.Permission == "" {
			return problem.New(problem.PermissionDenied, "The operation's action cannot be authorized.")
		}
		return s.authorize(ctx, who, action, op.Target)
	}
	return nil
}
