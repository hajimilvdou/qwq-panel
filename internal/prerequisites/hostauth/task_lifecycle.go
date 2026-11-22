// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 固定 capability 路由与当前私有执行对象 ========================

// BeginCapability 只用 SQL 读取实际路由候选；运行权限仍由 Begin 的原
// executor proof/当前角色/策略校验取得。允许的动作名必须来自宿主固定表。
func (a *Authority) BeginCapability(ctx context.Context, metadata Invocation, allowed ...string) (context.Context, func(), error) {
	if a == nil || a.db == nil || a.operations == nil || ctx == nil || ctx.Err() != nil ||
		(metadata.PluginID != "domain.dns" && metadata.PluginID != "tls.certificates") ||
		metadata.InstanceID != operations.ControllerDispatchInstance || !names.ID(metadata.OperationID) ||
		metadata.Operation != "" || metadata.Subject != "" || len(allowed) == 0 || len(allowed) > 8 {
		return nil, nil, fault.New("PERMISSION_DENIED", "能力路由需要真实派发元数据与固定方法")
	}
	for index, name := range allowed {
		if name == "" || len(name) > 64 || strings.ContainsAny(name, "/\x00\r\n") || slices.Contains(allowed[:index], name) {
			return nil, nil, fault.New("PERMISSION_DENIED", "能力路由固定动作名单无效")
		}
	}
	var node, action string
	var rawAction, rawTarget []byte
	if err := a.db.Reader().QueryRowContext(ctx, "SELECT node_id, action, action_meta, target FROM operations WHERE operation_id=?", metadata.OperationID).
		Scan(&node, &action, &rawAction, &rawTarget); err != nil {
		return nil, nil, fault.New("PERMISSION_DENIED", "能力路由没有当前实际 operation")
	}
	defer clear(rawAction)
	defer clear(rawTarget)
	var declared operations.Action
	var target operations.Target
	if !strictObject(rawAction, &declared, 1<<20) || !strictObject(rawTarget, &target, 1<<20) || node != a.nodeID ||
		declared.Source != operations.PluginSource || declared.PluginID != metadata.PluginID ||
		declared.Placement != operations.PlacementController || !slices.Contains(allowed, declared.Operation) ||
		action != metadata.PluginID+"/"+declared.Operation || declared.ID != action || target.PluginID != metadata.PluginID ||
		(target.InstanceID != "" && target.InstanceID != metadata.InstanceID) || (target.NodeID != "" && target.NodeID != a.nodeID) ||
		!strings.HasPrefix(target.Subject, "plugins/"+metadata.PluginID+"/resources/") {
		return nil, nil, fault.New("PERMISSION_DENIED", "能力路由的插件、节点、动作或完整目标不符")
	}
	metadata.Operation, metadata.Subject = declared.Operation, target.Subject
	return a.Begin(ctx, metadata)
}

// CurrentInvocation 只返回当前已建立私有对象的固定路由，不输出 actor/Args。
func (a *Authority) CurrentInvocation(ctx context.Context) (Invocation, error) {
	value, err := a.current(ctx)
	if err != nil {
		return Invocation{}, err
	}
	value.mu.RLock()
	defer value.mu.RUnlock()
	if value.released || ctx.Err() != nil {
		return Invocation{}, fault.New("PERMISSION_DENIED", "能力执行来源已释放")
	}
	return value.invocation, nil
}

// AuthorizeCurrent 仅追加宿主固定权限检查；Actor 仍留在私有执行对象中，
// 此结果不能代替原 operation 的许可，也不生成另一运行 proof。
func (a *Authority) AuthorizeCurrent(ctx context.Context, permission string, resource authz.Resource) error {
	value, err := a.current(ctx)
	if err != nil {
		return err
	}
	value.mu.RLock()
	if value.released || ctx.Err() != nil || value.snapshot.Actor.Kind == actor.System {
		value.mu.RUnlock()
		return fault.New("PERMISSION_DENIED", "额外权限需要当前实际调用者")
	}
	who := value.snapshot.Actor
	value.mu.RUnlock()
	if err := a.authorizer.Authorize(ctx, who, permission, resource); err != nil {
		return err
	}
	latest, err := a.current(ctx)
	if err != nil {
		return err
	}
	latest.mu.RLock()
	defer latest.mu.RUnlock()
	if latest != value || latest.released || ctx.Err() != nil {
		return fault.New("PERMISSION_DENIED", "额外权限检查期间调用来源失效")
	}
	return nil
}

// JobContext 只兑换原插件 job 的真实生命周期；来源释放后不能重新兑换。
func (a *Authority) JobContext(ctx context.Context) (context.Context, func(), error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, nil, err
	}
	value.mu.RLock()
	defer value.mu.RUnlock()
	if value.released || ctx.Err() != nil {
		return nil, nil, fault.New("PERMISSION_DENIED", "任务来源已经释放")
	}
	return a.operations.DispatchedJobContext(ctx, value.snapshot)
}

// TaskBudget 返回不可作为权限的内部分组及容量预算，避免监视器耗尽默认委托限速。
func (a *Authority) TaskBudget(ctx context.Context, interval time.Duration) (string, int, error) {
	if interval < 100*time.Millisecond || interval > 5*time.Second {
		return "", 0, fault.New("VALIDATION_FAILED", "授权监视间隔超出有界范围")
	}
	value, err := a.current(ctx)
	if err != nil {
		return "", 0, err
	}
	value.mu.RLock()
	if value.released || ctx.Err() != nil {
		value.mu.RUnlock()
		return "", 0, fault.New("PERMISSION_DENIED", "任务预算的调用来源已经释放")
	}
	who := value.snapshot.Actor
	value.mu.RUnlock()
	sum := sha256.Sum256([]byte(string(who.Kind) + "\x00" + who.ID))
	group := hex.EncodeToString(sum[:])
	if who.Kind != actor.AIAgent {
		return group, 8, nil
	}
	delegation, err := a.authorizer.Delegation(ctx, who.ID)
	if err != nil {
		return "", 0, err
	}
	// ResolveDispatched 每轮真实核验至少两次角色/委托；为实际业务保留一半预算。
	checks := int((time.Minute+interval-1)/interval) * 2
	capacity := int(delegation.Policy.Normalized().RequestsPerMinute) / (checks * 2)
	if capacity < 1 {
		return "", 0, fault.New("RATE_LIMITED", "委托请求预算不足以维持任务授权监视")
	}
	return group, min(8, capacity), nil
}

// TaskArgs 只选择当前任务，不提供 actor、owner、路径或另一运行许可。
type TaskArgs struct {
	TaskID string `json:"task_id"`
}

// DecodePersistedObject 复用现有有界、重复成员/未知字段拒绝的状态边界。
func DecodePersistedObject(raw []byte, destination any, limit int) bool {
	return strictObject(raw, destination, limit)
}

// CheckTaskIntent 复核新查询/取消 operation 的固定任务目标。
func (a *Authority) CheckTaskIntent(ctx context.Context, taskID, certificateID string) error {
	value, err := a.current(ctx)
	if err != nil {
		return err
	}
	input, err := DecodeArguments[TaskArgs](ctx, a)
	if err != nil {
		return err
	}
	if !names.ID(taskID) || !names.ID(certificateID) || input.TaskID != taskID || value.invocation.PluginID != "tls.certificates" ||
		(value.invocation.Operation != "tasks.get" && value.invocation.Operation != "tasks.cancel") ||
		value.invocation.Subject != "plugins/tls.certificates/resources/tasks/"+taskID {
		return fault.New("PERMISSION_DENIED", "任务读取或取消不属于原已接受意图")
	}
	return nil
}
