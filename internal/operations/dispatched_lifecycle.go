// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 真实 executor 的只读生命周期派生 ========================

// DispatchedJobContext 只接受原正在执行的插件 job 私有快照。入口 ctx 约束
// 当次权限核验；成功的子上下文继承真实 executor 的取消、结束及更早期限。
// 调用方必须 release，并在每个业务步骤继续检查当前权限；这里不缓存撤权结论，
// 不从 RPC/JSON/持久 RUNNING 数据创建新的 executor，也不启动监视 goroutine。
func (s *Service) DispatchedJobContext(ctx context.Context, accepted DispatchedContext) (context.Context, context.CancelFunc, error) {
	if s == nil || s.clock == nil || ctx == nil {
		return nil, nil, problem.New(problem.Unavailable, "任务生命周期需要真实宿主执行上下文。")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, problem.From(err)
	}
	proof := accepted.runtimeProof
	if !sameCleanupSnapshot(accepted, proof) || proof.service != s || accepted.Action.Source != PluginSource ||
		accepted.Action.Mode != ModeJob || !s.cleanupRuntimeAlive(proof) {
		return nil, nil, dispatchDenied()
	}
	current, err := s.ResolveDispatched(ctx, proof.exact, accepted.OperationID)
	if err != nil {
		return nil, nil, err
	}
	defer current.Clear()
	if !sameCleanupSnapshot(accepted, current.runtimeProof) || current.runtimeProof.job != proof.job {
		return nil, nil, dispatchDenied()
	}

	s.runMu.Lock()
	job := s.running[accepted.OperationID]
	valid := job == proof.job && cleanupJobAlive(job) && job.context != nil && job.context.Err() == nil
	var executor context.Context
	if valid {
		executor = job.context
	}
	s.runMu.Unlock()
	remaining := accepted.Deadline.Sub(s.clock.Now())
	if !valid || remaining <= 0 {
		return nil, nil, dispatchDenied()
	}
	worker, release := context.WithTimeout(executor, remaining)
	// 派生之后再核对同一注册对象，替换/结束不能穿过查询与 Context 创建的接缝。
	s.runMu.Lock()
	valid = s.running[accepted.OperationID] == job && cleanupJobAlive(job) && job.context.Err() == nil
	s.runMu.Unlock()
	if !valid || ctx.Err() != nil || worker.Err() != nil {
		release()
		return nil, nil, dispatchDenied()
	}
	return worker, release, nil
}
