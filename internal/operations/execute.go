// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"errors"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// executeCreated runs an operation that already exists: a job goes to the
// worker queue, a plugin invocation calls the dispatcher, and a host action
// (approved in the meantime) runs inside its own transaction.
func (s *Service) executeCreated(ctx context.Context, op *Operation) error {
	// 已持久化的 operation 与请求生命周期解耦：客户端断开不得让它卡在 RUNNING
	// 或丢失结果。用户主动 Cancel 仍经 s.running 里的 runCtx 生效（OPS-01）。
	ctx = context.WithoutCancel(ctx)
	switch {
	case op.Mode == ModeJob:
		// Plugin jobs stream from the dispatcher; host jobs run their own
		// executor on the same worker (GAPS gap 7).
		s.enqueue(ctx, op.ID)
		return nil
	case op.Meta.Source == PluginSource:
		return s.executePlugin(ctx, op)
	default:
		return s.executeHost(ctx, op)
	}
}

// resume continues an operation that was interrupted by a restart: jobs are
// queued for a worker, invocations and approved host actions run again. The
// status check inside executeCreated's helpers makes a repeated call harmless.
func (s *Service) resume(ctx context.Context, id string) {
	op, err := loadOperation(ctx, s.db.Reader(), id)
	if err != nil {
		s.log.ErrorContext(ctx, "operations: resume", "operation_id", id, "error", err)
		return
	}
	if isTerminal(op.Status) {
		return
	}
	if err := s.executeCreated(ctx, op); err != nil {
		s.log.WarnContext(ctx, "operations: resumed operation failed", "operation_id", id, "error", err)
	}
}

// executeHost runs a host action after it was approved: the handler and the
// terminal status share one transaction.
func (s *Service) executeHost(ctx context.Context, op *Operation) error {
	handler, ok := s.hostAction(op.Action)
	if !ok || handler.handler == nil {
		return s.recordFailure(ctx, op.ID, problem.New(problem.Unavailable,
			"The host action has no executor."))
	}
	err := s.withOperation(ctx, op.ID, func(ctx context.Context, tx *storage.Tx, cur *Operation) error {
		if isTerminal(cur.Status) {
			return nil
		}
		if err := s.checkOperationPreconditions(ctx, tx, cur); err != nil {
			return err
		}
		if err := s.checkExpectedRevision(ctx, tx, cur); err != nil {
			return err
		}
		if err := s.enterRunning(ctx, tx, cur); err != nil {
			return err
		}
		result, err := handler.handler(ctx, tx, s.interactiveHostRequest(ctx, cur))
		if err != nil {
			return err
		}
		if len(result) > 0 {
			cur.Result = result
		}
		return s.finishOperation(ctx, tx, cur, Succeeded, nil)
	})
	if err != nil {
		return s.recordFailure(ctx, op.ID, err)
	}
	return nil
}

// errSkip 表示 operation 已不处于可启动状态（终态或已在运行），调用方必须放弃执行。
var errSkip = errors.New("operations: not startable")

// executePlugin hands the operation to a plugin instance. The write
// transactions that bracket the call are short: RUNNING before, the result and
// the plugin's resource changes after (ADR-0008 §3).
func (s *Service) executePlugin(ctx context.Context, op *Operation) error {
	if s.dispatcher == nil {
		return s.recordFailure(ctx, op.ID, problem.New(problem.Unavailable,
			"No plugin dispatcher is configured."))
	}
	// 先注册再进入 RUNNING：两者之间到达的 Cancel 也能找到执行者。
	runCtx, cancel := context.WithTimeout(ctx, op.Timeout)
	defer cancel()
	if !s.registerRunningContext(op.ID, cancel, runCtx) {
		return nil
	}
	err := s.withOperation(ctx, op.ID, func(ctx context.Context, tx *storage.Tx, cur *Operation) error {
		if isTerminal(cur.Status) || cur.Status == Running {
			return errSkip
		}
		if err := s.checkOperationPreconditions(ctx, tx, cur); err != nil {
			return err
		}
		if err := s.checkExpectedRevision(ctx, tx, cur); err != nil {
			return err
		}
		return s.enterRunning(ctx, tx, cur)
	})
	if errors.Is(err, errSkip) {
		s.unregisterRunning(op.ID)
		return nil
	}
	if err != nil {
		s.unregisterRunning(op.ID)
		return s.recordFailure(ctx, op.ID, err)
	}

	res, invokeErr := s.dispatcher.Invoke(runCtx, s.dispatchRequest(op))
	s.unregisterRunning(op.ID)
	if invokeErr != nil {
		return s.recordFailure(ctx, op.ID, invokeErr)
	}

	err = s.withOperation(ctx, op.ID, func(ctx context.Context, tx *storage.Tx, cur *Operation) error {
		if err := s.applyChanges(ctx, tx, cur, res.Changes); err != nil {
			return err
		}
		if len(res.Result) > 0 {
			cur.Result = res.Result
		}
		return s.finishOperation(ctx, tx, cur, Succeeded, nil)
	})
	if err != nil {
		return s.recordFailure(ctx, op.ID, err)
	}
	return nil
}

// checkOperationPreconditions re-checks a plan's host-side preconditions at
// execution time, after the approval.
func (s *Service) checkOperationPreconditions(ctx context.Context, tx *storage.Tx, op *Operation) error {
	if op.PlanID == "" {
		return nil
	}
	plan, err := loadPlan(ctx, tx, op.PlanID)
	if err != nil {
		return err
	}
	return s.checkPlanPreconditions(ctx, tx, plan)
}

// withOperation loads the operation inside a write transaction, sets the
// transaction origin and runs fn. The row is always read inside the
// transaction, so a worker never acts on a stale copy.
func (s *Service) withOperation(ctx context.Context, id string, fn func(context.Context, *storage.Tx, *Operation) error) error {
	return s.db.Update(ctx, func(tx *storage.Tx) error {
		op, err := loadOperation(ctx, tx, id)
		if err != nil {
			return err
		}
		tx.SetOrigin(s.origin(op.Actor, op.ID, op.TraceID, op.NodeID))
		return fn(ctx, tx, op)
	})
}

// recordFailure marks an operation failed (or canceled, when a cancel was
// requested while it ran) and returns the problem that caused it.
func (s *Service) recordFailure(ctx context.Context, id string, cause error) error {
	ctx = context.WithoutCancel(ctx)
	werr := s.withOperation(ctx, id, func(ctx context.Context, tx *storage.Tx, op *Operation) error {
		if isTerminal(op.Status) {
			return nil
		}
		target := Failed
		if op.CancelRequested {
			target = Canceled
		}
		return s.failOperation(ctx, tx, op, target, cause)
	})
	if werr != nil {
		s.log.ErrorContext(ctx, "operations: record failure", "operation_id", id, "error", werr)
	}
	return withOperationID(problem.From(cause), id)
}

// registerRunning makes a running operation reachable from Cancel. It reports
// false when another executor in this process already holds the operation; the
// caller must then not run it.
func (s *Service) registerRunning(id string, cancel context.CancelFunc) bool {
	return s.registerRunningContext(id, cancel, nil)
}

// registerRunningContext 保存真实 executor 的子作用域；缺失 runCtx 的旧内部
// wrapper 仍可用于清理替换夹具，但不能兑换长任务生命周期。
func (s *Service) registerRunningContext(id string, cancel context.CancelFunc, runCtx context.Context) bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if _, ok := s.running[id]; ok {
		return false
	}
	var scoped context.Context
	var release context.CancelFunc
	if runCtx != nil {
		scoped, release = context.WithCancel(runCtx)
	}
	s.running[id] = &runningJob{context: scoped, release: release, cancel: cancel, done: make(chan struct{})}
	return true
}

// isRunning reports whether this process holds an executor for the operation.
func (s *Service) isRunning(id string) bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	_, ok := s.running[id]
	return ok
}

func (s *Service) unregisterRunning(id string) {
	var release context.CancelFunc
	s.runMu.Lock()
	if job, ok := s.running[id]; ok {
		close(job.done)
		delete(s.running, id)
		release = job.release
	}
	s.runMu.Unlock()
	// 原 executor 的结果提交/取消顺序不变；仅在锁外释放其所有能力子任务。
	if release != nil {
		release()
	}
}

// cancelRunning asks the dispatcher to stop a running operation and, after the
// grace period, cancels its context (ADR-0007 #15). It is best effort.
func (s *Service) cancelRunning(ctx context.Context, op *Operation) {
	s.runMu.Lock()
	job, ok := s.running[op.ID]
	s.runMu.Unlock()
	if !ok {
		return
	}
	if s.dispatcher != nil {
		cancelCtx, cancel := context.WithTimeout(ctx, s.cfg.JobCancelGrace)
		_ = s.dispatcher.Cancel(cancelCtx, PluginCancelRequest{
			OperationID: op.ID, NodeID: op.Target.NodeID, PluginID: op.Meta.PluginID,
			InstanceID: op.Target.InstanceID, Placement: op.Meta.Placement,
			Operation: op.Meta.Operation, APIVersion: op.Meta.APIVersion,
		})
		cancel()
	}
	go func() {
		select {
		case <-job.done:
		case <-s.clock.After(s.cfg.JobCancelGrace):
			job.cancel()
		}
	}()
}
