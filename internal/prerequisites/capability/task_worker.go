// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"
	"errors"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/contextbudget"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 有界监视、真实工作与私有最终收据 ========================

const taskProgressInterval = time.Second

func (m *Tasks) monitor(work *runningTask, done <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-work.ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if _, err := m.authority.CurrentInvocation(work.ctx); err != nil {
				work.cancel()
				return
			}
		}
	}
}

// safeRunTask 只隔离当前同步执行器的 panic；固定错误文本不包含 panic 值。
func safeRunTask(executor TaskExecutor, work *runningTask, progress certificates.Progress) (err error) {
	defer func() {
		if recover() != nil {
			err = fault.New("INTERNAL", "证书任务执行器发生内部错误")
		}
	}()
	record, _ := work.snapshot()
	_, err = executor.RunTask(work.ctx, record.Kind, record.CertificateID, record.AttemptID, record.ExpectedRevision, progress)
	return err
}

// persistTaskLocked 仅在写入成功时推进 CAS 版本；失败不丢失最后确认的版本。
func (m *Tasks) persistTaskLocked(ctx context.Context, work *runningTask) error {
	revision, err := m.saveTask(ctx, work.record, work.revision)
	if err != nil {
		return err
	}
	work.revision, work.lastPersisted = revision, m.clock.Now()
	return nil
}

func (m *Tasks) progress(work *runningTask) certificates.Progress {
	return func(stage string, percent uint32) error {
		work.mu.Lock()
		defer work.mu.Unlock()
		if work.finished {
			return fault.New("STATE_CONFLICT", "任务已结束，不能再报告进度")
		}
		if work.progressErr != nil {
			return work.progressErr
		}
		if err := work.ctx.Err(); err != nil {
			return err
		}
		fail := func(err error) error {
			work.progressErr = err
			work.cancel()
			return err
		}
		if percent < work.record.Percent || percent > 100 || !validTaskStage(stage) || stage == "queued" || stage == "completed" {
			return fail(fault.New("STATE_INVALID", "任务进度阶段或百分比无效"))
		}
		if stage == work.record.Stage && percent == work.record.Percent {
			return nil
		}
		due := m.clock.Now().Sub(work.lastPersisted) >= taskProgressInterval
		// 阶段切换与每次持久进度都重新授权；同阶段本地百分比不额外消耗委托限速。
		if stage != work.record.Stage || due {
			if _, err := m.authority.CurrentInvocation(work.ctx); err != nil {
				return fail(err)
			}
		}
		work.record.Stage, work.record.Percent = stage, percent
		if due {
			if err := m.persistTaskLocked(work.ctx, work); err != nil {
				return fail(err)
			}
		}
		return nil
	}
}

func taskFailure(err error, now time.Time) (string, time.Time) {
	code, retry := fault.Code(err), fault.Retry(err)
	var hostFailure *problem.Error
	if errors.As(err, &hostFailure) && hostFailure.Code.Known() {
		code = string(hostFailure.Code)
		if retry.IsZero() && hostFailure.RetryAfterSec > 0 && hostFailure.RetryAfterSec <= 86400 {
			retry = now.Add(time.Duration(hostFailure.RetryAfterSec) * time.Second)
		}
	}
	if code == "" || !validTaskErrorCode(code) {
		code = "INTERNAL"
	}
	return code, retry
}

func (m *Tasks) run(work *runningTask) {
	monitorDone := make(chan struct{})
	monitorStopped := make(chan struct{})
	go m.monitor(work, monitorDone, monitorStopped)
	work.mu.Lock()
	work.record.State, work.record.Stage = "running", "starting"
	err := m.persistTaskLocked(work.ctx, work)
	work.mu.Unlock()
	if err == nil {
		if _, err = m.authority.CurrentInvocation(work.ctx); err == nil {
			err = safeRunTask(m.executor, work, m.progress(work))
		}
	}
	close(monitorDone)
	<-monitorStopped
	if err == nil {
		_, err = m.authority.CurrentInvocation(work.ctx)
	}
	work.mu.Lock()
	work.finished = true
	if work.progressErr != nil {
		err = work.progressErr
	}
	if err != nil {
		work.record.State = "failed"
		work.record.ErrorCode, work.record.RetryAt = taskFailure(err, m.clock.Now())
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			work.record.State, work.record.ErrorCode = "cancelled", "CANCELLED"
		}
		var failure *fault.Error
		if work.record.ErrorCode == "OUTCOME_UNKNOWN" || (errors.As(err, &failure) && failure.Uncertain) {
			work.record.State = "outcome_unknown"
		}
	} else {
		work.record.State, work.record.Stage, work.record.Percent = "succeeded", "completed", 100
	}
	// 这里只保存原任务的最终收据，不获取普通权限，不进行外部请求或延长原期限。
	finalCtx, stop := contextbudget.Detached(work.ctx, 2*time.Second)
	finalErr := m.persistTaskLocked(finalCtx, work)
	stop()
	if finalErr != nil {
		work.record.State, work.record.ErrorCode = "outcome_unknown", "OUTCOME_UNKNOWN"
	}
	id := work.record.ID
	work.mu.Unlock()
	work.release()
	m.mu.Lock()
	if finalErr != nil && m.drainErr == nil {
		m.drainErr = fault.New("TASK_PERSISTENCE_FAILED", "任务最终收据保存失败，需要核对原任务状态")
	}
	delete(m.active, id)
	if len(m.active) == 0 {
		close(m.idle)
	}
	m.mu.Unlock()
}
