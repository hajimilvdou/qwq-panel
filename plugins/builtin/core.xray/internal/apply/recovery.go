// SPDX-License-Identifier: AGPL-3.0-only

package apply

import (
	"context"
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/coreproc"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xrayconfig"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// Activate 只从已提交快照恢复；没有 Host 和 operation，也不能揭示新秘密。
func (e *Engine) Activate(ctx context.Context) (err error) {
	unlock, err := e.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	e.mu.Lock()
	if e.active {
		e.mu.Unlock()
		return nil
	}
	e.lifetime, e.cancel = context.WithCancel(context.Background())
	e.active = true
	e.serial++
	e.busy = true
	e.mu.Unlock()
	defer e.endMutation()
	defer func() {
		if err != nil {
			e.Cancel()
			e.setFailure("RECOVERY_FAILED")
		}
	}()
	metadata, err := e.options.Store.Committed(ctx)
	if err != nil {
		return stateFailure(err)
	}
	if err := e.options.Store.CleanAbandonedWork(ctx); err != nil {
		return stateFailure(err)
	}
	if err := e.options.Store.Prune(ctx, metadata); err != nil {
		return stateFailure(err)
	}
	if metadata == nil || !metadata.Current.Enabled {
		return nil
	}
	if e.options.Binary == nil {
		return failure("CORE_BINARY_MISMATCH", nil)
	}
	if err := e.start(ctx, metadata.Current); err != nil {
		if cleanupErr := e.stopBounded(ctx); cleanupErr != nil {
			return failure("RECOVERY_FAILED", contextCause(ctx))
		}
		return err
	}
	if err := e.options.Process.WaitHealthy(ctx); err != nil {
		_ = e.stopBounded(ctx)
		return failure("RECOVERY_FAILED", contextCause(ctx))
	}
	observed := e.options.Process.Snapshot(ctx)
	if observed.State != "RUNNING" || observed.APIState != "READY" || observed.Digest != metadata.Current.Digest {
		_ = e.stopBounded(ctx)
		return failure("RECOVERY_FAILED", nil)
	}
	if metadata.Current.SummaryV2 != nil {
		if err := e.restartObfsForSummary(metadata.Current.SummaryV2); err != nil {
			_ = e.stopBounded(ctx)
			return failure("RECOVERY_FAILED", err)
		}
		if err := e.restartAnyTLSForSummary(ctx, metadata.Current.SummaryV2); err != nil {
			_ = e.stopBounded(ctx)
			return failure("RECOVERY_FAILED", err)
		}
	}
	updated := cloneMetadata(metadata)
	updated.State, updated.LastError, updated.ResetEpoch = "RUNNING", "", observed.Epoch
	if err := e.options.Store.Commit(ctx, updated); err != nil {
		_ = e.stopBounded(ctx)
		return failure("STATE_COMMIT_FAILED", contextCause(ctx))
	}
	if err := e.options.Process.MarkCommitted(); err != nil {
		_ = e.stopBounded(ctx)
		return failure("RECOVERY_FAILED", nil)
	}
	e.setFailure("")
	return nil
}

// Cancel 可在 SDK 后台 context 取消时立即调用，写事务会进入有界补偿。
func (e *Engine) Cancel() {
	e.mu.Lock()
	e.active = false
	e.serial++
	if e.cancel != nil {
		e.cancel()
	}
	e.mu.Unlock()
}
func (e *Engine) Deactivate(ctx context.Context) error {
	e.Cancel()
	unlock, err := e.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	e.beginMutation()
	defer e.endMutation()
	return e.stop(ctx)
}
func (e *Engine) Active() bool    { e.mu.Lock(); defer e.mu.Unlock(); return e.active }
func (e *Engine) Failure() string { e.mu.Lock(); defer e.mu.Unlock(); return e.failure }
func (e *Engine) Busy() bool      { e.mu.Lock(); defer e.mu.Unlock(); return e.busy }
func (e *Engine) Observe() Observation {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Observation{e.serial, e.busy, e.active, e.failure}
}
func (e *Engine) beginMutation()         { e.mu.Lock(); e.serial++; e.busy = true; e.mu.Unlock() }
func (e *Engine) endMutation()           { e.mu.Lock(); e.serial++; e.busy = false; e.mu.Unlock() }
func (e *Engine) setFailure(code string) { e.mu.Lock(); e.failure = code; e.mu.Unlock() }

func (e *Engine) lock(ctx context.Context) (func(), error) {
	select {
	case <-ctx.Done():
		return nil, failure("CANCELLED", ctx.Err())
	case <-e.gate:
		if ctx.Err() != nil {
			e.gate <- struct{}{}
			return nil, failure("CANCELLED", ctx.Err())
		}
		return func() { e.gate <- struct{}{} }, nil
	}
}
func (e *Engine) step(ctx context.Context, request Request, step Step) error {
	if ctx.Err() != nil || !e.Active() {
		return failure("CANCELLED", contextCause(ctx))
	}
	if e.options.Before != nil {
		if err := e.options.Before(ctx, step); err != nil {
			return failure("APPLY_ABORTED", contextCause(ctx))
		}
	}
	if request.Progress != nil {
		if err := request.Progress(step); err != nil {
			return failure("CANCELLED", contextCause(ctx))
		}
	}
	if ctx.Err() != nil || !e.Active() {
		return failure("CANCELLED", ctx.Err())
	}
	return nil
}
func generationInboundID(generation *state.Generation) string {
	if generation == nil {
		return ""
	}
	if generation.Summary != nil {
		return generation.Summary.InboundID
	}
	if generation.SummaryV2 != nil {
		for _, p := range generation.SummaryV2.Profiles {
			if p.Enabled && p.Protocol != corev2.ProtocolAnyTLS {
				return p.ID
			}
		}
		if len(generation.SummaryV2.Profiles) > 0 {
			return "api-only"
		}
	}
	return ""
}

func (e *Engine) start(ctx context.Context, generation *state.Generation) error {
	path, err := e.options.Store.GenerationPath(ctx, generation.Digest)
	if err != nil {
		return stateFailure(err)
	}
	if err := e.options.Process.Start(ctx, coreproc.StartSpec{ConfigPath: path, Digest: generation.Digest, InboundID: generationInboundID(generation)}); err != nil {
		return failure("CORE_START_FAILED", contextCause(ctx))
	}
	return nil
}
func (e *Engine) stop(ctx context.Context) error {
	if e.options.AnyTLS != nil {
		e.options.AnyTLS.StopAll(3 * time.Second)
	}
	if e.options.Obfs != nil {
		e.options.Obfs.StopAll(3 * time.Second)
	}
	if err := e.options.Process.Stop(ctx); err != nil {
		if e.options.Process.Snapshot(ctx).State != "STOPPED" {
			return failure("CORE_STOP_FAILED", contextCause(ctx))
		}
	}
	return nil
}
func (e *Engine) stopBounded(ctx context.Context) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return e.stop(cleanup)
}

// persistRecoveryFailure 仅标记已经核验的提交快照，不猜测候选；磁盘不可写时仍保留内存故障。
// 同步宿主投影失败不能反杀已恢复的数据面，保存运行事实并明确记录故障。
func (e *Engine) persistRecoveryFailure(ctx context.Context, recovered *state.Metadata) {
	// 总预算过期只代表本次补偿超时，不能把过期探测伪装成真实 API 故障。
	probe, stopProbe := boundedHostContext(context.WithoutCancel(ctx))
	observed := e.options.Process.Snapshot(probe)
	stopProbe()
	preserve := recovered != nil && recovered.State == "RUNNING" && e.Active() &&
		runtimeMatches(recovered, observed) && observed.Epoch == recovered.ResetEpoch
	if !preserve && (observed.State == "RUNNING" || observed.State == "STARTING" || observed.State == "STOPPING") {
		_ = e.stopBounded(ctx)
	}
	// 总补偿预算耗尽后，故障记账仍有独立的两秒边界；不能使用已过期的 context。
	persist, cancel := boundedHostContext(context.WithoutCancel(ctx))
	defer cancel()
	metadata, err := e.options.Store.Committed(persist)
	if err == nil && metadata != nil {
		metadata.State, metadata.LastError = "FAILED", "RECOVERY_FAILED"
		if preserve && metadata.Current.Digest == recovered.Current.Digest &&
			metadata.Current.Revision == recovered.Current.Revision && metadata.ResetEpoch == recovered.ResetEpoch {
			metadata.State = "RUNNING"
		}
		_ = e.options.Store.Commit(persist, metadata)
	}
}

// recover 先恢复指针，再恢复进程，防止补偿途中重启拾取已取消候选。
func (tx *transaction) recover(ctx context.Context) (bool, error) {
	e := tx.engine
	restored := cloneMetadata(tx.old)
	rollback := false
	if tx.processTouched {
		if err := e.stop(ctx); err != nil {
			return false, err
		}
		if err := e.options.Store.Restore(ctx, restored); err != nil {
			return false, err
		}
		if restored != nil {
			if restored.Current.Enabled && e.Active() {
				if err := e.start(ctx, restored.Current); err != nil {
					return false, err
				}
				if err := e.options.Process.WaitHealthy(ctx); err != nil {
					return false, err
				}
				observed := e.options.Process.Snapshot(ctx)
				if observed.State != "RUNNING" || observed.APIState != "READY" || observed.Digest != restored.Current.Digest {
					return false, failure("RECOVERY_FAILED", nil)
				}
				oldPlans := tx.oldObfsPlans
				if len(oldPlans) == 0 && restored.Current.SummaryV2 != nil {
					oldPlans = restored.Current.SummaryV2.ObfsPlans()
				}
				if e.options.Obfs != nil && len(oldPlans) > 0 {
					e.mu.Lock()
					lifetime := e.lifetime
					e.mu.Unlock()
					if err := e.options.Obfs.StartAll(lifetime, oldPlans); err != nil {
						return false, failure("RECOVERY_FAILED", err)
					}
					e.mu.Lock()
					e.obfsPlans = append([]xrayconfig.ObfsPlan(nil), oldPlans...)
					e.mu.Unlock()
				}
				if e.options.AnyTLS != nil && len(tx.oldAnyTLSSpecs) > 0 {
					e.mu.Lock()
					lifetime := e.lifetime
					e.mu.Unlock()
					if err := e.options.AnyTLS.StartAll(lifetime, tx.oldAnyTLSSpecs); err != nil {
						return false, failure("RECOVERY_FAILED", err)
					}
					e.mu.Lock()
					oldStored := e.anytlsSpecs
					e.anytlsSpecs = cloneAnyTLSSpecs(tx.oldAnyTLSSpecs)
					e.mu.Unlock()
					e.persistAnyTLSSpecs(tx.oldAnyTLSSpecs)
					clearAnyTLSSpecs(oldStored)
				} else if e.options.AnyTLS != nil && restored.Current.SummaryV2 != nil {
					if err := e.restartAnyTLSForSummary(ctx, restored.Current.SummaryV2); err != nil {
						return false, failure("RECOVERY_FAILED", err)
					}
				}
				restored.State, restored.LastError, restored.ResetEpoch = "RUNNING", "", observed.Epoch
				if err := e.options.Store.Commit(ctx, restored); err != nil {
					return false, err
				}
				if err := e.options.Process.MarkCommitted(); err != nil {
					return false, err
				}
				tx.recovered = restored
				rollback = true
			} else if !restored.Current.Enabled {
				rollback = true
			}
		}
	} else if tx.stateAttempted {
		e.persistAnyTLSSpecs(tx.oldAnyTLSSpecs)
		if err := e.options.Store.Restore(ctx, restored); err != nil {
			return false, err
		}
	}
	// 未替换的旧进程也已完成健康检查；恢复原快照后仍须核同一代次和存活标记。
	if !tx.processTouched && restored != nil && restored.State == "RUNNING" && e.Active() {
		observed := e.options.Process.Snapshot(ctx)
		if runtimeMatches(restored, observed) && observed.Epoch == restored.ResetEpoch {
			if err := e.options.Process.MarkCommitted(); err != nil {
				return false, err
			}
			tx.recovered = restored
		}
	}
	if tx.hostAttempted || tx.processTouched && tx.beforeHost.found {
		candidate := RunningRecord{}
		if tx.next != nil {
			candidate = recordFor(tx.next)
		}
		if err := restoreHost(ctx, tx.request.Host, tx.beforeHost, candidate, restored); err != nil {
			return false, err
		}
	}
	if tx.reportAttempted {
		if err := report(ctx, tx.request.Host, restored); err != nil {
			return false, err
		}
	}
	if tx.staged {
		if err := e.options.Store.CleanWork(ctx, tx.request.OperationID, tx.request.Attempt); err != nil {
			return false, err
		}
	}
	if tx.installed {
		if err := e.options.Store.Prune(ctx, restored); err != nil {
			return false, err
		}
	}
	return rollback, nil
}

func (e *Engine) result(metadata *state.Metadata, started, restarted bool) Result {
	observed := e.options.Process.Snapshot(context.Background())
	result := Result{DesiredRevision: metadata.Current.Revision, RunningRevision: metadata.Current.Revision, ConfigDigest: metadata.Current.Digest, CoreVersion: metadata.Current.Version, Enabled: metadata.Current.Enabled, ProcessState: observed.State, APIState: observed.APIState, ResetEpoch: metadata.ResetEpoch, RestartRequired: restarted, Restarted: restarted, Started: started, Warnings: []string{}}
	if metadata.Previous != nil {
		result.PreviousRevision = metadata.Previous.Revision
	}
	return result
}

func (e *Engine) maintain(ctx context.Context, metadata *state.Metadata, result *Result) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if e.options.Store.Prune(cleanup, metadata) != nil {
		result.Warnings = append(result.Warnings, "GENERATION_CLEANUP_PENDING")
	}
}
func report(ctx context.Context, host Host, metadata *state.Metadata) error {
	revision := ""
	if metadata != nil {
		revision = metadata.Current.Revision
	}
	call, cancel := boundedHostContext(ctx)
	defer cancel()
	return host.ReportChanges(call, pluginsdk.ResourceChange{Subject: "config/current", Revision: revision, Deleted: metadata == nil}, pluginsdk.ResourceChange{Subject: "runtime/current", Revision: revision, Deleted: metadata == nil})
}
func cloneMetadata(metadata *state.Metadata) *state.Metadata {
	if metadata == nil {
		return nil
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return nil
	}
	var clone state.Metadata
	if json.Unmarshal(data, &clone) != nil {
		return nil
	}
	return &clone
}
