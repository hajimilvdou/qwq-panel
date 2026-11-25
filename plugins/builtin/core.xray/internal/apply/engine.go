// SPDX-License-Identifier: AGPL-3.0-only

package apply

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/xraycore/anytls"
	"github.com/qwq-panel/qwq/internal/xraycore/coreproc"
	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/internal/xraycore/xrayconfig"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/secretmap"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// New 不创建文件或进程；所有资源从已验证的窄依赖供给。
// Binary 允许为空（降级态启动），在 Execute / Activate 阶段再返回明确的 CORE_BINARY_MISMATCH。
func New(options Options) (*Engine, error) {
	if options.Store == nil || options.Process == nil || !xrayconfig.ValidSocket(options.Socket) {
		return nil, failure("DATA_DIR_UNAVAILABLE", nil)
	}
	if options.Render == nil {
		options.Render = xrayconfig.Render
	}
	if options.RenderV2 == nil {
		options.RenderV2 = xrayconfig.RenderV2
	}
	engine := &Engine{options: options, gate: make(chan struct{}, 1), tlsBindings: make(map[string]TLSBindingStatus)}
	engine.gate <- struct{}{}
	return engine, nil
}

type transaction struct {
	engine          *Engine
	request         Request
	old             *state.Metadata
	beforeHost      hostSnapshot
	next            *state.Metadata
	work            state.Work
	staged          bool
	installed       bool
	processTouched  bool
	stateAttempted  bool
	hostAttempted   bool
	reportAttempted bool
	started         bool
	restarted       bool
	oldObfsPlans    []xrayconfig.ObfsPlan
	nextObfsPlans   []xrayconfig.ObfsPlan
	oldAnyTLSSpecs  []anytls.ProfileSpec
	nextAnyTLSSpecs []anytls.ProfileSpec
	// 恢复证明只在私有快照和原进程代次均已确认后设置。
	recovered *state.Metadata
}

// Execute 串行变更一个实例；失败补偿使用保留调用身份的独立有界 context。
func (e *Engine) Execute(parent context.Context, request Request) (result Result, err error) {
	unlock, err := e.lock(parent)
	if err != nil {
		return result, err
	}
	defer unlock()
	e.beginMutation()
	defer e.endMutation()
	e.mu.Lock()
	active, lifetime := e.active, e.lifetime
	prevObfs := append([]xrayconfig.ObfsPlan(nil), e.obfsPlans...)
	prevAnyTLS := cloneAnyTLSSpecs(e.anytlsSpecs)
	e.mu.Unlock()
	if !active || request.Host == nil || !state.ValidRevision(request.ConfigRevision) || !validOperation(request.OperationID) || request.Attempt == 0 {
		clearAnyTLSSpecs(prevAnyTLS)
		return result, failure("INSTANCE_NOT_ACTIVE", nil)
	}
	ctx, cancel := context.WithCancel(parent)
	stopLifetime := context.AfterFunc(lifetime, cancel)
	defer stopLifetime()
	defer cancel()
	tx := &transaction{engine: e, request: request, oldObfsPlans: prevObfs, oldAnyTLSSpecs: prevAnyTLS}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = failure("INTERNAL", nil)
		}
		if err != nil {
			clearAnyTLSSpecs(tx.nextAnyTLSSpecs)
			tx.nextAnyTLSSpecs = nil
			original := ErrorCode(err)
			if original == "" {
				original = "APPLY_FAILED"
			}
			cleanup, stop := context.WithTimeout(context.WithoutCancel(parent), 25*time.Second)
			rollback, recoveryErr := tx.recover(cleanup)
			if recoveryErr != nil {
				e.persistRecoveryFailure(cleanup, tx.recovered)
			}
			stop()
			clearAnyTLSSpecs(tx.oldAnyTLSSpecs)
			tx.oldAnyTLSSpecs = nil
			code := original
			if recoveryErr != nil {
				code = "RECOVERY_FAILED"
				rollback = false
			}
			revision := ""
			if tx.old != nil {
				revision = tx.old.Current.Revision
			}
			err = &Error{Code: code, RollbackPerformed: rollback, RunningRevision: revision, cause: contextCause(parent)}
			e.setFailure(code)
		}
	}()
	if err = e.step(ctx, request, LoadDesired); err != nil {
		return result, err
	}
	desired, err := loadDesiredAny(ctx, request)
	if err != nil {
		return result, err
	}
	if err = e.step(ctx, request, CheckPreconditions); err != nil {
		return result, err
	}
	tx.old, err = e.options.Store.Committed(ctx)
	if err != nil {
		return result, stateFailure(err)
	}
	if err = checkRunning(request, tx.old); err != nil {
		return result, err
	}
	tx.beforeHost, err = readHost(ctx, request.Host)
	if err != nil {
		return result, err
	}
	var summary *state.IntentSummary
	var summaryV2 *state.V2IntentSummary
	var same bool
	if desired.v1 != nil {
		summary, err = state.Summarize(desired.v1)
		if err != nil {
			return result, failure("INVALID_INTENT", nil)
		}
		same = sameDesired(tx.old, request.ConfigRevision, desired.v1, summary)
	} else {
		summaryV2, err = state.SummarizeV2(desired.v2)
		if err != nil {
			return result, failure("INVALID_INTENT", nil)
		}
		same = sameDesiredV2(tx.old, request.ConfigRevision, desired.v2, summaryV2)
	}
	observed := e.options.Process.Snapshot(ctx)
	// 已提交摘要覆盖完整逻辑 Intent；版本、快照与实际进程一致才可幂等返回。
	if same && runtimeMatches(tx.old, observed) {
		tx.next = cloneMetadata(tx.old)
		tx.next.ResetEpoch = observed.Epoch
		if tx.next.ResetEpoch != tx.old.ResetEpoch {
			tx.stateAttempted = true
			if err = e.options.Store.Commit(ctx, tx.next); err != nil {
				return result, failure("STATE_COMMIT_FAILED", contextCause(ctx))
			}
		}
		if !sameHost(tx.beforeHost, ptrRecord(recordFor(tx.next))) {
			if err = e.commitExisting(ctx, tx); err != nil {
				return result, err
			}
		}
		e.setFailure("")
		result = e.result(tx.next, false, false)
		e.maintain(ctx, tx.next, &result)
		return result, nil
	}
	if err = e.step(ctx, request, RevealSecrets); err != nil {
		return result, err
	}
	var native []byte
	var loadedTLS map[string]TLSBindingStatus
	if desired.v1 != nil {
		materials, merr := secretmap.Load(ctx, desired.v1, request.Host)
		if merr != nil {
			return result, failure("SECRET_UNAVAILABLE", contextCause(ctx))
		}
		defer materials.Clear()
		if err = e.step(ctx, request, RenderCandidate); err != nil {
			return result, err
		}
		native, err = e.options.Render(desired.v1, materials, xrayconfig.Options{APISocket: e.options.Socket})
		materials.Clear()
		if err != nil {
			return result, failure("CORE_CONFIG_INVALID", nil)
		}
	} else {
		loadedTLS = make(map[string]TLSBindingStatus)
		loader := &consumerDirTLSLoader{engine: e, loaded: loadedTLS, dataDir: e.options.DataDir}
		materialsV2, merr := secretmap.LoadV2(ctx, desired.v2, request.Host, loader)
		if merr != nil {
			if code := ErrorCode(merr); code != "" {
				return result, failure(code, contextCause(ctx))
			}
			return result, failure("SECRET_UNAVAILABLE", contextCause(ctx))
		}
		defer materialsV2.Clear()
		if err = e.step(ctx, request, RenderCandidate); err != nil {
			return result, err
		}
		v2Opts := xrayconfig.V2Options{
			Options:                xrayconfig.Options{APISocket: e.options.Socket},
			Now:                    e.now(),
			PermitTestCertificates: e.options.PermitTestCertificates,
			ObfsTargets:            xrayconfig.AllocateObfsTargets(desired.v2),
			SkipSocketMark:         e.options.EnforceSocketMarkProbe && !probeSocketMarkPermitted(),
		}
		if e.options.OutboundPolicy != nil {
			v2Opts.OutboundPolicy = e.options.OutboundPolicy()
		}
		obfsPlans, perr := xrayconfig.PlanObfs(desired.v2, v2Opts)
		if perr != nil {
			materialsV2.Clear()
			return result, failure("CORE_CONFIG_INVALID", nil)
		}
		if *desired.v2.Enabled && len(obfsPlans) > 0 && e.options.Obfs == nil {
			materialsV2.Clear()
			return result, failure("OBFS_UNAVAILABLE", nil)
		}
		if *desired.v2.Enabled {
			tx.nextObfsPlans = obfsPlans
			tx.nextAnyTLSSpecs = buildAnyTLSSpecs(desired.v2, materialsV2)
		}
		native, err = e.options.RenderV2(desired.v2, materialsV2, v2Opts)
		materialsV2.Clear()
		if err != nil {
			return result, failure("CORE_CONFIG_INVALID", nil)
		}
	}
	defer clear(native)
	if err = e.step(ctx, request, WriteWork); err != nil {
		return result, err
	}
	tx.staged = true
	tx.work, err = e.options.Store.Stage(ctx, request.OperationID, request.Attempt, native)
	if err != nil {
		return result, stateFailure(err)
	}
	clear(native)
	if err = e.step(ctx, request, NativeTest); err != nil {
		return result, err
	}
	if e.options.Binary == nil {
		return result, failure("CORE_BINARY_MISMATCH", nil)
	}
	if err = e.options.Binary.Preflight(ctx, tx.work.Path); err != nil {
		return result, failure("CORE_CONFIG_INVALID", contextCause(ctx))
	}
	if desired.v1 != nil {
		if err = e.preflightPort(ctx, desired.v1, tx.old); err != nil {
			return result, failure("CORE_PORT_UNAVAILABLE", contextCause(ctx))
		}
	} else {
		if err = e.preflightPortsV2(ctx, desired.v2, tx.old); err != nil {
			return result, failure("CORE_PORT_UNAVAILABLE", contextCause(ctx))
		}
	}
	if err = e.step(ctx, request, InstallGeneration); err != nil {
		return result, err
	}
	if err = e.options.Store.Install(ctx, tx.work); err != nil {
		return result, stateFailure(err)
	}
	tx.installed = true
	if err = e.step(ctx, request, SnapshotLastGood); err != nil {
		return result, err
	}
	tx.next = &state.Metadata{
		SchemaVersion: "1",
		State:         "STOPPED",
		Current: &state.Generation{
			Digest:    tx.work.Digest,
			Revision:  request.ConfigRevision,
			Version:   state.CoreVersion,
			Enabled:   desired.enabled(),
			Summary:   summary,
			SummaryV2: summaryV2,
		},
	}
	if tx.old != nil {
		tx.next.Previous = tx.old.Current
	}
	if err = e.step(ctx, request, StopOld); err != nil {
		return result, err
	}
	observed = e.options.Process.Snapshot(ctx)
	keepProcess := tx.old != nil && tx.old.State != "FAILED" && tx.old.Current.Digest == tx.next.Current.Digest && tx.old.Current.Enabled == tx.next.Current.Enabled && runtimeMatches(tx.old, observed)
	wasRunning := observed.State == "RUNNING"
	if !keepProcess {
		tx.processTouched = true
		if err = e.stop(ctx); err != nil {
			return result, err
		}
	}
	if err = e.step(ctx, request, StartCandidate); err != nil {
		return result, err
	}
	if tx.next.Current.Enabled && !keepProcess {
		if err = e.start(ctx, tx.next.Current); err != nil {
			return result, err
		}
		tx.started, tx.restarted = true, wasRunning
	}
	if err = e.step(ctx, request, WaitHealth); err != nil {
		return result, err
	}
	if tx.next.Current.Enabled {
		if err = e.options.Process.WaitHealthy(ctx); err != nil {
			return result, failure("CORE_API_UNAVAILABLE", contextCause(ctx))
		}
		observed = e.options.Process.Snapshot(ctx)
		if observed.State != "RUNNING" || observed.APIState != "READY" || observed.Digest != tx.next.Current.Digest {
			return result, failure("CORE_API_UNAVAILABLE", nil)
		}
		if len(tx.nextObfsPlans) > 0 && e.options.Obfs != nil && (!keepProcess || !reflect.DeepEqual(tx.oldObfsPlans, tx.nextObfsPlans)) {
			tx.processTouched = true
			if err = e.options.Obfs.StartAll(lifetime, tx.nextObfsPlans); err != nil {
				return result, failure("OBFS_START_FAILED", err)
			}
		}
		if e.options.AnyTLS != nil && (!keepProcess || !reflect.DeepEqual(tx.oldAnyTLSSpecs, tx.nextAnyTLSSpecs)) {
			if len(tx.nextAnyTLSSpecs) > 0 || len(tx.oldAnyTLSSpecs) > 0 {
				tx.processTouched = true
				if err = e.options.AnyTLS.StartAll(lifetime, tx.nextAnyTLSSpecs); err != nil {
					return result, failure("CORE_START_FAILED", err)
				}
			}
		}
		tx.next.State, tx.next.ResetEpoch = "RUNNING", observed.Epoch
	}
	if err = e.step(ctx, request, CommitState); err != nil {
		return result, err
	}
	tx.stateAttempted = true
	e.persistAnyTLSSpecs(tx.nextAnyTLSSpecs)
	if err = e.options.Store.Commit(ctx, tx.next); err != nil {
		return result, failure("STATE_COMMIT_FAILED", contextCause(ctx))
	}
	if err = e.step(ctx, request, CommitHost); err != nil {
		return result, err
	}
	tx.hostAttempted = true
	if err = writeHost(ctx, request.Host, tx.beforeHost, recordFor(tx.next)); err != nil {
		return result, err
	}
	if err = e.step(ctx, request, ReportChanges); err != nil {
		return result, err
	}
	tx.reportAttempted = true
	if err = report(ctx, request.Host, tx.next); err != nil {
		return result, failure("REPORT_CHANGES_FAILED", contextCause(ctx))
	}
	if err = e.step(ctx, request, CleanWork); err != nil {
		return result, err
	}
	if err = e.options.Store.CleanWork(ctx, request.OperationID, request.Attempt); err != nil {
		return result, failure("WORK_CLEANUP_FAILED", contextCause(ctx))
	}
	tx.staged = false
	if ctx.Err() != nil || !e.Active() {
		return result, failure("CANCELLED", contextCause(ctx))
	}
	if tx.started {
		if err = e.options.Process.MarkCommitted(); err != nil {
			return result, failure("CORE_START_FAILED", nil)
		}
	}
	e.mu.Lock()
	e.obfsPlans = append([]xrayconfig.ObfsPlan(nil), tx.nextObfsPlans...)
	oldStoredAnyTLS := e.anytlsSpecs
	e.anytlsSpecs = cloneAnyTLSSpecs(tx.nextAnyTLSSpecs)
	if len(loadedTLS) > 0 {
		if e.tlsBindings == nil {
			e.tlsBindings = make(map[string]TLSBindingStatus, len(loadedTLS))
		}
		for ref, st := range loadedTLS {
			e.tlsBindings[ref] = st
		}
	}
	e.mu.Unlock()
	clearAnyTLSSpecs(oldStoredAnyTLS)
	clearAnyTLSSpecs(tx.oldAnyTLSSpecs)
	clearAnyTLSSpecs(tx.nextAnyTLSSpecs)
	result = e.result(tx.next, tx.started, tx.restarted)
	// 指针与进程已经提交，GC 失败只保留显式维护警告，不虚构二次回滚。
	e.maintain(ctx, tx.next, &result)
	e.setFailure("")
	return result, nil
}

func (e *Engine) commitExisting(ctx context.Context, tx *transaction) error {
	if err := e.step(ctx, tx.request, CommitHost); err != nil {
		return err
	}
	tx.hostAttempted = true
	if err := writeHost(ctx, tx.request.Host, tx.beforeHost, recordFor(tx.next)); err != nil {
		return err
	}
	if err := e.step(ctx, tx.request, ReportChanges); err != nil {
		return err
	}
	tx.reportAttempted = true
	if err := report(ctx, tx.request.Host, tx.next); err != nil {
		return failure("REPORT_CHANGES_FAILED", contextCause(ctx))
	}
	return nil
}

func checkRunning(request Request, metadata *state.Metadata) error {
	revision := ""
	if metadata != nil {
		revision = metadata.Current.Revision
	}
	if request.ExpectedRunningRevision != nil && *request.ExpectedRunningRevision != revision {
		return failure("PRECONDITION_FAILED", nil)
	}
	for _, precondition := range request.Preconditions {
		if precondition.Subject == RunningKey && precondition.Revision != revision {
			return failure("PRECONDITION_FAILED", nil)
		}
	}
	return nil
}

func sameDesired(old *state.Metadata, revision string, intent *coreapi.Intent, summary *state.IntentSummary) bool {
	return old != nil && old.State != "FAILED" && old.Current.Revision == revision && old.Current.Enabled == *intent.Enabled && reflect.DeepEqual(old.Current.Summary, summary)
}
func runtimeMatches(metadata *state.Metadata, observed coreproc.Snapshot) bool {
	if metadata.Current.Enabled {
		return observed.State == "RUNNING" && observed.APIState == "READY" && observed.Digest == metadata.Current.Digest
	}
	return observed.State == "STOPPED"
}
func ptrRecord(record RunningRecord) *RunningRecord { return &record }
func validOperation(value string) bool {
	return len(value) <= 128 && !strings.Contains(value, "/") && pluginsdk.ValidateSubject(value) == nil
}
func validToken(value string, empty bool) bool {
	if value == "" {
		return empty
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func boundedHostContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 2*time.Second)
}
func contextCause(ctx context.Context) error {
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}
func failure(code string, cause error) *Error { return &Error{Code: code, cause: cause} }
func stateFailure(err error) error {
	if errors.Is(err, state.ErrCorrupt) {
		return failure("SNAPSHOT_CORRUPT", nil)
	}
	return failure("DATA_DIR_UNAVAILABLE", nil)
}
