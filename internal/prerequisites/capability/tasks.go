// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
)

// ======================== 原 operation 的有界任务，不保存可复活运行 proof ========================

type TaskKind string

const (
	IssueTask  TaskKind = "issue"
	ImportTask TaskKind = "import"
	TestTask   TaskKind = "test"
)

// TaskExecutor 由宿主构造，业务 kind 和参数仍须来自当次已接受的真实意图。
type TaskExecutor interface {
	RunTask(context.Context, TaskKind, string, string, string, certificates.Progress) (certificates.View, error)
}

type TaskOptions struct {
	Authority       *hostauth.Authority
	Repository      store.Repository
	Executor        TaskExecutor
	Clock           clock.Clock
	MaxJobs         int
	MonitorInterval time.Duration
}

type Tasks struct {
	mu         sync.Mutex
	authority  *hostauth.Authority
	repository store.Repository
	executor   TaskExecutor
	clock      clock.Clock
	limit      int
	interval   time.Duration
	active     map[string]*runningTask
	idle       chan struct{}
	closed     bool
	drainErr   error
}

type runningTask struct {
	mu            sync.Mutex
	group         string
	record        taskRecord
	revision      string
	lastPersisted time.Time
	progressErr   error
	finished      bool
	ctx           context.Context
	cancel        func()
	release       func()
}

func (work *runningTask) snapshot() (taskRecord, string) {
	work.mu.Lock()
	defer work.mu.Unlock()
	return work.record, work.revision
}

// NewTasks 限定最多 8 个 worker/监视器，缺少实际授权或后端时拒绝。
func NewTasks(options TaskOptions) (*Tasks, error) {
	if options.Authority == nil || options.Repository == nil || options.Executor == nil {
		return nil, fault.New("BACKEND_REQUIRED", "任务需要真实授权、持久状态与固定执行器")
	}
	if options.MaxJobs == 0 {
		options.MaxJobs = 8
	}
	if options.MonitorInterval == 0 {
		options.MonitorInterval = 5 * time.Second
	}
	if options.MaxJobs < 1 || options.MaxJobs > 8 || options.MonitorInterval < 100*time.Millisecond || options.MonitorInterval > 5*time.Second {
		return nil, fault.New("VALIDATION_FAILED", "任务数量或授权监视间隔无效")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	idle := make(chan struct{})
	close(idle)
	return &Tasks{authority: options.Authority, repository: options.Repository, executor: options.Executor, clock: options.Clock,
		limit: options.MaxJobs, interval: options.MonitorInterval, active: make(map[string]*runningTask), idle: idle}, nil
}

func taskOperation(kind TaskKind) string {
	switch kind {
	case IssueTask:
		return "certificates.issue"
	case ImportTask:
		return "certificates.import"
	case TestTask:
		return "certificates.test"
	}
	return ""
}

func (m *Tasks) validateSubmit(ctx context.Context, kind TaskKind, certificateID, attempt, expected string) (hostauth.Invocation, error) {
	invocation, err := m.authority.CurrentInvocation(ctx)
	if err != nil {
		return hostauth.Invocation{}, err
	}
	if taskOperation(kind) == "" || invocation.PluginID != "tls.certificates" || invocation.Operation != taskOperation(kind) ||
		invocation.Subject != "plugins/tls.certificates/resources/certificates/"+certificateID || !names.ID(certificateID) || !names.ID(attempt) {
		return hostauth.Invocation{}, fault.New("PERMISSION_DENIED", "任务不是当前固定签发意图")
	}
	var actualID, actualAttempt string
	switch kind {
	case IssueTask:
		args, failure := hostauth.DecodeArguments[hostauth.IssueCertificateArgs](ctx, m.authority)
		err = failure
		actualID, actualAttempt = args.CertificateID, args.AttemptID
	case ImportTask:
		args, failure := hostauth.DecodeArguments[hostauth.ImportCertificateArgs](ctx, m.authority)
		err = failure
		actualID, actualAttempt = args.CertificateID, args.AttemptID
	case TestTask:
		args, failure := hostauth.DecodeArguments[hostauth.TestCertificateArgs](ctx, m.authority)
		err = failure
		actualID, actualAttempt = args.CertificateID, args.AttemptID
	}
	if err != nil {
		return hostauth.Invocation{}, err
	}
	if actualID != certificateID || actualAttempt != attempt {
		return hostauth.Invocation{}, fault.New("PERMISSION_DENIED", "任务换用了原 certificate/attempt")
	}
	if err := m.authority.RequireRevision(ctx, expected); err != nil {
		return hostauth.Invocation{}, err
	}
	return invocation, nil
}

// Submit 在保留容量后兑换真实 executor 生命周期；相同原意图不会启动第二个 worker。
func (m *Tasks) Submit(ctx context.Context, kind TaskKind, certificateID, attempt, expected string) (*certificatesv1.TaskView, error) {
	if m == nil {
		return nil, fault.New("BACKEND_REQUIRED", "任务后端未装配")
	}
	invocation, err := m.validateSubmit(ctx, kind, certificateID, attempt, expected)
	if err != nil {
		return nil, err
	}
	group, groupLimit, err := m.authority.TaskBudget(ctx, m.interval)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(invocation.OperationID + "\x00" + string(kind) + "\x00" + certificateID + "\x00" + attempt + "\x00" + expected))
	id := "ctask_" + hex.EncodeToString(digest[:])
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, fault.New("UNAVAILABLE", "任务后端已经关闭")
	}
	if current := m.active[id]; current != nil {
		record, revision := current.snapshot()
		return taskView(record, revision), nil
	}
	if len(m.active) >= m.limit {
		return nil, fault.New("RESOURCE_EXHAUSTED", "任务容量已满")
	}
	count := 0
	for _, work := range m.active {
		if work.group == group {
			count++
		}
	}
	if count >= groupLimit {
		return nil, fault.New("RESOURCE_EXHAUSTED", "当前委托的监视请求预算已用满")
	}
	saved, revision, found, err := m.loadTask(ctx, id)
	if err != nil {
		return nil, err
	}
	if found {
		if saved.Origin != invocation || saved.CertificateID != certificateID || saved.AttemptID != attempt || saved.ExpectedRevision != expected || saved.Kind != kind {
			return nil, fault.New("STATE_INVALID", "任务的固定原意图不符")
		}
		if saved.State == "running" || saved.State == "queued" {
			saved.State, saved.ErrorCode = "outcome_unknown", "OUTCOME_UNKNOWN"
		}
		return taskView(saved, revision), nil
	}
	lifetime, release, err := m.authority.JobContext(ctx)
	if err != nil {
		return nil, err
	}
	workerCtx, stop, err := m.authority.Begin(lifetime, invocation)
	if err != nil {
		release()
		return nil, err
	}
	record := taskRecord{Version: 1, ID: id, Kind: kind, Origin: invocation, CertificateID: certificateID,
		AttemptID: attempt, ExpectedRevision: expected, State: "queued", Stage: "queued", CreatedAt: m.clock.Now()}
	revision, err = m.saveTask(workerCtx, record, "")
	if err != nil {
		stop()
		release()
		return nil, err
	}
	if len(m.active) == 0 {
		m.idle = make(chan struct{})
	}
	execCtx, cancelExec := context.WithCancel(workerCtx)
	var releaseOnce sync.Once
	work := &runningTask{group: group, record: record, revision: revision, lastPersisted: record.CreatedAt,
		ctx: execCtx, cancel: cancelExec,
		release: func() {
			releaseOnce.Do(func() {
				cancelExec()
				stop()
				release()
			})
		}}
	m.active[id] = work
	go m.run(work)
	return taskView(record, revision), nil
}

// Get 使用新的真实查询意图，不把旧 task row 变成运行权限。
func (m *Tasks) Get(ctx context.Context, id string) (*certificatesv1.TaskView, error) {
	record, revision, found, err := m.loadTask(ctx, id)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fault.New("NOT_FOUND", "任务不存在")
	}
	if err := m.authority.CheckTaskIntent(ctx, id, record.CertificateID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	work := m.active[id]
	m.mu.Unlock()
	if work != nil {
		record, revision = work.snapshot()
	} else if record.State == "queued" || record.State == "running" {
		record.State, record.ErrorCode = "outcome_unknown", "OUTCOME_UNKNOWN"
	}
	return taskView(record, revision), nil
}

// Cancel 只停止精确任务，由原 worker 保存最终收据并执行原 cleanup。
func (m *Tasks) Cancel(ctx context.Context, id string) (*certificatesv1.TaskView, error) {
	view, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	invocation, err := m.authority.CurrentInvocation(ctx)
	if err != nil || invocation.Operation != "tasks.cancel" {
		return nil, fault.New("PERMISSION_DENIED", "取消必须来自当前固定写意图")
	}
	m.mu.Lock()
	work := m.active[id]
	m.mu.Unlock()
	if work != nil {
		work.cancel()
	}
	return view, nil
}

// Close 先封闭提交入口，再取消全部自有 worker/监视器；Wait 返回完整收尾证据。
func (m *Tasks) Close(ctx context.Context) error {
	if m == nil {
		return fault.New("BACKEND_REQUIRED", "任务后端未装配")
	}
	m.mu.Lock()
	m.closed = true
	cancel := make([]func(), 0, len(m.active))
	for _, work := range m.active {
		cancel = append(cancel, work.cancel)
	}
	m.mu.Unlock()
	for _, stop := range cancel {
		stop()
	}
	return m.Wait(ctx)
}

func (m *Tasks) Wait(ctx context.Context) error {
	if m == nil || ctx == nil {
		return fault.New("VALIDATION_FAILED", "等待需要有效上下文")
	}
	for {
		m.mu.Lock()
		idle := m.idle
		if len(m.active) == 0 {
			err := m.drainErr
			m.mu.Unlock()
			return err
		}
		m.mu.Unlock()
		select {
		case <-idle:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
