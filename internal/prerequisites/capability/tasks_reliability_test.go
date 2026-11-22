// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 只替换受检执行与存储故障，授权链仍为真实宿主 ========================

type taskExecutorFunc func(context.Context, TaskKind, string, string, string, certificates.Progress) (certificates.View, error)

func (run taskExecutorFunc) RunTask(ctx context.Context, kind TaskKind, id, attempt, expected string, progress certificates.Progress) (certificates.View, error) {
	return run(ctx, kind, id, attempt, expected, progress)
}

type taskRepositoryObserver struct {
	store.Repository
	writes atomic.Int32
	reject func(taskRecord) error
}

func (r *taskRepositoryObserver) Put(ctx context.Context, key, expected string, raw []byte) (string, error) {
	r.writes.Add(1)
	if r.reject != nil {
		var record taskRecord
		if !hostauth.DecodePersistedObject(raw, &record, 64<<10) {
			return "", fault.New("STATE_INVALID", "回归收据无法解码")
		}
		if err := r.reject(record); err != nil {
			return "", err
		}
	}
	return r.Repository.Put(ctx, key, expected, raw)
}

func TestTasksContainExecutorPanicAndReleaseCapacity(t *testing.T) {
	f := newTaskFixture(t)
	var calls atomic.Int32
	work := taskExecutorFunc(func(_ context.Context, _ TaskKind, id, _, _ string, progress certificates.Progress) (certificates.View, error) {
		if calls.Add(1) == 1 {
			if err := progress("issuing", 20); err != nil {
				return certificates.View{}, err
			}
			panic("fixture-private-panic-content")
		}
		return certificates.View{ID: id}, nil
	})
	pool := f.pool(t, work, 1)
	ctx, args := f.testCall(t, "cert-panic", "attempt-panic")
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	drainTasks(t, pool, "")
	record, _, found, err := pool.loadTask(f.host.Context, one.Id)
	if err != nil || !found || record.State != "failed" || record.ErrorCode != "INTERNAL" || record.Stage != "issuing" || record.Percent != 20 {
		t.Fatal("panic 没有保留当前失败阶段与固定内部错误")
	}
	raw, err := json.Marshal(taskView(record, "revision"))
	if err != nil || bytes.Contains(raw, []byte("fixture-private-panic-content")) {
		t.Fatal("panic 内容泄漏到公开任务")
	}
	if _, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent"); err != nil || calls.Load() != 1 {
		t.Fatal("失败原任务重放启动了第二次执行")
	}
	second, other := f.testCall(t, "cert-after-panic", "attempt-after-panic")
	if _, err := pool.Submit(second, TestTask, other.CertificateID, other.AttemptID, "absent"); err != nil {
		t.Fatal("panic 后容量或监视器没有收尾")
	}
	drainTasks(t, pool, "")
	if calls.Load() != 2 {
		t.Fatal("panic 后固定执行器无法继续服务")
	}
}

func TestTasksReplayShowsLatestProgressAndThrottlesDurableWrites(t *testing.T) {
	f := newTaskFixture(t)
	ready, resume, persisted, finish := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	work := taskExecutorFunc(func(ctx context.Context, _ TaskKind, id, _, _ string, progress certificates.Progress) (certificates.View, error) {
		for percent := uint32(1); percent <= 50; percent++ {
			if err := progress("waiting_dns", percent); err != nil {
				return certificates.View{}, err
			}
		}
		close(ready)
		select {
		case <-ctx.Done():
			return certificates.View{}, ctx.Err()
		case <-resume:
		}
		if err := progress("issuing", 80); err != nil {
			return certificates.View{}, err
		}
		close(persisted)
		select {
		case <-ctx.Done():
			return certificates.View{}, ctx.Err()
		case <-finish:
			return certificates.View{ID: id}, nil
		}
	})
	observer := &taskRepositoryObserver{Repository: f.repository(t)}
	pool := f.pool(t, work, 1, observer)
	ctx, args := f.testCall(t, "cert-progress", "attempt-progress")
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	awaitTaskSignal(t, ready)
	if observer.writes.Load() != 2 {
		t.Fatal("高频本地进度产生了无界持久写入")
	}
	var parallel sync.WaitGroup
	for range 6 {
		parallel.Add(1)
		go func() {
			defer parallel.Done()
			view, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
			if err != nil || view.Id != one.Id || view.Status != "running" || view.Stage != "waiting_dns" || view.Percent != 50 {
				t.Error("相同原请求并发重放没有读取活动进度")
			}
		}()
	}
	parallel.Wait()
	f.clock.Advance(time.Second)
	close(resume)
	awaitTaskSignal(t, persisted)
	if observer.writes.Load() != 3 {
		t.Fatal("节流时间到期后没有保存当前进度")
	}
	close(finish)
	drainTasks(t, pool, "")
	record, _, found, err := pool.loadTask(f.host.Context, one.Id)
	if err != nil || !found || record.State != "succeeded" || record.Percent != 100 || observer.writes.Load() != 4 {
		t.Fatal("节流跳过了强制最终收据")
	}
}

func TestTasksKeepConfirmedRevisionAfterRunningReceiptFails(t *testing.T) {
	f := newTaskFixture(t)
	var calls atomic.Int32
	work := taskExecutorFunc(func(_ context.Context, _ TaskKind, _, _, _ string, _ certificates.Progress) (certificates.View, error) {
		calls.Add(1)
		return certificates.View{}, nil
	})
	observer := &taskRepositoryObserver{Repository: f.repository(t), reject: func(record taskRecord) error {
		if record.State == "running" {
			return &problem.Error{Code: problem.RateLimited, Detail: "fixture-private-storage-detail", RetryAfterSec: 10}
		}
		return nil
	}}
	pool := f.pool(t, work, 1, observer)
	ctx, args := f.testCall(t, "cert-running-save", "attempt-running-save")
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	drainTasks(t, pool, "")
	record, _, found, err := pool.loadTask(f.host.Context, one.Id)
	if err != nil || !found || record.State != "failed" || record.Stage != "starting" || record.ErrorCode != "RATE_LIMITED" ||
		!record.RetryAt.Equal(f.clock.Now().Add(10*time.Second)) || calls.Load() != 0 {
		t.Fatal("运行收据失败后丢失CAS版本、错误码或错误重启执行器")
	}
}

func TestTasksReportFinalReceiptFailureAndNeverResubmitUnknownWork(t *testing.T) {
	f := newTaskFixture(t)
	var calls atomic.Int32
	work := taskExecutorFunc(func(_ context.Context, _ TaskKind, id, _, _ string, _ certificates.Progress) (certificates.View, error) {
		calls.Add(1)
		return certificates.View{ID: id}, nil
	})
	observer := &taskRepositoryObserver{Repository: f.repository(t), reject: func(record taskRecord) error {
		if record.State != "queued" && record.State != "running" {
			return errors.New("fixture-private-final-store-detail")
		}
		return nil
	}}
	pool := f.pool(t, work, 1, observer)
	ctx, args := f.testCall(t, "cert-final-save", "attempt-final-save")
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	drainTasks(t, pool, "TASK_PERSISTENCE_FAILED")
	replayed, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil || replayed.Status != "outcome_unknown" || replayed.ErrorCode != "OUTCOME_UNKNOWN" || calls.Load() != 1 {
		t.Fatal("未保存最终结果的任务被宣称成功或再次执行")
	}
	query := f.start(t, "tasks.get", "plugins/tls.certificates/resources/tasks/"+one.Id, "absent", hostauth.TaskArgs{TaskID: one.Id})
	view, err := pool.Get(query, one.Id)
	if err != nil || view.Status != "outcome_unknown" {
		t.Fatal("无活动worker的旧running行被当成活跃任务")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := pool.Close(closeCtx); fault.Code(err) != "TASK_PERSISTENCE_FAILED" || bytes.Contains([]byte(err.Error()), []byte("fixture-private-final-store-detail")) {
		t.Fatal("Close 没有给出脱敏的收尾失败证据")
	}
}

func TestTasksLatchInvalidProgressAndRejectLateCallbacks(t *testing.T) {
	f := newTaskFixture(t)
	var callback certificates.Progress
	work := taskExecutorFunc(func(_ context.Context, _ TaskKind, id, _, _ string, progress certificates.Progress) (certificates.View, error) {
		callback = progress
		if err := progress("waiting_dns", 20); err != nil {
			return certificates.View{}, err
		}
		// 执行器忽略错误也不能把倒退进度变成成功。
		_ = progress("waiting_dns", 10)
		return certificates.View{ID: id}, nil
	})
	pool := f.pool(t, work, 1)
	ctx, args := f.testCall(t, "cert-invalid-progress", "attempt-invalid-progress")
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	drainTasks(t, pool, "")
	record, revision, found, err := pool.loadTask(f.host.Context, one.Id)
	if err != nil || !found || record.State != "failed" || record.ErrorCode != "STATE_INVALID" || record.Stage != "waiting_dns" || record.Percent != 20 {
		t.Fatal("执行器忽略的无效进度没有锁定失败结果")
	}
	if err := callback("issuing", 100); fault.Code(err) != "STATE_CONFLICT" {
		t.Fatal("执行器结束后仍能追加任务进度")
	}
	_, after, _, err := pool.loadTask(f.host.Context, one.Id)
	if err != nil || revision != after {
		t.Fatal("晚到进度改写了最终收据")
	}
}

func TestTasksPreserveExplicitUncertainOutcomeAndRetryTime(t *testing.T) {
	f := newTaskFixture(t)
	retry := f.clock.Now().Add(time.Minute)
	work := taskExecutorFunc(func(_ context.Context, _ TaskKind, _, _, _ string, progress certificates.Progress) (certificates.View, error) {
		if err := progress("publishing_dns", 40); err != nil {
			return certificates.View{}, err
		}
		return certificates.View{}, &fault.Error{Code: "STATE_UNAVAILABLE", Detail: "fixture 原写结果待核对", Uncertain: true, RetryAt: retry}
	})
	pool := f.pool(t, work, 1)
	ctx, args := f.testCall(t, "cert-unknown-result", "attempt-unknown-result")
	one, err := pool.Submit(ctx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	drainTasks(t, pool, "")
	record, _, found, err := pool.loadTask(f.host.Context, one.Id)
	if err != nil || !found || record.State != "outcome_unknown" || record.ErrorCode != "STATE_UNAVAILABLE" || record.Stage != "publishing_dns" || !record.RetryAt.Equal(retry) {
		t.Fatal("明确不确定结果被当作已拒绝或丢失Retry-After")
	}
}
