// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/xraycore/coreproc"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ============================================================================
// 恢复使用真实快照；宿主调用真实等到超时，健康旧进程与同步故障分别断言。
// ============================================================================

type timeoutRollbackHost struct {
	*fakeApplyHost
	writes   int
	timedOut bool
}

func (h *timeoutRollbackHost) PutState(ctx context.Context, key string, value []byte, option pluginsdk.PutOption) (string, error) {
	var record apply.RunningRecord
	if err := json.Unmarshal(value, &record); err != nil {
		return "", err
	}
	if record.RunningRevision != "1" {
		return h.fakeApplyHost.PutState(ctx, key, value, option)
	}
	h.writes++
	select {
	case <-ctx.Done():
		h.timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		return "", ctx.Err()
	case <-time.After(3 * time.Second):
		return "", errors.New("rollback host call has no bounded deadline")
	}
}

func TestFakeRollbackBudgetCoversProcessAndHostRecovery(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	old, err := f.store.Committed(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var remaining time.Duration
	var deadlineFound bool
	f.process.beforeStart = func(ctx context.Context, spec coreproc.StartSpec) {
		if spec.Digest == old.Current.Digest {
			deadline, ok := ctx.Deadline()
			deadlineFound = ok
			remaining = time.Until(deadline)
		}
	}
	f.changeDesired()
	f.failStep = apply.CommitHost
	if _, err := f.engine.Execute(t.Context(), f.request()); apply.ErrorCode(err) != "APPLY_ABORTED" || !apply.RolledBack(err) {
		t.Fatalf("ordinary rollback did not restore the old core: %v", err)
	}
	if !deadlineFound || remaining < 20*time.Second || remaining > 25*time.Second {
		t.Fatalf("rollback start has %v remaining; expected the bounded 25s total budget", remaining)
	}
}

func TestFakeRollbackHostTimeoutPreservesHealthyOldProcess(t *testing.T) {
	for _, layout := range []string{"replacement", "unchanged"} {
		t.Run(layout, func(t *testing.T) {
			f := newApplyFixture(t)
			if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
				t.Fatal(err)
			}
			old, err := f.store.Committed(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if layout == "replacement" {
				f.changeDesired()
			} else {
				f.host.revision = "2"
			}
			f.failStep = apply.ReportChanges
			host := &timeoutRollbackHost{fakeApplyHost: f.host}
			request := f.request()
			request.Host = host
			if _, err := f.engine.Execute(t.Context(), request); apply.ErrorCode(err) != "RECOVERY_FAILED" || apply.RolledBack(err) {
				t.Fatalf("unconfirmed host synchronization was reported as fully recovered: %v", err)
			}
			if !host.timedOut || host.writes != 1 {
				t.Fatalf("host timeout did not use one bounded CAS call: timeout=%v writes=%d", host.timedOut, host.writes)
			}
			observed := f.process.Snapshot(t.Context())
			if observed.State != "RUNNING" || observed.APIState != "READY" || observed.Digest != old.Current.Digest {
				t.Fatalf("host synchronization timeout killed the recovered old core: state=%s api=%s", observed.State, observed.APIState)
			}
			if layout == "unchanged" && observed.Epoch != old.ResetEpoch {
				t.Fatal("unchanged native configuration restarted the old process during host recovery")
			}
			metadata, err := f.store.Committed(t.Context())
			if err != nil || metadata.State != "RUNNING" || metadata.Current.Revision != "1" || metadata.ResetEpoch != observed.Epoch || metadata.LastError != "RECOVERY_FAILED" {
				t.Fatalf("private recovered state lost its running fact or explicit synchronization failure: %v", err)
			}
			if f.engine.Failure() != "RECOVERY_FAILED" {
				t.Fatal("host synchronization failure was hidden")
			}
			// 宿主重新可写后，原失败操作可继续推进并清掉同步故障。
			f.failStep = ""
			if result, err := f.engine.Execute(t.Context(), f.request()); err != nil || result.RunningRevision != "2" || f.engine.Failure() != "" {
				t.Fatalf("retry after host recovery failed: %v", err)
			}
		})
	}
}
