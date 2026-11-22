// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/coreproc"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// fakeApplyHost 只替代宿主调用；private Store、Render、Secretmap 使用生产实现。
type fakeApplyHost struct {
	config     []byte
	revision   string
	key        []byte
	uuid       []byte
	revealed   [][]byte
	kv         []byte
	kvRev      uint64
	found      bool
	reports    int
	putFail    bool
	putLost    bool
	reportFail bool
}

func (h *fakeApplyHost) GetConfig(context.Context, string) ([]byte, string, error) {
	return append([]byte(nil), h.config...), h.revision, nil
}
func (h *fakeApplyHost) RevealSecret(_ context.Context, reference, purpose string) ([]byte, error) {
	if purpose != "core.xray.apply" {
		return nil, errors.New("fake purpose mismatch")
	}
	value := h.uuid
	if strings.HasSuffix(reference, "00") {
		value = h.key
	}
	copy := append([]byte(nil), value...)
	h.revealed = append(h.revealed, copy)
	return copy, nil
}
func (h *fakeApplyHost) GetState(context.Context, string) ([]byte, string, bool, error) {
	if !h.found {
		return nil, "", false, nil
	}
	return append([]byte(nil), h.kv...), strconv.FormatUint(h.kvRev, 10), true, nil
}
func (h *fakeApplyHost) PutState(_ context.Context, _ string, value []byte, option pluginsdk.PutOption) (string, error) {
	if option.MustNotExist && h.found || option.ExpectedRevision != "" && (!h.found || option.ExpectedRevision != strconv.FormatUint(h.kvRev, 10)) {
		return "", pluginsdk.Errorf("REVISION_CONFLICT", "fake conflict")
	}
	if h.putFail {
		h.putFail = false
		return "", errors.New("fake disk detail must not escape")
	}
	h.kvRev++
	h.found, h.kv = true, append([]byte(nil), value...)
	if h.putLost {
		h.putLost = false
		return "", errors.New("fake response lost after write")
	}
	return strconv.FormatUint(h.kvRev, 10), nil
}
func (h *fakeApplyHost) DeleteState(_ context.Context, _ string, expected string) error {
	if !h.found || expected != strconv.FormatUint(h.kvRev, 10) {
		return pluginsdk.Errorf("REVISION_CONFLICT", "fake delete conflict")
	}
	h.found, h.kv = false, nil
	return nil
}
func (h *fakeApplyHost) ReportChanges(context.Context, ...pluginsdk.ResourceChange) error {
	h.reports++
	if h.reportFail {
		h.reportFail = false
		return errors.New("fake report failure")
	}
	return nil
}

type fakeApplyProcess struct {
	mu             sync.Mutex
	snapshot       coreproc.Snapshot
	starts         int
	stops          int
	startFail      bool
	stopFail       bool
	healthFail     bool
	healthFailures int
	beforeStart    func(context.Context, coreproc.StartSpec)
}

func (p *fakeApplyProcess) Start(ctx context.Context, spec coreproc.StartSpec) error {
	if p.beforeStart != nil {
		p.beforeStart(ctx, spec)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.startFail {
		p.startFail = false
		return coreproc.ErrStart
	}
	if p.snapshot.State == "RUNNING" {
		return coreproc.ErrAlreadyRunning
	}
	p.starts++
	p.snapshot = coreproc.Snapshot{State: "RUNNING", APIState: "READY", Digest: spec.Digest, Epoch: "fake-" + strconv.Itoa(p.starts), PID: p.starts}
	return nil
}
func (p *fakeApplyProcess) Stop(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stops++
	if p.stopFail {
		p.snapshot.State = "UNKNOWN"
		return coreproc.ErrStop
	}
	p.snapshot.State, p.snapshot.APIState = "STOPPED", "UNAVAILABLE"
	return nil
}
func (p *fakeApplyProcess) WaitHealthy(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.healthFailures > 0 {
		p.healthFailures--
		return coreproc.ErrUnhealthy
	}
	if p.healthFail {
		p.healthFail = false
		return coreproc.ErrUnhealthy
	}
	if p.snapshot.State != "RUNNING" {
		return coreproc.ErrUnhealthy
	}
	return nil
}
func (p *fakeApplyProcess) MarkCommitted() error { return nil }
func (p *fakeApplyProcess) Snapshot(context.Context) coreproc.Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshot
}

type fakeApplyBinary struct{ calls int }

func (b *fakeApplyBinary) Preflight(context.Context, string) error { b.calls++; return nil }

type applyFixture struct {
	engine             *apply.Engine
	store              *state.Store
	process            *fakeApplyProcess
	host               *fakeApplyHost
	binary             *fakeApplyBinary
	directory          string
	failStep           apply.Step
	cancelStep         apply.Step
	cancel             context.CancelFunc
	faultStore         *fakeApplySnapshots
	captureStep        apply.Step
	capture            func()
	cancelLifetimeStep apply.Step
	driver             *driverRuntime
}

// fakeApplySnapshots 可让真实原子写成功后丢失返回值，验证不确定文件提交的补偿。
type fakeApplySnapshots struct {
	*state.Store
	failCommitAfterWrite bool
}

func (s *fakeApplySnapshots) Commit(ctx context.Context, metadata *state.Metadata) error {
	if err := s.Store.Commit(ctx, metadata); err != nil {
		return err
	}
	if s.failCommitAfterWrite {
		s.failCommitAfterWrite = false
		return errors.New("fake fsync response failure")
	}
	return nil
}

func newApplyFixture(t *testing.T) *applyFixture {
	t.Helper()
	return newApplyFixtureWithProcess(t, nil)
}

// newApplyFixtureWithProcess 复用同一宿主/快照，仅替换当前进程边界。
func newApplyFixtureWithProcess(t *testing.T, decorate func(*fakeApplyProcess) apply.Process) *applyFixture {
	t.Helper()
	directory, err := os.MkdirTemp("", "apply-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	material := fakeSecretMaterials(t)
	f := &applyFixture{directory: directory, store: state.NewStore(directory), process: &fakeApplyProcess{snapshot: coreproc.Snapshot{State: "STOPPED", APIState: "UNAVAILABLE"}}, host: &fakeApplyHost{config: testIntent(t), revision: "1", key: material.key, uuid: material.uuid}, binary: &fakeApplyBinary{}}
	f.faultStore = &fakeApplySnapshots{Store: f.store}
	process := apply.Process(f.process)
	if decorate != nil {
		process = decorate(f.process)
	}
	f.engine, err = apply.New(apply.Options{Store: f.faultStore, Process: process, Binary: f.binary, Socket: filepath.Join(directory, "runtime", "api.sock"), Before: func(ctx context.Context, step apply.Step) error {
		if step == f.cancelStep {
			// 普通请求取消保留活动生命周期，随后由事务恢复旧核心。
			f.cancel()
		}
		if step == f.captureStep && f.capture != nil {
			f.capture()
			return errors.New("fake crash capture")
		}
		if step == f.cancelLifetimeStep {
			f.engine.Cancel()
		}
		if step == f.failStep {
			return errors.New("fake phase failure")
		}
		return ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.engine.Activate(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.engine.Deactivate(context.Background()) })
	return f
}

func (f *applyFixture) request() apply.Request {
	return apply.Request{Host: f.host, ConfigRevision: f.host.revision, OperationID: "op-apply", Attempt: 1}
}

func (f *applyFixture) changeDesired() {
	f.host.revision = "2"
	f.host.config = bytes.Replace(f.host.config, []byte(`"port":10443`), []byte(`"port":11443`), 1)
}

// ======================== fake 系统与真实私有快照事务 ========================
func TestFakeApplySuccessIdempotenceAndPublicResult(t *testing.T) {
	f := newApplyFixture(t)
	result, err := f.engine.Execute(t.Context(), f.request())
	if err != nil || result.RunningRevision != "1" || result.ProcessState != "RUNNING" || result.APIState != "READY" {
		t.Fatalf("fake apply failed: %v", err)
	}
	metadata, err := f.store.Committed(t.Context())
	if err != nil || metadata.Current.Revision != "1" || metadata.ResetEpoch != result.ResetEpoch {
		t.Fatal("private state was not committed")
	}
	starts, stops, preflights := f.process.starts, f.process.stops, f.binary.calls
	replay, err := f.engine.Execute(t.Context(), f.request())
	if err != nil || replay.ResetEpoch != result.ResetEpoch || f.process.starts != starts || f.process.stops != stops || f.binary.calls != preflights {
		t.Fatal("idempotent replay changed process state")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sec_", "private_key", "uuid", "config.json", "api.sock", "-config", "QWQ_"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatal("result exposed private data")
		}
	}
	for _, received := range f.host.revealed {
		if !allZero(received) {
			t.Fatal("apply retained secret material")
		}
	}
}

func TestFakeApplyPreconditionsAreCheckedBeforeEffects(t *testing.T) {
	f := newApplyFixture(t)
	request := f.request()
	request.ConfigRevision = "2"
	if _, err := f.engine.Execute(t.Context(), request); apply.ErrorCode(err) != "CONFIG_REVISION_CONFLICT" {
		t.Fatal("stale desired version was accepted")
	}
	wanted := "7"
	request = f.request()
	request.ExpectedRunningRevision = &wanted
	if _, err := f.engine.Execute(t.Context(), request); apply.ErrorCode(err) != "PRECONDITION_FAILED" {
		t.Fatal("stale running version was accepted")
	}
	if len(f.host.revealed) != 0 || f.process.starts != 0 || f.binary.calls != 0 {
		t.Fatal("precondition failure produced side effects")
	}
}

func TestFakeApplyEveryFailureAndCancellationPreservesLastGood(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		for _, step := range apply.Steps() {
			t.Run(string(step)+strconv.FormatBool(cancelled), func(t *testing.T) {
				f := newApplyFixture(t)
				if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
					t.Fatal(err)
				}
				f.changeDesired()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if cancelled {
					f.cancelStep, f.cancel = step, cancel
				} else {
					f.failStep = step
				}
				if _, err := f.engine.Execute(ctx, f.request()); err == nil {
					t.Fatal("injected failure was ignored")
				}
				metadata, err := f.store.Committed(t.Context())
				if err != nil || metadata.Current.Revision != "1" {
					t.Fatalf("failure changed committed version: %v", err)
				}
				if f.process.Snapshot(t.Context()).State != "RUNNING" {
					t.Fatal("healthy old core was not retained/restored")
				}
				for _, received := range f.host.revealed {
					if !allZero(received) {
						t.Fatal("failure retained secret material")
					}
				}
			})
		}
	}
}

func TestFakeApplyLostCASResponseAndReportFailureRestoreBothStores(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(strconv.FormatBool(lost), func(t *testing.T) {
			f := newApplyFixture(t)
			if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
				t.Fatal(err)
			}
			f.changeDesired()
			if lost {
				f.host.putLost = true
			} else {
				f.host.reportFail = true
			}
			_, err := f.engine.Execute(t.Context(), f.request())
			if err == nil || !apply.RolledBack(err) {
				t.Fatal("failed commit/report did not recover old core")
			}
			metadata, err := f.store.Committed(t.Context())
			if err != nil || metadata.Current.Revision != "1" {
				t.Fatal("disk state was not restored")
			}
			var record apply.RunningRecord
			if json.Unmarshal(f.host.kv, &record) != nil || record.RunningRevision != "1" {
				t.Fatal("host record was not restored")
			}
		})
	}
}

func TestFakeApplyStateWriteLostResponseRestoresOldPointers(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	f.changeDesired()
	f.faultStore.failCommitAfterWrite = true
	if _, err := f.engine.Execute(t.Context(), f.request()); apply.ErrorCode(err) != "STATE_COMMIT_FAILED" || !apply.RolledBack(err) {
		t.Fatal("ambiguous file commit did not restore last-good")
	}
	metadata, err := f.store.Committed(t.Context())
	if err != nil || metadata.Current.Revision != "1" || metadata.Previous != nil {
		t.Fatal("old pointer pair was not restored")
	}
	var record apply.RunningRecord
	if json.Unmarshal(f.host.kv, &record) != nil || record.RunningRevision != "1" || record.ResetEpoch != metadata.ResetEpoch {
		t.Fatal("restored file/process/host epochs disagree")
	}
}

func TestFakeApplyUnconfirmedStopNeverStartsSecondCore(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	f.changeDesired()
	f.process.stopFail = true
	starts := f.process.starts
	if _, err := f.engine.Execute(t.Context(), f.request()); apply.ErrorCode(err) != "RECOVERY_FAILED" || apply.RolledBack(err) {
		t.Fatal("unconfirmed stop was reported as recovered")
	}
	if f.process.starts != starts {
		t.Fatal("unconfirmed old process allowed a second core")
	}
	metadata, err := f.store.Committed(t.Context())
	if err != nil || metadata.State != "FAILED" || metadata.LastError != "RECOVERY_FAILED" {
		t.Fatal("recovery failure was not retained")
	}
}

func TestFakeApplyFailedOldHealthDoesNotClaimRollback(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	f.changeDesired()
	f.process.healthFailures = 2
	if _, err := f.engine.Execute(t.Context(), f.request()); apply.ErrorCode(err) != "RECOVERY_FAILED" || apply.RolledBack(err) {
		t.Fatal("unhealthy recovery was reported as success")
	}
	if f.engine.Failure() != "RECOVERY_FAILED" {
		t.Fatal("failure state disappeared")
	}
	if f.process.Snapshot(t.Context()).State != "STOPPED" {
		t.Fatal("unhealthy old process survived failed recovery")
	}
}

func TestFakeApplyIdenticalNativeBytesAdvanceRevisionWithoutRestart(t *testing.T) {
	f := newApplyFixture(t)
	first, err := f.engine.Execute(t.Context(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	starts, stops := f.process.starts, f.process.stops
	f.host.revision = "2"
	second, err := f.engine.Execute(t.Context(), f.request())
	if err != nil || second.RunningRevision != "2" || second.Restarted || second.Started || second.ResetEpoch != first.ResetEpoch || f.process.starts != starts || f.process.stops != stops {
		t.Fatal("identical native config caused an unnecessary process switch")
	}
	metadata, err := f.store.Committed(t.Context())
	if err != nil || metadata.Current.Revision != "2" || metadata.Current.Digest != first.ConfigDigest {
		t.Fatal("unchanged process did not advance its recorded desired revision")
	}
}
