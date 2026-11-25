// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package apply

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwq-panel/qwq/internal/xraycore/coreproc"
	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/testfixture"
)

// ============================================================================
// 仅替代进程边界；真实私有快照验证预算耗尽不等于已恢复的数据面失效。
// ============================================================================

type expiredProbeProcess struct {
	Process
	observed coreproc.Snapshot
	stops    int
}

func (p *expiredProbeProcess) Snapshot(ctx context.Context) coreproc.Snapshot {
	observed := p.observed
	// 与生产 Manager.probe 相同：过期探测仍有活进程，只是无法确认 API。
	if ctx.Err() != nil {
		observed.APIState = "UNAVAILABLE"
	}
	return observed
}

func (p *expiredProbeProcess) Stop(context.Context) error {
	p.stops++
	p.observed.State, p.observed.APIState = "STOPPED", "UNAVAILABLE"
	return nil
}

func TestRecoveryFailureExpiredContextPreservesVerifiedProcess(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store := state.NewStore(directory)
	work, err := store.Stage(t.Context(), "op-restored", 1, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Install(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	summary, err := state.Summarize(testfixture.Intent())
	if err != nil {
		t.Fatal(err)
	}
	recovered := &state.Metadata{SchemaVersion: "1", State: "RUNNING", ResetEpoch: "same-generation",
		Current: &state.Generation{Digest: work.Digest, Revision: "1", Version: state.CoreVersion, Enabled: true, Summary: summary}}
	if err := store.Commit(t.Context(), recovered); err != nil {
		t.Fatal(err)
	}
	process := &expiredProbeProcess{observed: coreproc.Snapshot{
		State: "RUNNING", APIState: "READY", Digest: work.Digest, Epoch: recovered.ResetEpoch}}
	engine := &Engine{options: Options{Store: store, Process: process}, active: true}
	expired, cancel := context.WithCancel(t.Context())
	cancel()
	engine.persistRecoveryFailure(expired, recovered)
	if process.stops != 0 || process.observed.State != "RUNNING" {
		t.Fatalf("expired rollback context stopped the verified process: stops=%d state=%s", process.stops, process.observed.State)
	}
	metadata, err := store.Committed(t.Context())
	if err != nil || metadata.State != "RUNNING" || metadata.ResetEpoch != recovered.ResetEpoch || metadata.LastError != "RECOVERY_FAILED" {
		t.Fatalf("expired rollback budget lost the running fact or bounded failure bookkeeping: %v", err)
	}
}
