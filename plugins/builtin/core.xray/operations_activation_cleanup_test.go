// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"testing"

	"github.com/qwq-panel/qwq/internal/xraycore/coreproc"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
)

// ============================================================================
// 启动确认丢失时仍有被拥有的进程，Activate 失败必须停止并核验清理结果。
// ============================================================================

type failedActivationProcess struct {
	*fakeApplyProcess
	failConfirmation bool
}

func (p *failedActivationProcess) Start(ctx context.Context, spec coreproc.StartSpec) error {
	if err := p.fakeApplyProcess.Start(ctx, spec); err != nil {
		return err
	}
	if p.failConfirmation {
		return coreproc.ErrStart
	}
	return nil
}

func TestFakeActivationFailedStartCleansOwnedProcess(t *testing.T) {
	for _, stopFailure := range []bool{false, true} {
		name := "confirmed-cleanup"
		if stopFailure {
			name = "unconfirmed-cleanup"
		}
		t.Run(name, func(t *testing.T) {
			var process *failedActivationProcess
			f := newApplyFixtureWithProcess(t, func(base *fakeApplyProcess) apply.Process {
				process = &failedActivationProcess{fakeApplyProcess: base}
				return process
			})
			if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
				t.Fatal(err)
			}
			if err := f.engine.Deactivate(t.Context()); err != nil {
				t.Fatal(err)
			}
			process.failConfirmation = true
			f.process.stopFail = stopFailure
			defer func() { f.process.stopFail = false }()
			stops := f.process.stops
			code, state := "CORE_START_FAILED", "STOPPED"
			if stopFailure {
				code, state = "RECOVERY_FAILED", "UNKNOWN"
			}
			if err := f.engine.Activate(t.Context()); apply.ErrorCode(err) != code {
				t.Fatalf("failed activation did not report its cleanup outcome: %v", err)
			}
			if f.process.stops <= stops || f.process.Snapshot(t.Context()).State != state || f.engine.Active() {
				t.Fatalf("failed activation kept an owned process without cleanup: stops=%d state=%s", f.process.stops-stops, f.process.Snapshot(t.Context()).State)
			}
			metadata, err := f.store.Committed(t.Context())
			if err != nil || metadata.Current.Revision != "1" {
				t.Fatalf("failed activation changed the committed configuration: %v", err)
			}
			process.failConfirmation, f.process.stopFail = false, false
			if err := f.engine.Deactivate(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := f.engine.Activate(t.Context()); err != nil || f.process.Snapshot(t.Context()).State != "RUNNING" {
				t.Fatalf("retry after owned cleanup failed: %v", err)
			}
		})
	}
}
