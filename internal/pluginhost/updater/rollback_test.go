// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestRollbackHappyPath(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	e.requireActive("acme.demo", "2.0.0")

	res, err := e.u.Rollback(e.ctx(), "acme.demo")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if res.FromVersion != "2.0.0" || res.ToVersion != "1.0.0" || res.State != SagaCommitted {
		t.Fatalf("result = %+v", res)
	}
	e.requireActive("acme.demo", "1.0.0")
	if v := e.dbVersion("acme.demo", "2.0.0"); v.Status != VersionStopped || v.Active {
		t.Fatalf("rolled-back version = %+v", v)
	}
	if v := e.dbVersion("acme.demo", "1.0.0"); v.Status != VersionActive || !v.Active {
		t.Fatalf("target version = %+v", v)
	}
	if got := e.rt.activations("acme.demo", "1.0.0"); got != 2 {
		t.Fatalf("target activations = %d, want 2 (install + rollback)", got)
	}
	calls := e.rt.callList()
	startOld := lastCall(t, calls, "Start|acme.demo@1.0.0")
	swap := lastCall(t, calls, "SwapRoutes|")
	deactivateCurrent := lastCall(t, calls, "Deactivate|acme.demo@2.0.0")
	activateOld := lastCall(t, calls, "Activate|acme.demo@1.0.0")
	stopCurrent := lastCall(t, calls, "Stop|acme.demo@2.0.0")
	releaseCurrent := lastCall(t, calls, "Release|acme.demo@2.0.0")
	if !(startOld < swap && swap < deactivateCurrent && deactivateCurrent < activateOld &&
		activateOld < stopCurrent && stopCurrent < releaseCurrent) {
		t.Fatalf("rollback order = %v", calls)
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("rollback left a running saga")
	}
}

func TestRollbackWithoutPreviousVersion(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	_, err := e.u.Rollback(e.ctx(), "acme.demo")
	requireProblem(t, err, problem.NotFound)
	e.requireActive("acme.demo", "1.0.0")
}

func TestRollbackRestartWhenMemoryTight(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	e.mem.set(80<<20, "acme.demo", 40<<20)

	res, err := e.u.Rollback(e.ctx(), "acme.demo")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if res.Strategy != StrategyRestart || !res.Restarted {
		t.Fatalf("result = %+v", res)
	}
	e.requireActive("acme.demo", "1.0.0")
	calls := e.rt.callList()
	stopCurrent := lastCall(t, calls, "Stop|acme.demo@2.0.0")
	startOld := lastCall(t, calls, "Start|acme.demo@1.0.0")
	if stopCurrent > startOld {
		t.Fatalf("restart rollback started the target before stopping the current version: %v", calls)
	}
}

// TestRestartOnlyRuntimeNeverOverlaps covers the production wiring: the
// systemd unit is per plugin, so even with plenty of memory the updater must
// choose the controlled restart for update and rollback. Before
// Options.RestartOnly, a rollback with 4 GiB available selected the overlap
// strategy and the runtime refused the second unit.
func TestRestartOnlyRuntimeNeverOverlaps(t *testing.T) {
	e := newEnv(t)
	e.opts.RestartOnly = true
	e.u = e.newUpdater()
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))

	up, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if up.Strategy != StrategyRestart || !up.Restarted {
		t.Fatalf("update result = %+v, want a controlled restart", up)
	}
	e.requireActive("acme.demo", "2.0.0")

	rb, err := e.u.Rollback(e.ctx(), "acme.demo")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rb.Strategy != StrategyRestart || !rb.Restarted {
		t.Fatalf("rollback result = %+v, want a controlled restart", rb)
	}
	e.requireActive("acme.demo", "1.0.0")
}

func TestRollbackStartFailureKeepsCurrent(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	e.rt.setFail("Start", "acme.demo", "1.0.0", errBoom)

	_, err := e.u.Rollback(e.ctx(), "acme.demo")
	requireProblem(t, err, problem.PluginUnavailable)
	e.requireActive("acme.demo", "2.0.0")
	if v := e.dbVersion("acme.demo", "1.0.0"); v.Status != VersionRolledBack {
		t.Fatalf("failed rollback target = %+v", v)
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("failed rollback left a running saga")
	}
}
