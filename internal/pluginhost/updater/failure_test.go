// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestUpdateInstallFailureKeepsOld(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	e.ins.mu.Lock()
	e.ins.installNx["acme.demo@2.0.0"] = errBoom
	e.ins.mu.Unlock()

	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	requireProblem(t, err, problem.Internal)
	e.requireActive("acme.demo", "1.0.0")
	if v := e.dbVersion("acme.demo", "2.0.0"); v.Status != VersionRolledBack {
		t.Fatalf("candidate = %+v", v)
	}
	sagas := e.sagasFor("acme.demo")
	if last := sagas[len(sagas)-1]; last.State != SagaRolledBack {
		t.Fatalf("saga = %+v", last)
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("failed install step left a running saga")
	}
	if e.rt.count("Start") != 1 { // only the v1 install
		t.Fatalf("runtime started a package whose unit failed: %v", e.rt.callList())
	}
}

func TestUpdateReadinessFailureDiscardsCandidate(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	e.rt.setFail("Ready", "acme.demo", "2.0.0", errBoom)

	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	requireProblem(t, err, problem.PluginUnavailable)
	e.requireActive("acme.demo", "1.0.0")
	if got := e.rt.deactivations("acme.demo", "1.0.0"); got != 0 {
		t.Fatalf("old version was deactivated after a pre-swap failure: %d", got)
	}
	if inst := e.rt.instanceFor("acme.demo", "2.0.0"); inst != nil {
		t.Fatalf("candidate was not released: %+v", inst)
	}
	calls := e.rt.callList()
	stop := lastCall(t, calls, "Stop|acme.demo@2.0.0")
	release := lastCall(t, calls, "Release|acme.demo@2.0.0")
	if stop > release {
		t.Fatalf("candidate stop/release order = %v", calls)
	}
}

func TestUpdatePostSwapFailureRestoresOld(t *testing.T) {
	tests := []struct {
		name        string
		op          string
		version     string
		activations int
	}{
		{"deactivate_old", "Deactivate", "1.0.0", 1},
		{"activate_new", "Activate", "2.0.0", 2},
		{"drain_old", "Stop", "1.0.0", 2},
		{"release_old", "Release", "1.0.0", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.mustInstallV1("acme.demo")
			e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
			e.rt.setFail(tc.op, "acme.demo", tc.version, errBoom)

			_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
			requireProblem(t, err, problem.PluginUnavailable)
			e.requireActive("acme.demo", "1.0.0")
			if v := e.dbVersion("acme.demo", "1.0.0"); v.Status != VersionActive || !v.Active {
				t.Fatalf("old version after post-swap failure = %+v", v)
			}
			if v := e.dbVersion("acme.demo", "2.0.0"); v.Status != VersionRolledBack || v.Active {
				t.Fatalf("candidate after post-swap failure = %+v", v)
			}
			sagas := e.sagasFor("acme.demo")
			if last := sagas[len(sagas)-1]; last.State != SagaRolledBack || last.Err == "" {
				t.Fatalf("saga = %+v", last)
			}
			if e.runningSagaCount() != 0 {
				t.Fatal("failed update left a running saga")
			}
			// The old version is activated again when its background work was
			// deactivated before the failure; otherwise it never stopped.
			if got := e.rt.activations("acme.demo", "1.0.0"); got != tc.activations {
				t.Fatalf("old version activations = %d, want %d", got, tc.activations)
			}
		})
	}
}

// TestRecoverAfterPostSwapFailureKeepsConsistency verifies that a rollback of
// a failed post-swap update survives a host restart: the routes and the
// active row agree and a second Recover changes nothing.
func TestRecoverAfterPostSwapFailureKeepsConsistency(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	e.rt.setFail("Activate", "acme.demo", "2.0.0", errBoom)
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err == nil {
		t.Fatal("Update succeeded while Activate was failing")
	}
	e.requireActive("acme.demo", "1.0.0")

	e.reopen()
	if _, err := e.u.Recover(e.ctx()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	e.requireActive("acme.demo", "1.0.0")
	if e.runningSagaCount() != 0 {
		t.Fatal("Recover left a running saga")
	}
}

// TestAbortWithCanceledContextRecordsTerminalState: a caller that is already
// gone must not leave the saga RUNNING; abort rolls back on a detached context.
func TestAbortWithCanceledContextRecordsTerminalState(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	crashAfterStep(t, stepStart)
	if !expectPanic(t, func() {
		_, _ = e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	}) {
		t.Fatal("the injected kill did not fire")
	}
	testCrashHook = nil

	u := e.reopen()
	if err := u.loadState(e.ctx()); err != nil {
		t.Fatalf("loadState: %v", err)
	}
	running, err := u.runningSagas(e.ctx())
	if err != nil || len(running) != 1 {
		t.Fatalf("running sagas = %v, %v", running, err)
	}
	p, err := u.planFor(e.ctx(), &running[0])
	if err != nil {
		t.Fatalf("planFor: %v", err)
	}
	canceled, cancel := context.WithCancel(e.ctx())
	cancel()
	_ = u.abort(canceled, p, stepStart, errBoom)

	sagas := e.sagasFor("acme.demo")
	if last := sagas[len(sagas)-1]; last.State != SagaRolledBack && last.State != SagaFailed {
		t.Fatalf("saga state = %s, want a terminal state", last.State)
	}
	if err := u.requireNoRunningSaga(e.ctx(), "acme.demo"); err != nil {
		t.Fatalf("requireNoRunningSaga: %v", err)
	}
}

// TestReinstallAfterRejectedInstall checks that a version whose first install
// failed does not occupy its version number forever (PLG-10): the same
// package installs on retry, and a different package of the same version
// first removes the stale artifacts of the failed attempt.
func TestReinstallAfterRejectedInstall(t *testing.T) {
	e := newEnv(t)
	e.ins.add("pkg/v1.pkg", defaultPkg("acme.demo", "1.0.0"))
	e.rt.setFail("Start", "acme.demo", "1.0.0", errBoom)
	if _, err := e.u.Install(e.ctx(), InstallRequest{PackagePath: "pkg/v1.pkg"}); err == nil {
		t.Fatal("Install with a failing start succeeded")
	}
	if v := e.dbVersion("acme.demo", "1.0.0"); v.Status != VersionRejected || v.Active {
		t.Fatalf("failed install = %+v", v)
	}
	e.rt.setFail("Start", "acme.demo", "1.0.0", nil)

	if _, err := e.u.Install(e.ctx(), InstallRequest{PackagePath: "pkg/v1.pkg"}); err != nil {
		t.Fatalf("Install retry of the same package: %v", err)
	}
	e.requireActive("acme.demo", "1.0.0")

	e2 := newEnv(t)
	e2.ins.add("pkg/v1.pkg", defaultPkg("acme.demo", "1.0.0"))
	e2.rt.setFail("Start", "acme.demo", "1.0.0", errBoom)
	if _, err := e2.u.Install(e2.ctx(), InstallRequest{PackagePath: "pkg/v1.pkg"}); err == nil {
		t.Fatal("Install with a failing start succeeded")
	}
	e2.rt.setFail("Start", "acme.demo", "1.0.0", nil)
	rebuilt := defaultPkg("acme.demo", "1.0.0")
	rebuilt.MemoryMB = 64 // another package digest under the same version
	e2.ins.add("pkg/v1b.pkg", rebuilt)
	before := len(e2.ins.removedCopy())
	if _, err := e2.u.Install(e2.ctx(), InstallRequest{PackagePath: "pkg/v1b.pkg"}); err != nil {
		t.Fatalf("Install of a rebuilt package: %v", err)
	}
	if removed := e2.ins.removedCopy(); len(removed) != before+1 || removed[before] != "acme.demo@1.0.0" {
		t.Fatalf("RemoveUnit calls = %v, want the stale version removed first", removed)
	}
	if v := e2.dbVersion("acme.demo", "1.0.0"); !v.Active || v.Digest == e.dbVersion("acme.demo", "1.0.0").Digest {
		t.Fatalf("reinstalled version = %+v", v)
	}
}

// TestRetryUpdateAfterRolledBackCandidate checks that a rolled-back candidate
// can be retried with the same package, while a different package of that
// version is refused because the stale directory cannot be removed under the
// running plugin.
func TestRetryUpdateAfterRolledBackCandidate(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	e.rt.setFail("Ready", "acme.demo", "2.0.0", errBoom)
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err == nil {
		t.Fatal("Update with a failing readiness succeeded")
	}
	if v := e.dbVersion("acme.demo", "2.0.0"); v.Status != VersionRolledBack || v.Active {
		t.Fatalf("candidate = %+v", v)
	}
	e.rt.setFail("Ready", "acme.demo", "2.0.0", nil)

	rebuilt := defaultPkg("acme.demo", "2.0.0")
	rebuilt.MemoryMB = 64
	e.ins.add("pkg/v2b.pkg", rebuilt)
	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2b.pkg"})
	requireProblem(t, err, problem.StateConflict)
	e.requireActive("acme.demo", "1.0.0")

	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatalf("Update retry of the same package: %v", err)
	}
	e.requireActive("acme.demo", "2.0.0")
}
