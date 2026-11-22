// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/storage"
)

// crashAfterStep arms the test hook so that the saga panics after the
// external action of target and before its recording transaction.
func crashAfterStep(t *testing.T, target step) {
	t.Helper()
	testCrashHook = func(s string) {
		if s == string(target) {
			panic("simulated kill")
		}
	}
	t.Cleanup(func() { testCrashHook = nil })
}

func expectPanic(t *testing.T, fn func()) bool {
	t.Helper()
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		fn()
	}()
	return panicked
}

func TestCrashAtEveryOverlapStep(t *testing.T) {
	tests := []struct {
		step         step
		expectActive string
	}{
		{stepInstall, "1.0.0"},
		{stepStart, "1.0.0"},
		{stepSwap, "2.0.0"},
		{stepDeactivateOld, "2.0.0"},
		{stepActivateNew, "2.0.0"},
		{stepDrainOld, "2.0.0"},
		{stepReleaseOld, "2.0.0"},
		{stepCommit, "2.0.0"},
	}
	for _, tc := range tests {
		t.Run(string(tc.step), func(t *testing.T) {
			e := newEnv(t)
			e.mustInstallV1("acme.demo")
			e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
			crashAfterStep(t, tc.step)

			panicked := expectPanic(t, func() {
				_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
				if err != nil {
					t.Fatalf("Update failed before the injected kill: %v", err)
				}
			})
			if !panicked {
				t.Fatal("the injected kill did not fire")
			}
			testCrashHook = nil

			e.reopen()
			ids, err := e.u.Recover(e.ctx())
			if err != nil {
				t.Fatalf("Recover: %v", err)
			}
			if len(ids) != 1 {
				t.Fatalf("recovered sagas = %v, want 1", ids)
			}
			e.requireActive("acme.demo", tc.expectActive)
			if e.runningSagaCount() != 0 {
				t.Fatal("recovery left a running saga")
			}
			// No version may be activated twice; recovery either committed the
			// single activation or discarded the candidate before activating.
			if got := e.rt.activations("acme.demo", "2.0.0"); got > 1 {
				t.Fatalf("candidate activated %d times", got)
			}
			// The inactive version must not be running. A process that the
			// crash already stopped may still be known to the runtime until a
			// later Release; it is not serving anything.
			inactive := "2.0.0"
			if tc.expectActive == "2.0.0" {
				inactive = "1.0.0"
			}
			if inst := e.rt.instanceFor("acme.demo", inactive); inst != nil && !inst.stopped {
				t.Fatalf("inactive version still has a running instance: %+v", inst)
			}

			ids, err = e.u.Recover(e.ctx())
			if err != nil || len(ids) != 0 {
				t.Fatalf("second Recover = %v, %v; want empty and nil", ids, err)
			}
			e.requireActive("acme.demo", tc.expectActive)
		})
	}
}

func TestCrashAtEveryRestartStep(t *testing.T) {
	tests := []struct {
		step         step
		expectActive string
	}{
		{stepInstall, "1.0.0"}, // no staged package after a crash: cannot install
		{stepStopOld, "2.0.0"},
		{stepStart, "2.0.0"},
		{stepSwap, "2.0.0"},
		{stepActivateNew, "2.0.0"},
		{stepReleaseOld, "2.0.0"},
		{stepCommit, "2.0.0"},
	}
	for _, tc := range tests {
		t.Run(string(tc.step), func(t *testing.T) {
			e := newEnv(t)
			e.mustInstallV1("acme.demo")
			unsafe := defaultPkg("acme.demo", "2.0.0")
			unsafe.OverlapSafe = false
			e.ins.add("pkg/v2.pkg", unsafe)
			crashAfterStep(t, tc.step)

			panicked := expectPanic(t, func() {
				_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
				if err != nil {
					t.Fatalf("Update failed before the injected kill: %v", err)
				}
			})
			if !panicked {
				t.Fatal("the injected kill did not fire")
			}
			testCrashHook = nil

			e.reopen()
			if _, err := e.u.Recover(e.ctx()); err != nil {
				t.Fatalf("Recover: %v", err)
			}
			e.requireActive("acme.demo", tc.expectActive)
			if e.runningSagaCount() != 0 {
				t.Fatal("recovery left a running saga")
			}
			if got := e.rt.activations("acme.demo", "2.0.0"); got > 1 {
				t.Fatalf("candidate activated %d times", got)
			}
		})
	}
}

func TestCrashDuringInstallSaga(t *testing.T) {
	t.Run("commit", func(t *testing.T) {
		e := newEnv(t)
		e.ins.add("pkg/v1.pkg", defaultPkg("acme.demo", "1.0.0"))
		crashAfterStep(t, stepCommit)
		panicked := expectPanic(t, func() {
			_, err := e.u.Install(e.ctx(), InstallRequest{PackagePath: "pkg/v1.pkg"})
			if err != nil {
				t.Fatalf("Install failed before the injected kill: %v", err)
			}
		})
		if !panicked {
			t.Fatal("the injected kill did not fire")
		}
		testCrashHook = nil
		e.reopen()
		ids, err := e.u.Recover(e.ctx())
		if err != nil || len(ids) != 1 {
			t.Fatalf("Recover = %v, %v", ids, err)
		}
		e.requireActive("acme.demo", "1.0.0")
	})

	t.Run("install", func(t *testing.T) {
		e := newEnv(t)
		e.ins.add("pkg/v1.pkg", defaultPkg("acme.demo", "1.0.0"))
		crashAfterStep(t, stepInstall)
		panicked := expectPanic(t, func() {
			_, err := e.u.Install(e.ctx(), InstallRequest{PackagePath: "pkg/v1.pkg"})
			if err != nil {
				t.Fatalf("Install failed before the injected kill: %v", err)
			}
		})
		if !panicked {
			t.Fatal("the injected kill did not fire")
		}
		testCrashHook = nil
		e.reopen()
		ids, err := e.u.Recover(e.ctx())
		if err != nil {
			t.Fatalf("Recover: %v", err)
		}
		if len(ids) != 1 {
			t.Fatalf("recovered = %v", ids)
		}
		if _, ok := e.u.Active("acme.demo"); ok {
			t.Fatal("an interrupted install became active")
		}
		if v := e.dbVersion("acme.demo", "1.0.0"); v.Status != VersionRejected {
			t.Fatalf("interrupted install version = %+v", v)
		}
		sagas := e.sagasFor("acme.demo")
		if len(sagas) != 1 || sagas[0].State != SagaFailed {
			t.Fatalf("saga = %+v", sagas)
		}
		if removed := e.ins.removedCopy(); len(removed) != 1 {
			t.Fatalf("RemoveUnit calls = %v", removed)
		}
	})
}

func TestCrashDuringRollback(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	crashAfterStep(t, stepStart)
	panicked := expectPanic(t, func() {
		_, err := e.u.Rollback(e.ctx(), "acme.demo")
		if err != nil {
			t.Fatalf("Rollback failed before the injected kill: %v", err)
		}
	})
	if !panicked {
		t.Fatal("the injected kill did not fire")
	}
	testCrashHook = nil

	e.reopen()
	if _, err := e.u.Recover(e.ctx()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	e.requireActive("acme.demo", "2.0.0")
	if v := e.dbVersion("acme.demo", "1.0.0"); v.Status != VersionRolledBack {
		t.Fatalf("interrupted rollback target = %+v", v)
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("recovery left a running saga")
	}
}

func TestRecoverIsIdempotentAndRebuildsRoutes(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	before := e.rt.count("SwapRoutes")
	e.reopen()
	ids, err := e.u.Recover(e.ctx())
	if err != nil || len(ids) != 0 {
		t.Fatalf("Recover = %v, %v", ids, err)
	}
	if got := e.rt.count("SwapRoutes"); got != before+1 {
		t.Fatalf("Recover published %d route tables, want 1", got-before)
	}
	e.requireActive("acme.demo", "2.0.0")
	ids, err = e.u.Recover(e.ctx())
	if err != nil || len(ids) != 0 {
		t.Fatalf("second Recover = %v, %v", ids, err)
	}
}

func TestRecoverUnreadableSagaFailsIt(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	// Fabricate a running saga whose target version does not exist.
	if err := e.db.Update(e.ctx(), func(tx *storage.Tx) error {
		_, ierr := tx.ExecContext(e.ctx(), `INSERT INTO plugin_update_sagas
			(saga_id, plugin_id, from_version, to_version, mode, strategy, state, step, error, created_at, updated_at)
			VALUES ('sag_missing', 'acme.demo', '1.0.0', '9.9.9', 'update', 'overlap', 'RUNNING', 'start', '', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`)
		return ierr
	}); err != nil {
		t.Fatal(err)
	}
	if _, rerr := e.u.Recover(e.ctx()); rerr == nil {
		t.Fatal("Recover accepted a saga with no target version")
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("unrecoverable saga is still running")
	}
	e.requireActive("acme.demo", "1.0.0")
}
