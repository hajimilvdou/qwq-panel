// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

func TestUpdateOverlapHappyPath(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))

	res, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.State != SagaCommitted || res.Strategy != StrategyOverlap || res.Restarted {
		t.Fatalf("result = %+v", res)
	}
	if res.FromVersion != "1.0.0" || res.ToVersion != "2.0.0" {
		t.Fatalf("result versions = %+v", res)
	}
	e.requireActive("acme.demo", "2.0.0")

	old := e.dbVersion("acme.demo", "1.0.0")
	if old.Status != VersionStopped || old.Active {
		t.Fatalf("old version after update = %+v", old)
	}
	current := e.dbVersion("acme.demo", "2.0.0")
	if current.Status != VersionActive || !current.Active || current.ActivatedAt.IsZero() {
		t.Fatalf("new version after update = %+v", current)
	}
	if versions, err := e.u.Versions("acme.demo"); err != nil || len(versions) != 2 {
		t.Fatalf("Versions = %+v, %v", versions, err)
	}
	if got := e.rt.activations("acme.demo", "2.0.0"); got != 1 {
		t.Fatalf("candidate Activations = %d, want 1", got)
	}
	if got := e.rt.deactivations("acme.demo", "1.0.0"); got != 1 {
		t.Fatalf("old Deactivations = %d, want 1", got)
	}

	calls := e.rt.callList()
	startNew := findCall(t, calls, "Start|acme.demo@2.0.0")
	swap := lastCall(t, calls, "SwapRoutes|")
	deactivateOld := findCall(t, calls, "Deactivate|acme.demo@1.0.0")
	activateNew := findCall(t, calls, "Activate|acme.demo@2.0.0")
	stopOld := findCall(t, calls, "Stop|acme.demo@1.0.0")
	releaseOld := findCall(t, calls, "Release|acme.demo@1.0.0")
	if !(startNew < swap && swap < deactivateOld && deactivateOld < activateNew &&
		activateNew < stopOld && stopOld < releaseOld) {
		t.Fatalf("unexpected update order: %v", calls)
	}

	sagas := e.sagasFor("acme.demo")
	if len(sagas) != 2 { // install + update
		t.Fatalf("sagas = %+v", sagas)
	}
	last := sagas[len(sagas)-1]
	if last.State != SagaCommitted || last.Step != string(stepCommitted) || last.Mode != modeUpdate {
		t.Fatalf("update saga = %+v", last)
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("a saga is still running")
	}
}

func TestUpdateRestartFromManifest(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	unsafe := defaultPkg("acme.demo", "2.0.0")
	unsafe.OverlapSafe = false
	e.ins.add("pkg/v2.pkg", unsafe)

	res, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.Strategy != StrategyRestart || !res.Restarted {
		t.Fatalf("result = %+v", res)
	}
	e.requireActive("acme.demo", "2.0.0")
	if got := e.rt.deactivations("acme.demo", "1.0.0"); got != 0 {
		t.Fatalf("restart must not Deactivate the stopped old version, got %d", got)
	}
	calls := e.rt.callList()
	stopOld := findCall(t, calls, "Stop|acme.demo@1.0.0")
	startNew := findCall(t, calls, "Start|acme.demo@2.0.0")
	swap := lastCall(t, calls, "SwapRoutes|")
	if !(stopOld < startNew && startNew < swap) {
		t.Fatalf("restart order = %v", calls)
	}
}

func TestUpdateInsufficientMemoryDowngradesToRestart(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.mem.set(80<<20, "acme.demo", 40<<20) // overlap needs 152 MiB, restart needs 112 MiB
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))

	res, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.Strategy != StrategyRestart || !res.Restarted {
		t.Fatalf("result = %+v", res)
	}
	e.requireActive("acme.demo", "2.0.0")
}

func TestUpdateInsufficientMemoryIsRefused(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.mem.set(10<<20, "acme.demo", 20<<20) // restart needs 112 MiB
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))

	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	requireProblem(t, err, problem.Unavailable)
	e.requireActive("acme.demo", "1.0.0")
	if versions, _ := e.u.Versions("acme.demo"); len(versions) != 1 {
		t.Fatalf("a refused preflight left a version: %+v", versions)
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("a refused preflight left a running saga")
	}
}

func TestUpdateRestartFailureRestoresOld(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	unsafe := defaultPkg("acme.demo", "2.0.0")
	unsafe.OverlapSafe = false
	e.ins.add("pkg/v2.pkg", unsafe)
	e.rt.setFail("Start", "acme.demo", "2.0.0", errBoom)

	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	requireProblem(t, err, problem.PluginUnavailable)
	e.requireActive("acme.demo", "1.0.0")
	old := e.dbVersion("acme.demo", "1.0.0")
	if old.Status != VersionActive || !old.Active {
		t.Fatalf("old version after failed restart = %+v", old)
	}
	failed := e.dbVersion("acme.demo", "2.0.0")
	if failed.Status != VersionRolledBack || failed.Active {
		t.Fatalf("failed candidate = %+v", failed)
	}
	if got := e.rt.activations("acme.demo", "1.0.0"); got != 2 {
		t.Fatalf("old version activations = %d, want 2 (install + restore)", got)
	}
	sagas := e.sagasFor("acme.demo")
	last := sagas[len(sagas)-1]
	if last.State != SagaRolledBack {
		t.Fatalf("saga state = %+v", last)
	}
	if last.Err == "" {
		t.Fatal("rolled back saga has no error text")
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("failed update left a running saga")
	}
}

func TestUpdateOverlapStartFailureKeepsOld(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	e.rt.setFail("Start", "acme.demo", "2.0.0", errBoom)

	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	requireProblem(t, err, problem.PluginUnavailable)
	e.requireActive("acme.demo", "1.0.0")
	if v := e.dbVersion("acme.demo", "2.0.0"); v.Status != VersionRolledBack {
		t.Fatalf("candidate = %+v", v)
	}
	if got := e.rt.deactivations("acme.demo", "1.0.0"); got != 0 {
		t.Fatalf("old version was deactivated before the route switch: %d", got)
	}
}

func TestUpdateRejectsNewCapability(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	withCap := defaultPkg("acme.demo", "2.0.0")
	withCap.Caps = []manifest.Capability{{Name: "fs.write", Scope: "/data", Reason: "needed"}}
	e.ins.add("pkg/v2.pkg", withCap)

	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	requireProblem(t, err, problem.ValidationFailed)
	pe := problem.From(err)
	if len(pe.Violations) != 1 || pe.Violations[0].Code != "CAPABILITY_NOT_ACCEPTED" {
		t.Fatalf("violations = %+v", pe.Violations)
	}
	e.requireActive("acme.demo", "1.0.0")
	if _, ok := e.u.Active("acme.demo"); !ok {
		t.Fatal("old version lost after capability rejection")
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("capability rejection left a running saga")
	}

	res, err := e.u.Update(e.ctx(), UpdateRequest{
		PluginID: "acme.demo", PackagePath: "pkg/v2.pkg", AcceptedCapabilities: []string{"fs.write"},
	})
	if err != nil {
		t.Fatalf("Update with accepted capability: %v", err)
	}
	if res.ToVersion != "2.0.0" {
		t.Fatalf("result = %+v", res)
	}
	e.requireActive("acme.demo", "2.0.0")
}

func TestUpdateExpectedRevisionConflict(t *testing.T) {
	e := newEnv(t)
	active := e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))

	_, err := e.u.Update(e.ctx(), UpdateRequest{
		PluginID: "acme.demo", PackagePath: "pkg/v2.pkg", ExpectedRevision: active.Revision + 1,
	})
	requireProblem(t, err, problem.RevisionConflict)
	if got := problem.From(err).CurrentRevision; got != fmtRevision(active.Revision) {
		t.Fatalf("CurrentRevision = %q, want %q", got, fmtRevision(active.Revision))
	}
	e.requireActive("acme.demo", "1.0.0")
}

func TestUpdateDuplicateVersionConflict(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/same.pkg", defaultPkg("acme.demo", "1.0.0"))
	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/same.pkg"})
	requireProblem(t, err, problem.StateConflict)

	_, err = e.u.Install(e.ctx(), InstallRequest{PackagePath: "pkg/same.pkg"})
	requireProblem(t, err, problem.StateConflict)
}

func TestConcurrentUpdatesSerialized(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))

	type outcome struct {
		res *UpdateResult
		err error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
			results <- outcome{res: res, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var successes, conflicts int
	for r := range results {
		switch {
		case r.err == nil:
			successes++
		case problem.HasCode(r.err, problem.StateConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent update error: %v", r.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d, want 1/1", successes, conflicts)
	}
	e.requireActive("acme.demo", "2.0.0")
	if got := e.rt.activations("acme.demo", "2.0.0"); got != 1 {
		t.Fatalf("candidate activations = %d, want 1", got)
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("concurrent updates left a running saga")
	}
}

func TestIllegalVersionTransition(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	err := e.db.Update(e.ctx(), func(tx *storage.Tx) error {
		return e.u.setVersionStatusTx(e.ctx(), tx, "acme.demo", "1.0.0", VersionStaged)
	})
	requireProblem(t, err, problem.StateConflict)

	if canTransition(VersionRejected, VersionActive) {
		t.Fatal("REJECTED -> ACTIVE accepted")
	}
	if canTransition(VersionCandidate, VersionActive) == false {
		t.Fatal("CANDIDATE -> ACTIVE rejected")
	}
	if !canTransition(VersionActive, VersionActive) {
		t.Fatal("same-state transition should be a no-op")
	}
}

// TestUpdateTimeoutFailsBeforeAnyEffect checks that an expired deadline does
// not leave a running saga. (Caller cancellation is ignored on purpose; see
// TestUpdateCallerCancelStillFinalizesSaga.)
func TestUpdateTimeoutFailsBeforeAnyEffect(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg", Timeout: time.Nanosecond})
	if err == nil {
		t.Fatal("Update succeeded past its deadline")
	}
	e.requireActive("acme.demo", "1.0.0")
	if e.runningSagaCount() != 0 {
		t.Fatal("cancelled update left a running saga")
	}
}

func fmtRevision(n int64) string { return strconv.FormatInt(n, 10) }

// TestUpdateCallerCancelStillFinalizesSaga: the caller cancelling mid-saga
// (closed page, proxy timeout) must not cut the saga in half. The update runs
// on a detached context and reaches a terminal state with a running version.
func TestUpdateCallerCancelStillFinalizesSaga(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	unsafe := defaultPkg("acme.demo", "2.0.0")
	unsafe.OverlapSafe = false
	e.ins.add("pkg/v2.pkg", unsafe)
	ctx, cancel := context.WithCancel(e.ctx())
	defer cancel()
	testCrashHook = func(s string) {
		if s == string(stepStart) {
			cancel()
		}
	}
	t.Cleanup(func() { testCrashHook = nil })

	if _, err := e.u.Update(ctx, UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatalf("Update after caller cancel: %v", err)
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("caller cancel left a running saga")
	}
	e.requireActive("acme.demo", "2.0.0")
	if inst := e.rt.instanceFor("acme.demo", "2.0.0"); inst == nil || inst.stopped {
		t.Fatalf("active version is not running: %+v", inst)
	}
}

// TestOrphanRunningSagaRecoveredInline: a RUNNING saga seen under the plugin
// lock is an orphan; the next operation recovers it instead of refusing until
// the host restarts.
func TestOrphanRunningSagaRecoveredInline(t *testing.T) {
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
	if e.runningSagaCount() != 1 {
		t.Fatal("the kill did not leave a running saga")
	}

	e.ins.add("pkg/v3.pkg", defaultPkg("acme.demo", "3.0.0"))
	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v3.pkg"}); err != nil {
		t.Fatalf("Update with an orphan saga: %v", err)
	}
	if e.runningSagaCount() != 0 {
		t.Fatal("orphan saga still running")
	}
	e.requireActive("acme.demo", "3.0.0")
}

// singleUnitRestartUpdate installs v1 on a single-unit runtime, breaks op on
// v2 and runs the update, which must roll back.
func singleUnitRestartUpdate(t *testing.T, op string) *env {
	t.Helper()
	e := newEnv(t)
	e.rt.singleUnit = true
	e.opts.RestartOnly = true
	e.u = e.newUpdater()
	e.mustInstallV1("acme.demo")
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	e.rt.setFail(op, "acme.demo", "2.0.0", errBoom)

	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	requireProblem(t, err, problem.PluginUnavailable)
	e.requireActive("acme.demo", "1.0.0")
	inst := e.rt.instanceFor("acme.demo", "1.0.0")
	if inst == nil || inst.stopped || !inst.active {
		t.Fatalf("restored v1 instance = %+v, want running and active; calls %v", inst, e.rt.callList())
	}
	sagas := e.sagasFor("acme.demo")
	if last := sagas[len(sagas)-1]; last.State != SagaRolledBack {
		t.Fatalf("saga = %+v, want ROLLED_BACK", last)
	}
	return e
}

func TestRestartUpdateCandidateStartFailureRestoresOldSingleUnit(t *testing.T) {
	e := singleUnitRestartUpdate(t, "Start")
	calls := e.rt.callList()
	restart := lastCall(t, calls, "Start|acme.demo@1.0.0")
	for i, c := range calls {
		if c == "Stop|acme.demo@2.0.0" && i > restart {
			t.Fatalf("the candidate was stopped after v1 restarted: %v", calls)
		}
	}
}

func TestRestartUpdateCandidateNotReadyRestoresOldSingleUnit(t *testing.T) {
	e := singleUnitRestartUpdate(t, "Ready")
	calls := e.rt.callList()
	if stop, restart := findCall(t, calls, "Stop|acme.demo@2.0.0"), lastCall(t, calls, "Start|acme.demo@1.0.0"); stop > restart {
		t.Fatalf("Stop|v2 after Start|v1: %v", calls)
	}
}

// TestUpdateScopeWideningRequiresAcceptance checks that capabilities are
// identified by (name, scope): widening the scope of an already granted
// capability needs fresh consent, and a bare name is ambiguous once the
// manifest declares it under several scopes (PLG-09).
func TestUpdateScopeWideningRequiresAcceptance(t *testing.T) {
	e := newEnv(t)
	v1 := defaultPkg("acme.demo", "1.0.0")
	v1.Caps = []manifest.Capability{{Name: "fs.write", Scope: "/var/lib/x", Reason: "needed"}}
	e.installPackage("pkg/v1.pkg", v1, "fs.write")
	v2 := defaultPkg("acme.demo", "2.0.0")
	v2.Caps = []manifest.Capability{{Name: "fs.write", Scope: "/", Reason: "needed"}}
	e.ins.add("pkg/v2.pkg", v2)

	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	requireProblem(t, err, problem.ValidationFailed)
	if pe := problem.From(err); len(pe.Violations) != 1 || pe.Violations[0].Code != "CAPABILITY_NOT_ACCEPTED" {
		t.Fatalf("violations = %+v", pe.Violations)
	}
	_, err = e.u.Update(e.ctx(), UpdateRequest{
		PluginID: "acme.demo", PackagePath: "pkg/v2.pkg", AcceptedCapabilities: []string{"fs.write:/var/lib/x"},
	})
	requireProblem(t, err, problem.ValidationFailed)
	e.requireActive("acme.demo", "1.0.0")

	if _, err := e.u.Update(e.ctx(), UpdateRequest{
		PluginID: "acme.demo", PackagePath: "pkg/v2.pkg", AcceptedCapabilities: []string{"fs.write:/"},
	}); err != nil {
		t.Fatalf("Update with the widened scope accepted: %v", err)
	}
	e.requireActive("acme.demo", "2.0.0")

	v3 := defaultPkg("acme.demo", "3.0.0")
	v3.Caps = []manifest.Capability{
		{Name: "fs.write", Scope: "/", Reason: "needed"},
		{Name: "fs.write", Scope: "/srv", Reason: "needed"},
	}
	e.ins.add("pkg/v3.pkg", v3)
	_, err = e.u.Update(e.ctx(), UpdateRequest{
		PluginID: "acme.demo", PackagePath: "pkg/v3.pkg", AcceptedCapabilities: []string{"fs.write"},
	})
	requireProblem(t, err, problem.ValidationFailed)
	if pe := problem.From(err); len(pe.Violations) != 1 || pe.Violations[0].Code != "AMBIGUOUS_CAPABILITY" {
		t.Fatalf("violations = %+v", pe.Violations)
	}
}

// TestUpdateScopeUnchangedNoPrompt checks that an update keeping the same
// (name, scope) needs no consent, while a bare name still accepts a capability
// declared under a single scope.
func TestUpdateScopeUnchangedNoPrompt(t *testing.T) {
	e := newEnv(t)
	v1 := defaultPkg("acme.demo", "1.0.0")
	v1.Caps = []manifest.Capability{{Name: "fs.write", Scope: "/var/lib/x", Reason: "needed"}}
	e.installPackage("pkg/v1.pkg", v1, "fs.write")
	v2 := defaultPkg("acme.demo", "2.0.0")
	v2.Caps = v1.Caps
	e.ins.add("pkg/v2.pkg", v2)

	if _, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatalf("Update with an unchanged scope: %v", err)
	}
	e.requireActive("acme.demo", "2.0.0")
}

// installForPublisher installs v1 of acme.demo by publisher a and stages v2 by
// publisher b.
func installForPublisher(e *env) {
	v1 := defaultPkg("acme.demo", "1.0.0")
	v1.Publisher = "a"
	e.installPackage("pkg/v1.pkg", v1)
	v2 := defaultPkg("acme.demo", "2.0.0")
	v2.Publisher = "b"
	e.ins.add("pkg/v2.pkg", v2)
}

func TestUpdateRejectsPublisherChange(t *testing.T) {
	e := newEnv(t)
	installForPublisher(e)
	_, err := e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	if !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Update = %v, want VALIDATION_FAILED", err)
	}
	e.requireActive("acme.demo", "1.0.0")
}

func TestUpdatePublisherChangeWithAcceptance(t *testing.T) {
	e := newEnv(t)
	installForPublisher(e)
	if _, err := e.u.Update(e.ctx(), UpdateRequest{
		PluginID: "acme.demo", PackagePath: "pkg/v2.pkg", AcceptPublisherChange: true,
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	e.requireActive("acme.demo", "2.0.0")
}

func TestInstallAndUpdateRejectOldSchema(t *testing.T) {
	e := newEnv(t)
	old := defaultPkg("acme.old", "1.0.0")
	old.SchemaVersion = "1.1"
	e.ins.add("pkg/old.pkg", old)
	_, err := e.u.Install(e.ctx(), InstallRequest{PackagePath: "pkg/old.pkg"})
	requireProblem(t, err, problem.ValidationFailed)

	e.mustInstallV1("acme.demo")
	v2 := defaultPkg("acme.demo", "2.0.0")
	v2.SchemaVersion = "1.0"
	e.ins.add("pkg/v2.pkg", v2)
	_, err = e.u.Update(e.ctx(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	requireProblem(t, err, problem.ValidationFailed)
	if pe := problem.From(err); len(pe.Violations) != 1 || pe.Violations[0].Code != "SCHEMA_VERSION_TOO_OLD" {
		t.Fatalf("violations = %+v", pe.Violations)
	}
	e.requireActive("acme.demo", "1.0.0")
}

// TestStageProblemMapping: an install policy rejection is VALIDATION_FAILED
// with the violation the installer produced; anything else stays INTERNAL.
func TestStageProblemMapping(t *testing.T) {
	perr := &install.PolicyError{Path: "ui/app.js", Code: "UI_REMOTE_SCRIPT", Message: "no remote scripts"}
	mapped := problem.From(stageProblem(perr))
	if mapped.Code != problem.ValidationFailed || len(mapped.Violations) != 1 ||
		mapped.Violations[0].Pointer != "/ui/app.js" || mapped.Violations[0].Code != "UI_REMOTE_SCRIPT" {
		t.Fatalf("mapped = %+v", mapped)
	}
	other := problem.From(stageProblem(errors.New("boom")))
	if other.Code != problem.Internal {
		t.Fatalf("internal mapping = %+v", other)
	}
}
