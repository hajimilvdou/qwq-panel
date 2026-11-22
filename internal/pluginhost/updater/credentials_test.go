// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// ======================== saga 与凭据发布的真实 SQLite 接缝 ========================

// credentialTrackingInstaller 复用已有包/运行时 fixture，只以 SQLite 记录器
// 模拟磁盘凭据发布。生命周期方法先于生产接口存在，RED 仍能编译原实现。
type credentialTrackingInstaller struct {
	*fakeInstaller
	db          *storage.DB
	t           *testing.T
	beginCalls  int
	finishCalls int
	checkWindow bool
	oldDigest   string
	issued      int
	afterIssue  func()
}

func (*credentialTrackingInstaller) CredentialRotationEnabled() bool { return true }

func (i *credentialTrackingInstaller) BeginCredentialRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error {
	i.beginCalls++
	_, err := tx.ExecContext(ctx, `UPDATE plugin_credentials SET prev_token_sha256 = token_sha256 WHERE plugin_id = ?`, pluginID)
	return err
}

func (i *credentialTrackingInstaller) FinishCredentialRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error {
	i.finishCalls++
	_, err := tx.ExecContext(ctx, `UPDATE plugin_credentials SET prev_token_sha256 = '' WHERE plugin_id = ?`, pluginID)
	return err
}

func (i *credentialTrackingInstaller) snapshot(ctx context.Context, pluginID string) (string, string, error) {
	var current, previous string
	err := i.db.Reader().QueryRowContext(ctx, `SELECT token_sha256, prev_token_sha256 FROM plugin_credentials WHERE plugin_id = ?`, pluginID).Scan(&current, &previous)
	return current, previous, err
}

func (i *credentialTrackingInstaller) InstallUnit(ctx context.Context, staged Staged) error {
	if err := i.fakeInstaller.InstallUnit(ctx, staged); err != nil {
		return err
	}
	return i.issueCredential(ctx, staged.PluginID, staged.Version)
}

func (i *credentialTrackingInstaller) ReinstallUnit(ctx context.Context, pluginID, version string, m *manifest.Manifest) error {
	if err := i.fakeInstaller.ReinstallUnit(ctx, pluginID, version, m); err != nil {
		return err
	}
	return i.issueCredential(ctx, pluginID, version)
}

func (i *credentialTrackingInstaller) issueCredential(ctx context.Context, pluginID, version string) error {
	_, previous, err := i.snapshot(ctx, pluginID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if i.checkWindow && previous != i.oldDigest {
		i.t.Error("the saga did not capture the original credential before installing a candidate")
	}
	// 同一阶段两次发布不同候选凭据，模拟外部动作成功后尚未记步骤的重试。
	for range 2 {
		i.issued++
		digest := sha256.Sum256([]byte(fmt.Sprintf("TEST-ONLY-credential:%s:%s:%d", pluginID, version, i.issued)))
		err := i.db.Update(ctx, func(tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO plugin_credentials (plugin_id, token_sha256, issued_at) VALUES (?, ?, ?)
				ON CONFLICT (plugin_id) DO UPDATE SET token_sha256 = excluded.token_sha256, issued_at = excluded.issued_at`,
				pluginID, hex.EncodeToString(digest[:]), storage.FormatTime(tx.Now()))
			return err
		})
		if err != nil {
			return err
		}
		_, previous, err := i.snapshot(ctx, pluginID)
		if err != nil {
			return err
		}
		if i.checkWindow && previous != i.oldDigest {
			i.t.Error("a repeated credential issue discarded the still-running original credential")
		}
	}
	if i.afterIssue != nil {
		i.afterIssue()
	}
	return nil
}

func newCredentialEnv(t *testing.T) (*env, *credentialTrackingInstaller) {
	t.Helper()
	return newCredentialEnvAt(t, true)
}

func newCredentialEnvAt(t *testing.T, singleUnit bool) (*env, *credentialTrackingInstaller) {
	t.Helper()
	e := newEnv(t)
	i := &credentialTrackingInstaller{fakeInstaller: e.ins, db: e.db, t: t}
	e.opts.Installer = i
	e.opts.RestartOnly = singleUnit
	e.rt.singleUnit = singleUnit
	e.u = e.newUpdater()
	e.mustInstallV1("acme.demo")
	current, _, err := i.snapshot(t.Context(), "acme.demo")
	if err != nil {
		t.Fatal(err)
	}
	i.oldDigest = current
	i.checkWindow = true
	i.beginCalls, i.finishCalls = 0, 0
	e.ins.add("pkg/v2.pkg", defaultPkg("acme.demo", "2.0.0"))
	return e, i
}

func TestSagaCredentialWindowBeginsOnceAndClosesAtCommit(t *testing.T) {
	e, i := newCredentialEnv(t)
	if _, err := e.u.Update(t.Context(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatal(err)
	}
	if i.beginCalls != 1 || i.finishCalls != 1 {
		t.Errorf("credential lifecycle calls: begin=%d finish=%d, want one of each", i.beginCalls, i.finishCalls)
	}
	current, previous, err := i.snapshot(t.Context(), "acme.demo")
	if err != nil {
		t.Fatal(err)
	}
	if current == i.oldDigest || previous != "" {
		t.Fatal("committed candidate did not keep only its own credential")
	}
	e.requireActive("acme.demo", "2.0.0")
}

func requireCredentialSettled(t *testing.T, e *env, i *credentialTrackingInstaller, version string) {
	t.Helper()
	current, previous, err := i.snapshot(t.Context(), "acme.demo")
	if err != nil || previous != "" || current == i.oldDigest {
		t.Fatal("healthy terminal state did not keep only the actual current generation's credential")
	}
	e.requireActive("acme.demo", version)
	instance := e.rt.instanceFor("acme.demo", version)
	if instance == nil || instance.stopped || !instance.active {
		t.Fatal("the database marked a missing or stopped credential generation healthy")
	}
	if e.runningSagaCount() != 0 || i.beginCalls != 1 {
		t.Fatal("credential recovery remained running or recaptured the original slot")
	}
}

func TestCredentialRecoveryAtEveryStep(t *testing.T) {
	for _, target := range []step{stepInstall, stepStopOld, stepStart, stepSwap, stepActivateNew, stepReleaseOld, stepCommit} {
		t.Run(string(target), func(t *testing.T) {
			runCredentialCrash(t, target, true)
		})
	}
}

func runCredentialCrash(t *testing.T, target step, singleUnit bool) {
	t.Helper()
	e, i := newCredentialEnvAt(t, singleUnit)
	crashAfterStep(t, target)
	if !expectPanic(t, func() {
		_, _ = e.u.Update(t.Context(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"})
	}) {
		t.Fatal("the injected credential crash did not fire")
	}
	testCrashHook = nil
	e.reopen()
	if _, err := e.u.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	version := "2.0.0"
	if target == stepInstall || (!singleUnit && target == stepStart) {
		version = "1.0.0"
	}
	requireCredentialSettled(t, e, i, version)
	if recovered, err := e.u.Recover(t.Context()); err != nil || len(recovered) != 0 {
		t.Fatal("a repeated recovery reopened the credential window")
	}
}

func TestCredentialOverlapRecoveryAtEveryStep(t *testing.T) {
	for _, target := range []step{stepInstall, stepStart, stepSwap, stepDeactivateOld, stepActivateNew, stepDrainOld, stepReleaseOld, stepCommit} {
		t.Run(string(target), func(t *testing.T) { runCredentialCrash(t, target, false) })
	}
}

func TestCredentialRollbackRecoveryAtEveryStep(t *testing.T) {
	for _, target := range []step{stepArm, stepStopOld, stepStart, stepSwap, stepActivateNew, stepReleaseOld, stepCommit} {
		t.Run(string(target), func(t *testing.T) {
			e, i := newCredentialEnv(t)
			if _, err := e.u.Update(t.Context(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
				t.Fatal(err)
			}
			current, _, err := i.snapshot(t.Context(), "acme.demo")
			if err != nil {
				t.Fatal(err)
			}
			i.oldDigest = current
			i.beginCalls, i.finishCalls = 0, 0
			crashAfterStep(t, target)
			if !expectPanic(t, func() { _, _ = e.u.Rollback(t.Context(), "acme.demo") }) {
				t.Fatal("the injected rollback credential crash did not fire")
			}
			testCrashHook = nil
			e.reopen()
			if _, err := e.u.Recover(t.Context()); err != nil {
				t.Fatal(err)
			}
			requireCredentialSettled(t, e, i, "1.0.0")
		})
	}
}

func TestCredentialPreStopFailureReplacesOldHandle(t *testing.T) {
	e, i := newCredentialEnv(t)
	previous := e.rt.instanceFor("acme.demo", "1.0.0")
	e.ins.mu.Lock()
	e.ins.installNx["acme.demo@2.0.0"] = errBoom
	e.ins.mu.Unlock()
	if _, err := e.u.Update(t.Context(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err == nil {
		t.Fatal("the failed unit install was accepted")
	}
	requireCredentialSettled(t, e, i, "1.0.0")
	if previous == e.rt.instanceFor("acme.demo", "1.0.0") || !previous.stopped || !previous.released {
		t.Fatal("credential restoration reused the process that still held the old token")
	}
}

func TestCredentialCommitAndRollbackTxRecovery(t *testing.T) {
	e, i := newCredentialEnv(t)
	if err := e.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `CREATE TRIGGER fail_credential_close BEFORE UPDATE OF prev_token_sha256 ON plugin_credentials
			WHEN NEW.prev_token_sha256 = '' AND OLD.prev_token_sha256 <> '' BEGIN SELECT RAISE(ABORT, 'TEST-ONLY-close-failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.u.Update(t.Context(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err == nil {
		t.Fatal("failed commit and rollback credential transactions were accepted")
	}
	sagas := e.sagasFor("acme.demo")
	latest := sagas[len(sagas)-1]
	if latest.State != SagaRunning || latest.Step != credentialAbortPrefix+string(stepCommit) {
		t.Fatal("the failed terminal write lost its persisted compensation intent")
	}
	if err := e.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DROP TRIGGER fail_credential_close`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	if _, err := e.u.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireCredentialSettled(t, e, i, "1.0.0")
	if candidate := e.rt.instanceFor("acme.demo", "2.0.0"); candidate != nil && !candidate.stopped {
		t.Fatal("credential recovery resurrected the stopped candidate as active")
	}
}

func TestCredentialAbortMarkerFailureHasNoCompensation(t *testing.T) {
	e, i := newCredentialEnv(t)
	if err := e.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `CREATE TRIGGER fail_credential_marker BEFORE UPDATE OF step ON plugin_update_sagas
			WHEN NEW.step LIKE 'credential_abort/%' BEGIN SELECT RAISE(ABORT, 'TEST-ONLY-marker-failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.rt.setFail("Ready", "acme.demo", "2.0.0", errBoom)
	if _, err := e.u.Update(t.Context(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err == nil {
		t.Fatal("the failed compensation marker was accepted")
	}
	for _, call := range e.rt.callList() {
		if strings.HasPrefix(call, "Stop|acme.demo@2.0.0") {
			t.Fatal("external compensation ran before its intent was durable")
		}
	}
	if e.rt.count("Start") != 2 {
		t.Fatal("credential compensation started another process before its intent was durable")
	}
	if err := e.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DROP TRIGGER fail_credential_marker`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.rt.setFail("Ready", "acme.demo", "2.0.0", nil)
	e.reopen()
	if _, err := e.u.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireCredentialSettled(t, e, i, "2.0.0")
}

func TestCredentialCallerCancelStillSettles(t *testing.T) {
	e, i := newCredentialEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	i.afterIssue = cancel
	if _, err := e.u.Update(ctx, UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err != nil {
		t.Fatal("caller cancellation interrupted the already accepted credential saga")
	}
	requireCredentialSettled(t, e, i, "2.0.0")
}

func TestCredentialBeginTxFailureHasNoInstall(t *testing.T) {
	e, i := newCredentialEnv(t)
	_, _, before := e.ins.counts()
	if err := e.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `CREATE TRIGGER fail_credential_begin BEFORE UPDATE OF prev_token_sha256 ON plugin_credentials
			WHEN NEW.prev_token_sha256 = NEW.token_sha256 AND NEW.prev_token_sha256 <> '' BEGIN SELECT RAISE(ABORT, 'TEST-ONLY-begin-failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.u.Update(t.Context(), UpdateRequest{PluginID: "acme.demo", PackagePath: "pkg/v2.pkg"}); err == nil {
		t.Fatal("a failed credential window transaction was accepted")
	}
	current, previous, err := i.snapshot(t.Context(), "acme.demo")
	_, _, after := e.ins.counts()
	if err != nil || current != i.oldDigest || previous != "" || len(before) != len(after) || e.runningSagaCount() != 0 {
		t.Fatal("a failed credential begin transaction left a saga, changed slots or installed a unit")
	}
}

// 单 unit 的存活进程也必须核版本，清理旧版不得误附着/停掉当前新版。
func TestSingleUnitAttachRequiresExactVersion(t *testing.T) {
	runtime := newFakeRuntime()
	runtime.singleUnit = true
	spec := InstanceSpec{PluginID: "acme.demo", Version: "1.0.0"}
	handle, err := runtime.Start(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	other := spec
	other.Version = "2.0.0"
	if _, err := runtime.Attach(t.Context(), other); err == nil {
		t.Fatal("the single unit's other version was accepted as a cleanup handle")
	}
	actual, err := runtime.Attach(t.Context(), spec)
	if err != nil || actual != handle {
		t.Fatal("the exact live version could not be attached")
	}
	instance := handle.(*fakeInstance)
	if instance.stopped || instance.released {
		t.Fatal("rejecting a foreign version changed the live instance")
	}
}
