// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// sagaMode distinguishes the three transactions that use the same steps.
type sagaMode string

const (
	modeInstall  sagaMode = "install"
	modeUpdate   sagaMode = "update"
	modeRollback sagaMode = "rollback"
)

// step is one recoverable unit of a saga. The value stored in
// plugin_update_sagas.step is the step that still has to run; a crash leaves
// that step in place, and every step is executed idempotently.
type step string

const (
	stepInstall       step = "install"
	stepArm           step = "arm"
	stepStopOld       step = "stop_old"
	stepStart         step = "start"
	stepSwap          step = "swap"
	stepDeactivateOld step = "deactivate_old"
	stepActivateNew   step = "activate_new"
	stepDrainOld      step = "drain_old"
	stepReleaseOld    step = "release_old"
	stepCommit        step = "commit"
	stepCommitted     step = "committed"
)

// saga is one row of plugin_update_sagas.
type saga struct {
	ID          string
	PluginID    string
	FromVersion string
	ToVersion   string
	Mode        sagaMode
	Strategy    Strategy
	State       SagaState
	Step        string
	Err         string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// stepsFor returns the step order of a saga. Install has no old version to
// stop; rollback starts from an already installed version and only arms it.
func stepsFor(mode sagaMode, strategy Strategy) []step {
	switch mode {
	case modeInstall:
		return []step{stepInstall, stepStart, stepSwap, stepActivateNew, stepCommit}
	case modeRollback:
		if strategy == StrategyRestart {
			return []step{stepArm, stepStopOld, stepStart, stepSwap, stepActivateNew, stepReleaseOld, stepCommit}
		}
		return []step{stepArm, stepStart, stepSwap, stepDeactivateOld, stepActivateNew, stepDrainOld, stepReleaseOld, stepCommit}
	default:
		if strategy == StrategyRestart {
			return []step{stepInstall, stepStopOld, stepStart, stepSwap, stepActivateNew, stepReleaseOld, stepCommit}
		}
		return []step{stepInstall, stepStart, stepSwap, stepDeactivateOld, stepActivateNew, stepDrainOld, stepReleaseOld, stepCommit}
	}
}

func indexOfStep(steps []step, s step) int {
	for i := range steps {
		if steps[i] == s {
			return i
		}
	}
	return -1
}

func hasStep(steps []step, s step) bool { return indexOfStep(steps, s) >= 0 }

func nextStep(steps []step, cur step) (step, bool) {
	for i := range steps {
		if steps[i] == cur && i+1 < len(steps) {
			return steps[i+1], true
		}
	}
	return "", false
}

// plan is everything one saga execution needs. The staged package is only
// present for a fresh install or update, never for rollback or recovery.
type plan struct {
	saga      *saga
	steps     []step
	strategy  Strategy
	old       *Version
	candidate *Version
	staged    *Staged
}

// testCrashHook lets the tests kill a saga in the window between an external
// action and the transaction that records it. It is nil in production.
var testCrashHook func(step string)

// runSaga executes the plan from the recorded step until the saga reaches a
// terminal state. A step error asks abort to roll the plan back; an error from
// abort itself is returned together with the original cause.
func (u *Updater) runSaga(ctx context.Context, p *plan) error {
	for {
		cur := step(p.saga.Step)
		if cur == stepCommitted {
			if p.saga.State == SagaRunning {
				return u.finalizeCommittedSaga(ctx, p.saga)
			}
			return nil
		}
		if !hasStep(p.steps, cur) {
			return problem.New(problem.StateConflict,
				"The update saga for plugin %s is at unknown step %q.", p.saga.PluginID, p.saga.Step)
		}
		before := p.saga.Step
		if err := u.runStep(ctx, p, cur); err != nil {
			u.log.WarnContext(ctx, "plugin saga step failed", "plugin", p.saga.PluginID,
				"saga", p.saga.ID, "step", cur, "err", err)
			if aerr := u.abort(ctx, p, cur, err); aerr != nil {
				return aerr
			}
			return err
		}
		if p.saga.State != SagaRunning {
			return nil
		}
		if p.saga.Step == before {
			return problem.New(problem.Internal, "The update saga for plugin %s did not advance.", p.saga.PluginID)
		}
	}
}

func (u *Updater) runStep(ctx context.Context, p *plan, s step) error {
	switch s {
	case stepInstall:
		return u.stepInstall(ctx, p)
	case stepArm:
		return u.stepArm(ctx, p)
	case stepStopOld:
		return u.stepStopOld(ctx, p)
	case stepStart:
		return u.stepStart(ctx, p)
	case stepSwap:
		return u.stepSwap(ctx, p)
	case stepDeactivateOld:
		return u.stepDeactivateOld(ctx, p)
	case stepActivateNew:
		return u.stepActivateNew(ctx, p)
	case stepDrainOld:
		return u.stepDrainOld(ctx, p)
	case stepReleaseOld:
		return u.stepReleaseOld(ctx, p)
	case stepCommit:
		return u.stepCommit(ctx, p)
	}
	return problem.New(problem.Internal, "The update saga reached an unknown step %q.", s)
}

// advance records the completion of one step in a short transaction: the
// caller's extra status writes, the next step, and the step audit event. It
// never calls the runtime. testCrashHook fires before the transaction, which
// is the window a kill opens.
func (u *Updater) advance(ctx context.Context, p *plan, next step, extra func(*storage.Tx) error) error {
	cur := p.saga.Step
	if testCrashHook != nil {
		testCrashHook(cur)
	}
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		if extra != nil {
			if err := extra(tx); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `UPDATE plugin_update_sagas SET step = ?, updated_at = ?
			WHERE saga_id = ? AND state = ?`, string(next), storage.FormatTime(tx.Now()), p.saga.ID, SagaRunning)
		if err != nil {
			return err
		}
		if err := requireOneRow(res); err != nil {
			return problem.New(problem.StateConflict, "The update saga for plugin %s is no longer running.", p.saga.PluginID)
		}
		return u.recordStepEventTx(ctx, tx, p.saga, cur, string(next), "")
	})
	if err != nil {
		return err
	}
	p.saga.Step = string(next)
	p.saga.UpdatedAt = u.clock.Now().UTC().Truncate(time.Millisecond)
	return nil
}

// stepInstall publishes the staged package and its unit. The version is
// STARTING afterwards so a crash during the next step is distinguishable from
// a crash before the package existed.
func (u *Updater) stepInstall(ctx context.Context, p *plan) error {
	v, err := u.loadVersion(ctx, p.saga.PluginID, p.saga.ToVersion)
	if err != nil {
		return problem.Wrap(err)
	}
	next, ok := nextStep(p.steps, stepInstall)
	if !ok {
		return problem.New(problem.Internal, "The update saga has no step after install.")
	}
	if v.InstallStatus == InstallInstalled && v.Status == VersionStarting {
		return u.advance(ctx, p, next, nil)
	}
	if p.staged == nil {
		return problem.New(problem.StateConflict,
			"The staged package of %s %s is no longer available; the interrupted install cannot be resumed.",
			p.saga.PluginID, p.saga.ToVersion)
	}
	if err := u.install.InstallUnit(ctx, *p.staged); err != nil {
		return &problem.Error{
			Code:   problem.Internal,
			Detail: fmt.Sprintf("The package of plugin %s version %s could not be installed.", p.saga.PluginID, p.saga.ToVersion),
			Cause:  err,
		}
	}
	return u.advance(ctx, p, next, func(tx *storage.Tx) error {
		if err := u.setInstallStatusTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion, InstallInstalled); err != nil {
			return err
		}
		return u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion, VersionStarting)
	})
}

// stepArm moves a retained version from STOPPED/ROLLED_BACK back to STARTING
// before a rollback starts it.
func (u *Updater) stepArm(ctx context.Context, p *plan) error {
	next, ok := nextStep(p.steps, stepArm)
	if !ok {
		return problem.New(problem.Internal, "The update saga has no step after arm.")
	}
	// The unit name is per plugin, not per version: point it back at the
	// retained version before the runtime starts it. Without this the rollback
	// starts the unit definition of the version it is rolling back from.
	if p.candidate == nil || p.candidate.Manifest == nil {
		return problem.New(problem.Internal, "The rollback target has no manifest.")
	}
	if err := u.install.ReinstallUnit(ctx, p.saga.PluginID, p.saga.ToVersion, p.candidate.Manifest); err != nil {
		return err
	}
	return u.advance(ctx, p, next, func(tx *storage.Tx) error {
		return u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion, VersionStarting)
	})
}

// stepStart attaches to or starts the candidate, waits for readiness and
// records CANDIDATE. Restarting here never duplicates background work: the
// candidate has not been activated yet.
func (u *Updater) stepStart(ctx context.Context, p *plan) error {
	next, ok := nextStep(p.steps, stepStart)
	if !ok {
		return problem.New(problem.Internal, "The update saga has no step after start.")
	}
	h, err := u.ensureCandidate(ctx, p)
	if err != nil {
		return err
	}
	if err := u.rt.Ready(ctx, h); err != nil {
		return runtimeFailure("become ready", p.saga.PluginID, p.saga.ToVersion, err)
	}
	return u.advance(ctx, p, next, func(tx *storage.Tx) error {
		return u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion, VersionCandidate)
	})
}

// stepStopOld stops the old version before the candidate starts (restart
// strategy). The old row stays active in the database until commit; its
// lifecycle becomes STOPPED.
func (u *Updater) stepStopOld(ctx context.Context, p *plan) error {
	if p.old != nil {
		if h, ok := u.existingHandle(ctx, p.saga.PluginID, p.old); ok {
			if err := u.rt.Stop(ctx, h, u.opts.StopGrace); err != nil {
				return runtimeFailure("stop", p.saga.PluginID, p.old.Version, err)
			}
		}
	}
	return u.advance(ctx, p, stepStart, func(tx *storage.Tx) error {
		if p.old == nil {
			return nil
		}
		cur, err := loadVersionTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion)
		if err != nil {
			return err
		}
		switch cur.Status {
		case VersionActive:
			if err := u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion, VersionDraining); err != nil {
				return err
			}
			return u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion, VersionStopped)
		case VersionDraining:
			return u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion, VersionStopped)
		case VersionStopped:
			return nil
		default:
			return versionStatusProblem(p.saga.PluginID, p.saga.FromVersion, cur.Status, VersionStopped)
		}
	})
}

// stepSwap publishes the new route table and records the old version as
// draining. It is the point of no return: recovery continues forward after it.
func (u *Updater) stepSwap(ctx context.Context, p *plan) error {
	u.swapRoute(p.saga.PluginID, p.saga.ToVersion)
	next, ok := nextStep(p.steps, stepSwap)
	if !ok {
		return problem.New(problem.Internal, "The update saga has no step after swap.")
	}
	return u.advance(ctx, p, next, func(tx *storage.Tx) error {
		if p.old == nil {
			return nil
		}
		cur, err := loadVersionTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion)
		if err != nil {
			return err
		}
		if cur.Status != VersionActive {
			return nil
		}
		return u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion, VersionDraining)
	})
}

// stepDeactivateOld stops the old version's background work before the
// candidate activates, so timers and subscriptions never run twice.
func (u *Updater) stepDeactivateOld(ctx context.Context, p *plan) error {
	if p.old != nil {
		if h, ok := u.existingHandle(ctx, p.saga.PluginID, p.old); ok {
			if err := u.rt.Deactivate(ctx, h); err != nil {
				return runtimeFailure("deactivate", p.saga.PluginID, p.old.Version, err)
			}
		}
	}
	return u.advance(ctx, p, stepActivateNew, nil)
}

// stepActivateNew activates the candidate background work and checks health.
// Activate is idempotent, so recovery may repeat this step without running
// background work twice.
func (u *Updater) stepActivateNew(ctx context.Context, p *plan) error {
	next, ok := nextStep(p.steps, stepActivateNew)
	if !ok {
		return problem.New(problem.Internal, "The update saga has no step after activation.")
	}
	h, err := u.ensureCandidate(ctx, p)
	if err != nil {
		return err
	}
	if err := u.rt.Activate(ctx, h); err != nil {
		return runtimeFailure("activate", p.saga.PluginID, p.saga.ToVersion, err)
	}
	if err := u.rt.Health(ctx, h); err != nil {
		return runtimeFailure("pass its health check", p.saga.PluginID, p.saga.ToVersion, err)
	}
	return u.advance(ctx, p, next, nil)
}

// stepDrainOld waits for the old version to drain and stops it.
func (u *Updater) stepDrainOld(ctx context.Context, p *plan) error {
	if p.old != nil {
		if h, ok := u.existingHandle(ctx, p.saga.PluginID, p.old); ok {
			if err := u.rt.Stop(ctx, h, u.opts.StopGrace); err != nil {
				return runtimeFailure("drain", p.saga.PluginID, p.old.Version, err)
			}
		}
	}
	return u.advance(ctx, p, stepReleaseOld, func(tx *storage.Tx) error {
		if p.old == nil {
			return nil
		}
		cur, err := loadVersionTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion)
		if err != nil {
			return err
		}
		switch cur.Status {
		case VersionDraining:
			return u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion, VersionStopped)
		case VersionActive:
			if err := u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion, VersionDraining); err != nil {
				return err
			}
			return u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.FromVersion, VersionStopped)
		case VersionStopped:
			return nil
		default:
			return versionStatusProblem(p.saga.PluginID, p.saga.FromVersion, cur.Status, VersionStopped)
		}
	})
}

// stepReleaseOld frees the host-side resources of the stopped old version.
func (u *Updater) stepReleaseOld(ctx context.Context, p *plan) error {
	if p.old != nil {
		if h, ok := u.existingHandle(ctx, p.saga.PluginID, p.old); ok {
			if err := u.rt.Release(ctx, h); err != nil {
				return runtimeFailure("release", p.saga.PluginID, p.old.Version, err)
			}
			u.dropHandle(p.saga.PluginID, p.old.Version)
		}
	}
	return u.advance(ctx, p, stepCommit, nil)
}

// stepCommit publishes the new version as the committed active version.
func (u *Updater) stepCommit(ctx context.Context, p *plan) error {
	if testCrashHook != nil {
		testCrashHook(string(stepCommit))
	}
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		if err := u.finishCredentialRotationTx(ctx, tx, p.saga.PluginID); err != nil {
			return err
		}
		if _, _, err := u.clearActiveTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion); err != nil {
			return err
		}
		if err := u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion, VersionActive); err != nil {
			return err
		}
		if err := u.setVersionActiveTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion, true); err != nil {
			return err
		}
		if err := u.setVersionActivatedAtTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion, tx.Now()); err != nil {
			return err
		}
		if p.saga.Mode == modeInstall {
			if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_states (plugin_id, enabled, updated_at, revision)
				VALUES (?, 1, ?, 1)
				ON CONFLICT (plugin_id) DO UPDATE SET enabled = 1, updated_at = excluded.updated_at, revision = plugin_states.revision + 1`,
				p.saga.PluginID, storage.FormatTime(tx.Now())); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `UPDATE plugin_update_sagas SET state = ?, step = ?, error = '', updated_at = ?
			WHERE saga_id = ? AND state = ?`, SagaCommitted, string(stepCommitted),
			storage.FormatTime(tx.Now()), p.saga.ID, SagaRunning)
		if err != nil {
			return err
		}
		if err := requireOneRow(res); err != nil {
			return problem.New(problem.StateConflict, "The update saga for plugin %s is no longer running.", p.saga.PluginID)
		}
		if err := u.recordStepEventTx(ctx, tx, p.saga, string(stepCommit), string(stepCommitted), ""); err != nil {
			return err
		}
		return u.appendEventTx(ctx, tx, sagaEventName(p.saga.Mode, "committed"), "plugins/"+p.saga.PluginID, p.saga.ID,
			stepEvent{
				SagaID:      p.saga.ID,
				PluginID:    p.saga.PluginID,
				Mode:        string(p.saga.Mode),
				Strategy:    string(p.saga.Strategy),
				Step:        string(stepCommit),
				FromVersion: p.saga.FromVersion,
				ToVersion:   p.saga.ToVersion,
			})
	})
	if err != nil {
		return err
	}
	p.saga.State = SagaCommitted
	p.saga.Step = string(stepCommitted)
	p.saga.Err = ""
	if v, lerr := u.loadVersion(ctx, p.saga.PluginID, p.saga.ToVersion); lerr == nil {
		u.setActiveVersion(v)
	}
	return nil
}

// abort undoes a failed saga as far as it can, then records the terminal
// state. It returns nil when the rollback and the terminal write both
// succeeded; runSaga then reports the original step error. A non-nil result
// means the plan could not be made safe and the combined failure is returned.
func (u *Updater) abort(ctx context.Context, p *plan, failed step, cause error) error {
	// The rollback and the terminal record must happen even when the caller's
	// context is what failed the step; they get their own bounded context.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abortTimeout)
	defer cancel()
	if u.credentialLifecycle() != nil {
		if err := u.recordCredentialAbort(actx, p, failed, cause); err != nil {
			return problem.Wrap(errors.Join(cause, err))
		}
	}
	rbErr := u.rollbackRuntime(actx, p, failed)
	state := SagaRolledBack
	if p.saga.Mode == modeInstall || rbErr != nil || (u.credentialLifecycle() != nil && p.old == nil) {
		state = SagaFailed
	}
	finalErr := u.finalizeSaga(actx, p, state, failed, errors.Join(cause, rbErr))
	if rbErr != nil {
		u.log.ErrorContext(ctx, "plugin saga rollback failed", "plugin", p.saga.PluginID,
			"saga", p.saga.ID, "step", failed, "err", rbErr)
	}
	if finalErr != nil {
		u.log.ErrorContext(ctx, "plugin saga terminal state could not be recorded", "plugin", p.saga.PluginID,
			"saga", p.saga.ID, "err", finalErr)
		return problem.Wrap(errors.Join(cause, rbErr, finalErr))
	}
	if rbErr != nil {
		return problem.Wrap(errors.Join(cause, rbErr))
	}
	return nil
}

// rollbackRuntime discards the candidate and then restores the old version. It
// is best effort: every step is collected so the caller can report all problems.
func (u *Updater) rollbackRuntime(ctx context.Context, p *plan, failed step) error {
	var errs []error
	if p.saga.Mode == modeInstall {
		errs = append(errs, u.cleanupInstance(ctx, p.saga.PluginID, p.saga.ToVersion))
		if err := u.install.RemoveUnit(ctx, p.saga.PluginID, p.saga.ToVersion); err != nil {
			errs = append(errs, fmt.Errorf("remove unit: %w", err))
		}
		return errors.Join(errs...)
	}

	swap := indexOfStep(p.steps, stepSwap)
	postSwap := swap >= 0 && indexOfStep(p.steps, failed) >= swap
	restart := p.strategy == StrategyRestart
	credentials := u.credentialLifecycle() != nil

	if postSwap {
		// Stop the new background work before the old version takes over.
		if h := u.handle(p.saga.PluginID, p.saga.ToVersion); h != nil {
			if err := u.rt.Deactivate(ctx, h); err != nil {
				errs = append(errs, fmt.Errorf("deactivate candidate: %w", err))
			}
		}
	}
	// 先清理候选、再恢复旧版：单 unit 布局下两者共用一个进程槽位，
	// 先恢复旧版会让随后的候选清理附着到刚恢复的旧进程并把它停掉。
	cleanupErr := u.cleanupInstance(ctx, p.saga.PluginID, p.saga.ToVersion)
	errs = append(errs, cleanupErr)
	if credentials && cleanupErr != nil {
		// 候选是否已停止不确定时，不得让同一 unit 槽位开始恢复旧进程。
		return errors.Join(errs...)
	}
	if (restart || postSwap || credentials) && p.old != nil {
		if err := u.restoreOld(ctx, p); err != nil {
			errs = append(errs, fmt.Errorf("restore old version: %w", err))
		}
	}
	return errors.Join(errs...)
}

// restoreOld brings the old version back: start it if the restart strategy
// stopped it, make it ready, point routes at it and activate it again.
func (u *Updater) restoreOld(ctx context.Context, p *plan) error {
	if p.old == nil {
		return nil
	}
	// A failed update already rewrote the per-plugin unit to the candidate;
	// restore the old definition before starting the old version again.
	if p.old.Manifest == nil {
		return problem.New(problem.Internal, "The retained version has no manifest.")
	}
	if u.credentialLifecycle() != nil {
		// 新凭据不能交给仍持原 token 的健康 handle；先确认停机并释放，
		// 再重装/启动到当前文件。失败发生在 stop_old 前也不能省略此步骤。
		if h, ok := u.existingHandle(ctx, p.saga.PluginID, p.old); ok {
			if err := u.rt.Stop(ctx, h, u.opts.StopGrace); err != nil {
				return fmt.Errorf("stop old credential generation: %w", err)
			}
			if err := u.rt.Release(ctx, h); err != nil {
				return fmt.Errorf("release old credential generation: %w", err)
			}
			u.dropHandle(p.saga.PluginID, p.old.Version)
		}
	}
	if err := u.install.ReinstallUnit(ctx, p.saga.PluginID, p.old.Version, p.old.Manifest); err != nil {
		return err
	}
	h, err := u.readyHandle(ctx, u.specFor(p.saga.PluginID, *p.old))
	if err != nil {
		return err
	}
	u.swapRoute(p.saga.PluginID, p.old.Version)
	if err := u.rt.Activate(ctx, h); err != nil {
		return fmt.Errorf("activate: %w", err)
	}
	return nil
}

// readyHandle returns a ready instance of spec, starting it when none runs. A
// cached handle can point at a process that is gone (the restart strategy
// stopped it, or it crashed); it is dropped and the version started again.
func (u *Updater) readyHandle(ctx context.Context, spec InstanceSpec) (Handle, error) {
	h, ok, err := u.ensureHandle(ctx, spec, true)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("the instance is not available")
	}
	rerr := u.rt.Ready(ctx, h)
	if rerr == nil {
		return h, nil
	}
	u.dropHandle(spec.PluginID, spec.Version)
	h, ok, err = u.ensureHandle(ctx, spec, true)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("ready: %w", rerr)
	}
	if err := u.rt.Ready(ctx, h); err != nil {
		return nil, fmt.Errorf("ready: %w", err)
	}
	return h, nil
}

// cleanupInstance stops and releases the instance of a version, if any. When
// the handle was lost in a crash it attaches to a process that is still
// running, so a candidate is never leaked by recovery. Attach refuses a
// process of another version (Runtime contract), so the fallback never stops
// a version it was not asked to clean up.
func (u *Updater) cleanupInstance(ctx context.Context, pluginID, version string) error {
	h := u.handle(pluginID, version)
	if h == nil {
		if v, err := u.loadVersion(ctx, pluginID, version); err == nil {
			if ah, ok, _ := u.ensureHandle(ctx, u.specFor(pluginID, v), false); ok {
				h = ah
			}
		}
	}
	if h == nil {
		return nil
	}
	var errs []error
	if err := u.rt.Stop(ctx, h, u.opts.StopGrace); err != nil {
		errs = append(errs, fmt.Errorf("stop: %w", err))
	}
	if err := u.rt.Release(ctx, h); err != nil {
		errs = append(errs, fmt.Errorf("release: %w", err))
	}
	u.dropHandle(pluginID, version)
	return errors.Join(errs...)
}

// finalizeSaga writes the terminal state of a failed saga and the status of
// the versions it touched. It never calls the runtime.
func (u *Updater) finalizeSaga(ctx context.Context, p *plan, state SagaState, failed step, cause error) error {
	reason := problemDetail(cause)
	candidateStatus := VersionRolledBack
	if p.saga.Mode == modeInstall {
		candidateStatus = VersionRejected
	}
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		if p.candidate != nil {
			cur, err := loadVersionTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion)
			switch {
			case errors.Is(err, errNoVersion):
				// The version row disappeared; nothing left to annotate.
			case err != nil:
				return err
			default:
				if !isTerminal(cur.Status) {
					if cerr := u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion, candidateStatus); cerr != nil {
						return cerr
					}
				}
				if err := u.setVersionRejectedReasonTx(ctx, tx, p.saga.PluginID, p.saga.ToVersion, reason); err != nil {
					return err
				}
			}
		}
		if state == SagaRolledBack && p.old != nil {
			if err := u.finishCredentialRotationTx(ctx, tx, p.saga.PluginID); err != nil {
				return err
			}
			if err := u.setVersionStatusTx(ctx, tx, p.saga.PluginID, p.old.Version, VersionActive); err != nil {
				return err
			}
			if err := u.setVersionActiveTx(ctx, tx, p.saga.PluginID, p.old.Version, true); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `UPDATE plugin_update_sagas SET state = ?, step = ?, error = ?, updated_at = ?
			WHERE saga_id = ? AND state = ?`, state, string(failed), sagaErrorText(cause),
			storage.FormatTime(tx.Now()), p.saga.ID, SagaRunning)
		if err != nil {
			return err
		}
		if err := requireOneRow(res); err != nil {
			return problem.New(problem.StateConflict, "The update saga for plugin %s is no longer running.", p.saga.PluginID)
		}
		outcome := "rolled_back"
		if state == SagaFailed {
			outcome = "failed"
		}
		if err := u.recordStepEventTx(ctx, tx, p.saga, string(failed), "", reason); err != nil {
			return err
		}
		return u.appendEventTx(ctx, tx, sagaEventName(p.saga.Mode, outcome), "plugins/"+p.saga.PluginID, p.saga.ID,
			stepEvent{
				SagaID:      p.saga.ID,
				PluginID:    p.saga.PluginID,
				Mode:        string(p.saga.Mode),
				Strategy:    string(p.saga.Strategy),
				Step:        string(failed),
				FromVersion: p.saga.FromVersion,
				ToVersion:   p.saga.ToVersion,
				Error:       reason,
			})
	})
	if err != nil {
		return err
	}
	p.saga.State = state
	p.saga.Err = reason
	return nil
}

// isTerminal reports whether a version status has no outgoing saga transition
// that finalizeSaga needs to apply.
func isTerminal(s VersionStatus) bool {
	switch s {
	case VersionRejected, VersionRolledBack, VersionStopped:
		return true
	}
	return false
}

// runtimeFailure maps a runtime error to a problem, preserving a field-level
// problem returned by the plugin.
func runtimeFailure(action, pluginID, version string, err error) error {
	var pe *problem.Error
	if errors.As(err, &pe) {
		return pe
	}
	return &problem.Error{
		Code:   problem.PluginUnavailable,
		Detail: fmt.Sprintf("The plugin %s version %s could not %s.", pluginID, version, action),
		Cause:  err,
	}
}

// ensureCandidate returns a live handle for the candidate, attaching first
// and starting only when no process is running.
func (u *Updater) ensureCandidate(ctx context.Context, p *plan) (Handle, error) {
	spec := u.specFor(p.saga.PluginID, *p.candidate)
	h, ok, err := u.ensureHandle(ctx, spec, true)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, problem.New(problem.PluginUnavailable, "The candidate instance of plugin %s is not available.", p.saga.PluginID)
	}
	return h, nil
}

// existingHandle returns the cached or attached handle of v for cleanup. A
// missing process is not an error: the action it was needed for is already
// satisfied.
func (u *Updater) existingHandle(ctx context.Context, pluginID string, v *Version) (Handle, bool) {
	if v == nil {
		return nil, false
	}
	h, ok, err := u.ensureHandle(ctx, u.specFor(pluginID, *v), false)
	if err != nil {
		u.log.DebugContext(ctx, "cleanup handle unavailable", "plugin", pluginID, "version", v.Version, "err", err)
		return nil, false
	}
	return h, ok
}

// setActiveVersion updates the in-memory committed active version.
func (u *Updater) setActiveVersion(v Version) {
	u.activeMu.Lock()
	defer u.activeMu.Unlock()
	u.active[v.PluginID] = v
}
