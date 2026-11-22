// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"errors"
	"fmt"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Recover resolves every unfinished saga and republishes the route table. It
// is the host's startup step after a crash or restart and is safe to call
// repeatedly: a second call finds no RUNNING saga and only republishes the
// active routes.
//
// Overlap sagas that had not switched routes yet are rolled back: the old
// version is still authoritative and the candidate must not be adopted. Every
// other saga continues forward from its recorded step, because its external
// effects may already be visible. A failed forward step falls back to the same
// rollback path a live update would use.
func (u *Updater) Recover(ctx context.Context) ([]string, error) {
	if err := u.loadState(ctx); err != nil {
		return nil, problem.Wrap(err)
	}
	sagas, err := u.runningSagas(ctx)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	recovered := make([]string, 0, len(sagas))
	var errs []error
	for i := range sagas {
		s := sagas[i]
		unlock := u.locks.lock(s.PluginID)
		rerr := u.recoverSaga(ctx, &s)
		unlock()
		recovered = append(recovered, s.ID)
		if rerr != nil {
			u.log.ErrorContext(ctx, "plugin saga recovery failed", "plugin", s.PluginID, "saga", s.ID, "err", rerr)
			errs = append(errs, fmt.Errorf("saga %s: %w", s.ID, rerr))
		}
	}
	u.publishActiveRoutes()
	return recovered, errors.Join(errs...)
}

// ---------------------------------------------------------------------------
// 恢复期望状态（ARCH §12 第 3 步）：ACTIVE 版本必须有一个已 Initialize/Start/
// Activate 的实例。updater 是唯一负责"启动 + ABI bootstrap"的一方，持插件锁与
// saga 互斥；supervisor 只附着（见 controller.attachOnlyUnits）。
// ---------------------------------------------------------------------------

// EnsureActive makes sure the ACTIVE version of pluginID runs a ready, active
// instance: after a host reboot or a crash systemd restarts the process, but
// nothing initializes it. It holds the plugin's lock, so it waits for a saga
// in progress instead of racing it for the unit. A plugin without an ACTIVE
// version is NOT_FOUND.
func (u *Updater) EnsureActive(ctx context.Context, pluginID string) error {
	unlock := u.locks.lock(pluginID)
	defer unlock()
	v, ok := u.Active(pluginID)
	if !ok {
		return problem.New(problem.NotFound, "Plugin %s has no active version.", pluginID)
	}
	// A disabled plugin is never started, whatever asks for it: this is the
	// single place a unit is started, so the persistent flag holds across a
	// host restart, a dispatch and a rollback (GAPS gap 7).
	enabled, err := u.Enabled(ctx, pluginID)
	if err != nil {
		return err
	}
	if !enabled {
		return problem.New(problem.PluginUnavailable, "Plugin %s is disabled.", pluginID)
	}
	h, err := u.readyHandle(ctx, u.specFor(pluginID, v))
	if err == nil {
		// Activate is idempotent (Runtime contract), so a healthy instance
		// costs one Ready and one no-op Activate.
		err = u.rt.Activate(ctx, h)
	}
	if err != nil {
		return &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("Plugin %s version %s could not be restored.", pluginID, v.Version),
			Cause:  err,
		}
	}
	return nil
}

// recoverSaga drives one unfinished saga to a terminal state.
func (u *Updater) recoverSaga(ctx context.Context, s *saga) error {
	if s.State != SagaRunning {
		return nil
	}
	p, err := u.planFor(ctx, s)
	if err != nil {
		return u.markSagaFailed(ctx, s, err)
	}
	cur := step(s.Step)
	if failed, compensation := credentialAbortStep(s.Step); compensation {
		return u.abort(ctx, p, failed, problem.New(problem.Unavailable, "%s", s.Err))
	}
	if cur == stepCommitted {
		return u.finalizeCommittedSaga(ctx, s)
	}
	if (s.Mode == modeUpdate || s.Mode == modeRollback) && s.Strategy == StrategyOverlap {
		swap := indexOfStep(p.steps, stepSwap)
		idx := indexOfStep(p.steps, cur)
		if idx >= 0 && idx < swap {
			cause := problem.New(problem.Unavailable,
				"The host stopped before the route switch; the update of plugin %s is being rolled back.", s.PluginID)
			return u.abort(ctx, p, cur, cause)
		}
	}
	if err := u.runSaga(ctx, p); err != nil {
		// A step failure that abort already recorded as a terminal state is a
		// resolved saga, not a recovery failure; the row carries the reason.
		if p.saga.State == SagaRunning {
			return err
		}
		u.log.WarnContext(ctx, "saga ended in a non-committed terminal state",
			"plugin", s.PluginID, "saga", s.ID, "state", p.saga.State)
		return nil
	}
	return nil
}

// planFor rebuilds the plan of a persisted saga. The staged package is gone
// after a crash, so recovery can only resume from an installed version; the
// install step handles that case explicitly.
func (u *Updater) planFor(ctx context.Context, s *saga) (*plan, error) {
	steps := stepsFor(s.Mode, s.Strategy)
	cur := step(s.Step)
	failed, compensation := credentialAbortStep(s.Step)
	if (compensation && (u.credentialLifecycle() == nil || !hasStep(steps, failed))) || (!compensation && cur != stepCommitted && !hasStep(steps, cur)) {
		return nil, problem.New(problem.StateConflict,
			"The update saga for plugin %s is at unknown step %q.", s.PluginID, s.Step)
	}
	candidate, err := u.loadVersion(ctx, s.PluginID, s.ToVersion)
	if err != nil {
		return nil, fmt.Errorf("load candidate %s/%s: %w", s.PluginID, s.ToVersion, err)
	}
	p := &plan{
		saga:      s,
		steps:     steps,
		strategy:  s.Strategy,
		candidate: &candidate,
	}
	if s.FromVersion != "" {
		old, oerr := u.loadVersion(ctx, s.PluginID, s.FromVersion)
		switch {
		case errors.Is(oerr, errNoVersion):
			// The old row is gone; recovery can only continue forward.
		case oerr != nil:
			return nil, fmt.Errorf("load old version %s/%s: %w", s.PluginID, s.FromVersion, oerr)
		default:
			p.old = &old
		}
	}
	return p, nil
}

// markSagaFailed records a saga that cannot be resumed at all. The version
// rows are left as they are: without a plan there is nothing safe to undo.
func (u *Updater) markSagaFailed(ctx context.Context, s *saga, cause error) error {
	text := problemDetail(cause)
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE plugin_update_sagas SET state = ?, error = ?, updated_at = ?
			WHERE saga_id = ? AND state = ?`, SagaFailed, sagaErrorText(cause),
			storage.FormatTime(tx.Now()), s.ID, SagaRunning)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return nil // somebody else already finalized it
		}
		return u.appendEventTx(ctx, tx, sagaEventName(s.Mode, "failed"), "plugins/"+s.PluginID, s.ID, stepEvent{
			SagaID:      s.ID,
			PluginID:    s.PluginID,
			Mode:        string(s.Mode),
			Strategy:    string(s.Strategy),
			Step:        s.Step,
			FromVersion: s.FromVersion,
			ToVersion:   s.ToVersion,
			Error:       text,
		})
	})
	if err != nil {
		return problem.Wrap(err)
	}
	s.State = SagaFailed
	s.Err = text
	return problem.Wrap(cause)
}

// finalizeCommittedSaga closes a saga whose step is already "committed" but
// whose state was not written, which can only happen on a torn database edge.
func (u *Updater) finalizeCommittedSaga(ctx context.Context, s *saga) error {
	if u.credentialLifecycle() != nil {
		// 旧的 committed/仍 RUNNING 边缘记录不能单凭文字撤掉上一槽；
		// 先核实际候选版本 Ready/Activate/Health，再在终态事务收口。
		version, err := u.loadVersion(ctx, s.PluginID, s.ToVersion)
		if err != nil {
			return err
		}
		handle, err := u.readyHandle(ctx, u.specFor(s.PluginID, version))
		if err != nil {
			return err
		}
		if err := u.rt.Activate(ctx, handle); err != nil {
			return err
		}
		if err := u.rt.Health(ctx, handle); err != nil {
			return err
		}
	}
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		if err := u.finishCredentialRotationTx(ctx, tx, s.PluginID); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE plugin_update_sagas SET state = ?, updated_at = ?
			WHERE saga_id = ? AND state = ?`, SagaCommitted, storage.FormatTime(tx.Now()), s.ID, SagaRunning)
		if err != nil {
			return err
		}
		if err := requireOneRow(res); err != nil {
			return err
		}
		return u.appendEventTx(ctx, tx, sagaEventName(s.Mode, "committed"), "plugins/"+s.PluginID, s.ID, stepEvent{
			SagaID:      s.ID,
			PluginID:    s.PluginID,
			Mode:        string(s.Mode),
			Strategy:    string(s.Strategy),
			Step:        s.Step,
			FromVersion: s.FromVersion,
			ToVersion:   s.ToVersion,
		})
	})
	if err != nil {
		return problem.Wrap(err)
	}
	s.State = SagaCommitted
	if v, lerr := u.loadVersion(ctx, s.PluginID, s.ToVersion); lerr == nil && v.Active {
		u.setActiveVersion(v)
	}
	return nil
}
