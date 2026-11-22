// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"database/sql"
	"errors"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Enabled reports whether the plugin may run. A plugin without a state row is
// enabled, so an installation that predates migration 0015 keeps running.
func (u *Updater) Enabled(ctx context.Context, pluginID string) (bool, error) {
	var enabled int
	err := u.db.Reader().QueryRowContext(ctx,
		`SELECT enabled FROM plugin_states WHERE plugin_id = ?`, pluginID).Scan(&enabled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return true, nil
	case err != nil:
		return false, problem.Wrap(err)
	}
	return enabled == 1, nil
}

// SetEnabled persists the flag and makes the runtime agree with it (GAPS gap 7):
// disabling stops every instance of the plugin, enabling restores the active
// version. The flag survives a host restart because EnsureActive refuses to
// start a disabled plugin, and every unit start goes through EnsureActive.
func (u *Updater) SetEnabled(ctx context.Context, pluginID string, enabled bool) error {
	if err := checkPluginID(pluginID); err != nil {
		return err
	}
	ctx, cancel := u.withTimeout(ctx, 0)
	defer cancel()
	if err := u.writeEnabled(ctx, pluginID, enabled); err != nil {
		return err
	}
	if enabled {
		// EnsureActive takes the plugin lock itself.
		return u.EnsureActive(ctx, pluginID)
	}
	unlock := u.locks.lock(pluginID)
	defer unlock()
	versions, err := u.listVersions(ctx, pluginID)
	if err != nil {
		return err
	}
	for _, v := range versions {
		if err := u.cleanupInstance(ctx, pluginID, v.Version); err != nil {
			return err
		}
	}
	return nil
}

// writeEnabled upserts the flag in one short transaction with its event.
func (u *Updater) writeEnabled(ctx context.Context, pluginID string, enabled bool) error {
	return u.db.Update(ctx, func(tx *storage.Tx) error {
		// 活动缓存在卸载提交后才清理；同 Tx 读取真实版本，避免并发启停
		// 越过已完成的 purge 再写回残留启停位。
		_, active, err := loadActiveVersionTx(ctx, tx, pluginID)
		if err != nil {
			return problem.Wrap(err)
		}
		if !active {
			return problem.New(problem.NotFound, "Plugin %s has no active version.", pluginID)
		}
		tx.SetOrigin(storage.Origin{Actor: actor.SystemActor("updater")})
		seq, err := tx.Changed(ctx, storage.Change{
			Subject: "plugins/" + pluginID, Kind: storage.Updated, Pointers: []string{"/enabled"},
		})
		if err != nil {
			return err
		}
		value := 0
		if enabled {
			value = 1
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO plugin_states (plugin_id, enabled, updated_at, revision)
			VALUES (?, ?, ?, ?)
			ON CONFLICT (plugin_id) DO UPDATE SET enabled = excluded.enabled,
				updated_at = excluded.updated_at, revision = excluded.revision`,
			pluginID, value, storage.FormatTime(tx.Now()), seq)
		return err
	})
}
