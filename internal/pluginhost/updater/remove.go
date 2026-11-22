// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"sort"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// RemoveRequest is one uninstall (GAPS gap 7).
type RemoveRequest struct {
	PluginID string
	// PurgeData 清理本插件的配置、凭据、启停位、秘密与持久数据。
	// 默认保留这些数据，便于后续重装（ARCH §6.6）。
	PurgeData bool
	Timeout   time.Duration
}

// Dependents lists the plugins whose active manifest declares a dependency on
// pluginID. The uninstall route refuses with STATE_CONFLICT while any exists,
// so a plugin cannot be pulled out from under another one.
func (u *Updater) Dependents(pluginID string) ([]string, error) {
	versions, err := u.AllVersions()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range versions {
		if !v.Active || v.PluginID == pluginID || v.Manifest == nil {
			continue
		}
		for _, d := range v.Manifest.Dependencies {
			if d.Kind == "plugin" && d.ID == pluginID {
				out = append(out, v.PluginID)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Remove uninstalls a plugin as a sequence of idempotent steps, not a saga:
//
//  1. stop and release every instance of every recorded version;
//  2. ask the privileged helper to remove the unit artifacts and the version
//     trees (it refuses while the unit still has a main PID, and it is
//     idempotent, so a retry after a crash continues where it stopped);
//  3. delete the version rows in one short transaction, with a delete event per
//     version and one for the plugin, plus the data when PurgeData is set;
//  4. drop the caches and republish the route table.
//
// A crash between any two steps leaves the earlier ones done and the later ones
// pending; running Remove again finishes the job. Nothing here writes
// plugin_update_sagas: the uninstall has no candidate to roll back to.
func (u *Updater) Remove(ctx context.Context, req RemoveRequest) error {
	if err := checkPluginID(req.PluginID); err != nil {
		return err
	}
	ctx, cancel := u.withTimeout(ctx, req.Timeout)
	defer cancel()
	unlock := u.locks.lock(req.PluginID)
	defer unlock()
	if err := u.requireNoRunningSaga(ctx, req.PluginID); err != nil {
		return err
	}
	versions, err := u.listVersions(ctx, req.PluginID)
	if err != nil {
		return err
	}
	for _, v := range versions {
		if err := u.cleanupInstance(ctx, req.PluginID, v.Version); err != nil {
			return err
		}
	}
	for _, v := range versions {
		if err := u.install.RemoveUnit(ctx, req.PluginID, v.Version); err != nil {
			return err
		}
	}
	// ========================================================================
	// 文件失败不吞错，也不先删引用行；重启重试无需依赖仍存在的版本行。
	// ========================================================================
	if req.PurgeData {
		if err := u.install.PurgeData(ctx, req.PluginID); err != nil {
			return err
		}
	}
	err = u.db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: actor.SystemActor("updater")})
		for _, v := range versions {
			if err := deleteVersionTx(ctx, tx, req.PluginID, v.Version); err != nil {
				return err
			}
		}
		if req.PurgeData {
			if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_states WHERE plugin_id = ?`, req.PluginID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_configs WHERE plugin_id = ?`, req.PluginID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_credentials WHERE plugin_id = ?`, req.PluginID); err != nil {
				return err
			}
			if _, err := secrets.DeleteOwner(ctx, tx, "plugins/"+req.PluginID); err != nil {
				return err
			}
		}
		_, err := tx.Changed(ctx, storage.Change{Subject: "plugins/" + req.PluginID, Kind: storage.Deleted})
		return err
	})
	if err != nil {
		return problem.From(err)
	}
	u.activeMu.Lock()
	delete(u.active, req.PluginID)
	u.activeMu.Unlock()
	u.configMu.Lock()
	delete(u.configs, req.PluginID)
	u.configMu.Unlock()
	u.publishActiveRoutes()
	u.log.InfoContext(ctx, "plugin uninstalled", "plugin_id", req.PluginID,
		"versions", len(versions), "purge_data", req.PurgeData)
	return nil
}
