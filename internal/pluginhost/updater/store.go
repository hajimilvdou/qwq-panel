// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Subjects of resource.changed events. The version and configuration rows are
// resources in the public subject space (ARCH §5.7, ADR-0004 D3).
func versionSubject(pluginID, version string) string {
	return "plugins/" + pluginID + "/versions/" + version
}

func configSubject(pluginID string, revision int64) string {
	return "plugins/" + pluginID + "/configs/" + fmt.Sprint(revision)
}

// digestOf derives a package digest from the signed manifest bytes. It is the
// fallback when the installer adapter does not provide a package digest.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// scanVersion scans one plugin_versions row, including the manifest JSON.
func scanVersion(sc interface{ Scan(...any) error }) (Version, error) {
	var (
		v            Version
		manifestJSON string
		installedAt  string
		activatedAt  string
		active       int
	)
	if err := sc.Scan(&v.PluginID, &v.Version, &v.Digest, &manifestJSON, &v.Status,
		&v.InstallStatus, &active, &installedAt, &activatedAt, &v.RejectedReason, &v.Revision); err != nil {
		return Version{}, err
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		return Version{}, fmt.Errorf("updater: version %s/%s has an unreadable manifest: %w", v.PluginID, v.Version, err)
	}
	v.Manifest = &m
	v.Active = active != 0
	t, err := storage.ParseTime(installedAt)
	if err != nil {
		return Version{}, err
	}
	v.InstalledAt = t
	if activatedAt != "" {
		if v.ActivatedAt, err = storage.ParseTime(activatedAt); err != nil {
			return Version{}, err
		}
	}
	return v, nil
}

const versionColumns = `plugin_id, version, digest, manifest_json, status, install_status,
	active, installed_at, activated_at, rejected_reason, revision`

// listVersions returns the versions of pluginID, or of every plugin when
// pluginID is empty, newest first.
func (u *Updater) listVersions(ctx context.Context, pluginID string) ([]Version, error) {
	var out []Version
	err := u.db.View(ctx, func(tx *sql.Tx) error {
		q := `SELECT ` + versionColumns + ` FROM plugin_versions`
		args := []any{}
		if pluginID != "" {
			q += ` WHERE plugin_id = ?`
			args = append(args, pluginID)
		}
		q += ` ORDER BY plugin_id, installed_at DESC, version DESC`
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanVersion(rows)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// loadVersion reads one version from the database.
func (u *Updater) loadVersion(ctx context.Context, pluginID, version string) (Version, error) {
	var out Version
	err := u.db.View(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+versionColumns+` FROM plugin_versions WHERE plugin_id = ? AND version = ?`,
			pluginID, version)
		v, err := scanVersion(row)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	if err != nil {
		return Version{}, err
	}
	return out, nil
}

// loadVersionTx reads one version inside a write transaction.
func loadVersionTx(ctx context.Context, tx *storage.Tx, pluginID, version string) (Version, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+versionColumns+` FROM plugin_versions WHERE plugin_id = ? AND version = ?`,
		pluginID, version)
	return scanVersion(row)
}

// ============================================================================
//  版本号占用（PLG-10）
// ----------------------------------------------------------------------------
//  失败过且从未激活的版本行（REJECTED / ROLLED_BACK、active=0、activated_at
//  为空）不再永久占用版本号：重试时删除旧行再插入新行。
// ============================================================================

// versionSlot classifies the version number of a new install or update.
type versionSlot int

const (
	// slotFree means no row exists.
	slotFree versionSlot = iota
	// slotRetry means the row is a failed attempt that was never activated
	// and may be replaced.
	slotRetry
	// slotTaken means the version is installed and must not be replaced.
	slotTaken
)

// rowQuerier is satisfied by *sql.Tx and *storage.Tx.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// versionSlotOf classifies pluginID@version and returns the digest of an
// existing row.
func versionSlotOf(ctx context.Context, q rowQuerier, pluginID, version string) (versionSlot, string, error) {
	var (
		status      VersionStatus
		active      int
		activatedAt string
		digest      string
	)
	err := q.QueryRowContext(ctx, `SELECT status, active, activated_at, digest FROM plugin_versions
		WHERE plugin_id = ? AND version = ?`, pluginID, version).Scan(&status, &active, &activatedAt, &digest)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return slotFree, "", nil
	case err != nil:
		return slotTaken, "", err
	}
	if (status == VersionRejected || status == VersionRolledBack) && active == 0 && activatedAt == "" {
		return slotRetry, digest, nil
	}
	return slotTaken, digest, nil
}

// deleteVersionTx removes the row of a failed attempt and records the delete.
func deleteVersionTx(ctx context.Context, tx *storage.Tx, pluginID, version string) error {
	if _, err := tx.Changed(ctx, storage.Change{Subject: versionSubject(pluginID, version), Kind: storage.Deleted}); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM plugin_versions WHERE plugin_id = ? AND version = ?`, pluginID, version)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// deleteInactiveVersionTx removes an obsolete inactive version row during GC,
// guarding against deleting an active version even under concurrent changes.
func deleteInactiveVersionTx(ctx context.Context, tx *storage.Tx, pluginID, version string) error {
	if _, err := tx.Changed(ctx, storage.Change{Subject: versionSubject(pluginID, version), Kind: storage.Deleted}); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM plugin_versions WHERE plugin_id = ? AND version = ? AND active = 0`, pluginID, version)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// listActiveConfigs loads the applied configuration of every plugin.
func (u *Updater) listActiveConfigs(ctx context.Context) (map[string]ConfigRevision, error) {
	out := make(map[string]ConfigRevision)
	err := u.db.View(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT plugin_id, revision, config_json, active, created_at, applied_at, revision_seq
			FROM plugin_configs WHERE active = 1`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanConfig(rows)
			if err != nil {
				return err
			}
			out[c.PluginID] = c
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func scanConfig(sc interface{ Scan(...any) error }) (ConfigRevision, error) {
	var (
		c          ConfigRevision
		configJSON string
		active     int
		createdAt  string
		appliedAt  string
	)
	if err := sc.Scan(&c.PluginID, &c.Revision, &configJSON, &active, &createdAt, &appliedAt, &c.Seq); err != nil {
		return ConfigRevision{}, err
	}
	c.Config = json.RawMessage(configJSON)
	c.Active = active != 0
	t, err := storage.ParseTime(createdAt)
	if err != nil {
		return ConfigRevision{}, err
	}
	c.CreatedAt = t
	if appliedAt != "" {
		if c.AppliedAt, err = storage.ParseTime(appliedAt); err != nil {
			return ConfigRevision{}, err
		}
	}
	return c, nil
}

// loadConfig reads one configuration revision.
func (u *Updater) loadConfig(ctx context.Context, pluginID string, revision int64) (ConfigRevision, error) {
	var out ConfigRevision
	err := u.db.View(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT plugin_id, revision, config_json, active, created_at, applied_at, revision_seq
			FROM plugin_configs WHERE plugin_id = ? AND revision = ?`, pluginID, revision)
		c, err := scanConfig(row)
		if err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
}

// nextConfigRevision returns MAX(revision)+1 inside a write transaction.
func nextConfigRevision(ctx context.Context, tx *storage.Tx, pluginID string) (int64, error) {
	var maxRev sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(revision) FROM plugin_configs WHERE plugin_id = ?`,
		pluginID).Scan(&maxRev); err != nil {
		return 0, err
	}
	return maxRev.Int64 + 1, nil
}

// previousVersion returns the most recently activated, non-active version of
// pluginID that is still retained and can be started again.
func (u *Updater) previousVersion(ctx context.Context, pluginID string) (Version, error) {
	var out Version
	err := u.db.View(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+versionColumns+` FROM plugin_versions
			WHERE plugin_id = ? AND active = 0 AND activated_at <> '' AND install_status = ?
			  AND status IN ('STOPPED', 'ROLLED_BACK', 'QUARANTINED', 'DRAINING')
			ORDER BY activated_at DESC, installed_at DESC LIMIT 1`, pluginID, InstallInstalled)
		v, err := scanVersion(row)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// hasRunningSaga reports whether the plugin already has an unfinished saga.
func (u *Updater) hasRunningSaga(ctx context.Context, pluginID string) (bool, error) {
	var n int
	err := u.db.View(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_update_sagas WHERE plugin_id = ? AND state = ?`,
			pluginID, SagaRunning).Scan(&n)
	})
	return n > 0, err
}

// requireNoRunningSaga makes sure no saga of the plugin is unfinished before a
// new operation starts. Callers hold the plugin lock and every live saga runs
// under it, so a RUNNING saga seen here is an orphan (its caller panicked or
// the host lost it); it is recovered in place instead of blocking the plugin
// until the next restart. Only a saga recovery cannot finish is refused.
func (u *Updater) requireNoRunningSaga(ctx context.Context, pluginID string) error {
	ok, err := u.hasRunningSaga(ctx, pluginID)
	if err != nil {
		return problem.Wrap(err)
	}
	if !ok {
		return nil
	}
	sagas, err := u.runningSagas(ctx)
	if err != nil {
		return problem.Wrap(err)
	}
	for i := range sagas {
		if sagas[i].PluginID != pluginID {
			continue
		}
		u.log.WarnContext(ctx, "recovering an orphan plugin saga", "plugin", pluginID, "saga", sagas[i].ID)
		if rerr := u.recoverSaga(ctx, &sagas[i]); rerr != nil {
			u.log.ErrorContext(ctx, "orphan plugin saga recovery failed", "plugin", pluginID,
				"saga", sagas[i].ID, "err", rerr)
		}
	}
	u.publishActiveRoutes()
	if ok, err = u.hasRunningSaga(ctx, pluginID); err != nil {
		return problem.Wrap(err)
	}
	if ok {
		return problem.New(problem.StateConflict, "The plugin has an unfinished update that recovery could not finish.")
	}
	return nil
}

// runningSagas returns every unfinished saga, oldest first.
func (u *Updater) runningSagas(ctx context.Context) ([]saga, error) {
	var out []saga
	err := u.db.View(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT saga_id, plugin_id, from_version, to_version, mode, strategy,
			state, step, error, created_at, updated_at FROM plugin_update_sagas
			WHERE state = ? ORDER BY created_at, saga_id`, SagaRunning)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			s, err := scanSaga(rows)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// scanSaga scans one plugin_update_sagas row.
func scanSaga(sc interface{ Scan(...any) error }) (saga, error) {
	var (
		s                    saga
		createdAt, updatedAt string
	)
	if err := sc.Scan(&s.ID, &s.PluginID, &s.FromVersion, &s.ToVersion, &s.Mode, &s.Strategy,
		&s.State, &s.Step, &s.Err, &createdAt, &updatedAt); err != nil {
		return saga{}, err
	}
	var err error
	if s.CreatedAt, err = storage.ParseTime(createdAt); err != nil {
		return saga{}, err
	}
	if s.UpdatedAt, err = storage.ParseTime(updatedAt); err != nil {
		return saga{}, err
	}
	return s, nil
}

// loadActiveVersionTx reads the currently active version inside a write
// transaction. It returns ok=false when the plugin has none.
func loadActiveVersionTx(ctx context.Context, tx *storage.Tx, pluginID string) (Version, bool, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+versionColumns+` FROM plugin_versions
		WHERE plugin_id = ? AND active = 1`, pluginID)
	v, err := scanVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, false, nil
	}
	if err != nil {
		return Version{}, false, err
	}
	return v, true, nil
}

// errNoVersion is the sentinel of scanVersion for sql.ErrNoRows.
var errNoVersion = sql.ErrNoRows
