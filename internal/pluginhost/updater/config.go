// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// configEvent is the audit payload of one configuration outcome.
type configEvent struct {
	PluginID   string              `json:"plugin_id"`
	Revision   int64               `json:"revision"`
	Seq        int64               `json:"seq,omitempty"`
	Active     bool                `json:"active"`
	Error      string              `json:"error,omitempty"`
	Violations []problem.Violation `json:"violations,omitempty"`
}

// ApplyConfig stores an immutable candidate snapshot, lets the plugin
// validate and apply it, and only then moves the active pointer (ARCH §6.5).
// A failed plugin call keeps the previous revision active and leaves the
// candidate row inactive for diagnosis.
func (u *Updater) ApplyConfig(ctx context.Context, req ConfigRequest) (ConfigRevision, error) {
	if err := checkPluginID(req.PluginID); err != nil {
		return ConfigRevision{}, err
	}
	if len(req.Config) == 0 {
		return ConfigRevision{}, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "REQUIRED", Message: "A configuration object is required.",
		})
	}
	if len(req.Config) > maxConfigBytes {
		return ConfigRevision{}, &problem.Error{
			Code:   problem.PayloadTooLarge,
			Detail: fmt.Sprintf("A configuration snapshot must be at most %d bytes.", maxConfigBytes),
			Limit:  &problem.Limit{Name: "config_json", Max: maxConfigBytes},
		}
	}
	if !json.Valid(req.Config) {
		return ConfigRevision{}, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID_JSON", Message: "The configuration is not valid JSON.",
		})
	}
	ctx, cancel := u.withTimeout(ctx, req.Timeout)
	defer cancel()

	unlock := u.locks.lock(req.PluginID)
	defer unlock()

	active, ok := u.Active(req.PluginID)
	if !ok {
		return ConfigRevision{}, problem.New(problem.NotFound,
			"Plugin %s has no active version to configure.", req.PluginID)
	}
	if err := u.requireNoRunningSaga(ctx, req.PluginID); err != nil {
		return ConfigRevision{}, err
	}
	current, hasCurrent := u.ActiveConfig(req.PluginID)
	var curRev int64
	if hasCurrent {
		curRev = current.Revision
	}
	if req.ExpectedRevision != curRev {
		return ConfigRevision{}, problem.Conflict(fmt.Sprint(curRev))
	}

	h, ok, err := u.ensureHandle(ctx, u.specFor(req.PluginID, active), false)
	if err != nil || !ok {
		return ConfigRevision{}, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("Plugin %s is not running; its configuration cannot be applied.", req.PluginID),
			Cause:  err,
		}
	}

	candidate, err := u.insertConfigCandidate(ctx, req.PluginID, req.Config)
	if err != nil {
		return ConfigRevision{}, err
	}
	if err := u.rt.ValidateConfig(ctx, h, candidate.Revision, req.Config); err != nil {
		u.rejectConfig(ctx, req.PluginID, candidate.Revision, err)
		return ConfigRevision{}, configProblem(req.PluginID, candidate.Revision, err)
	}
	hotApply := active.Manifest == nil || active.Manifest.Config.HotApply
	if hotApply {
		if err := u.rt.ApplyConfig(ctx, h, candidate.Revision, req.Config); err != nil {
			u.rejectConfig(ctx, req.PluginID, candidate.Revision, err)
			return ConfigRevision{}, configProblem(req.PluginID, candidate.Revision, err)
		}
	}
	if err := u.switchConfig(ctx, req.PluginID, candidate.Revision); err != nil {
		return ConfigRevision{}, err
	}
	applied, err := u.loadConfig(ctx, req.PluginID, candidate.Revision)
	if err != nil {
		return ConfigRevision{}, problem.Wrap(err)
	}
	u.setActiveConfig(applied)
	if !hotApply {
		if err := u.restartForConfig(ctx, req.PluginID, active); err != nil {
			return ConfigRevision{}, err
		}
	}
	return applied, nil
}

// restartForConfig replaces the running instance of a hot_apply=false plugin,
// which receives the new active revision in Initialize. The revision is already
// committed: a failed restart reports PLUGIN_UNAVAILABLE and the next start
// (EnsureActive or recovery) still uses that revision.
func (u *Updater) restartForConfig(ctx context.Context, pluginID string, active Version) error {
	err := u.cleanupInstance(ctx, pluginID, active.Version)
	if err == nil {
		var h Handle
		if h, err = u.readyHandle(ctx, u.specFor(pluginID, active)); err == nil {
			err = u.rt.Activate(ctx, h)
		}
	}
	if err != nil {
		return &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("Plugin %s could not be restarted with its new configuration.", pluginID),
			Cause:  err,
		}
	}
	return nil
}

// insertConfigCandidate appends one inactive snapshot and records its create
// event with the next revision number.
func (u *Updater) insertConfigCandidate(ctx context.Context, pluginID string, cfg json.RawMessage) (ConfigRevision, error) {
	var candidate ConfigRevision
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		rev, err := nextConfigRevision(ctx, tx, pluginID)
		if err != nil {
			return err
		}
		seq, err := tx.Changed(ctx, storage.Change{Subject: configSubject(pluginID, rev), Kind: storage.Created})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_configs
			(plugin_id, revision, config_json, active, created_at, applied_at, revision_seq)
			VALUES (?, ?, ?, 0, ?, '', ?)`,
			pluginID, rev, string(cfg), storage.FormatTime(tx.Now()), seq); err != nil {
			return mapConstraint(err)
		}
		candidate = ConfigRevision{
			PluginID:  pluginID,
			Revision:  rev,
			Config:    append(json.RawMessage(nil), cfg...),
			Active:    false,
			Seq:       seq,
			CreatedAt: tx.Now(),
		}
		return nil
	})
	if err != nil {
		return ConfigRevision{}, err
	}
	return candidate, nil
}

// switchConfig moves the active configuration pointer and prunes old
// snapshots, all in one short transaction.
func (u *Updater) switchConfig(ctx context.Context, pluginID string, revision int64) error {
	return u.db.Update(ctx, func(tx *storage.Tx) error {
		var oldRev int64
		err := tx.QueryRowContext(ctx, `SELECT revision FROM plugin_configs WHERE plugin_id = ? AND active = 1`,
			pluginID).Scan(&oldRev)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		default:
			seq, cerr := tx.Changed(ctx, storage.Change{Subject: configSubject(pluginID, oldRev), Kind: storage.Updated})
			if cerr != nil {
				return cerr
			}
			if _, err := tx.ExecContext(ctx, `UPDATE plugin_configs SET active = 0, revision_seq = ?
				WHERE plugin_id = ? AND revision = ?`, seq, pluginID, oldRev); err != nil {
				return err
			}
		}
		seq, err := tx.Changed(ctx, storage.Change{Subject: configSubject(pluginID, revision), Kind: storage.Updated})
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE plugin_configs SET active = 1, applied_at = ?, revision_seq = ?
			WHERE plugin_id = ? AND revision = ?`, storage.FormatTime(tx.Now()), seq, pluginID, revision)
		if err != nil {
			return mapConstraint(err)
		}
		if err := requireOneRow(res); err != nil {
			return problem.New(problem.StateConflict, "The configuration revision %d of plugin %s disappeared.", revision, pluginID)
		}
		if err := u.appendEventTx(ctx, tx, "plugin.config.applied", configSubject(pluginID, revision), "", configEvent{
			PluginID: pluginID,
			Revision: revision,
			Seq:      seq,
			Active:   true,
		}); err != nil {
			return err
		}
		return u.pruneConfigsTx(ctx, tx, pluginID)
	})
}

// pruneConfigsTx keeps the newest KeepConfigs revisions and every revision
// younger than KeepConfigAge (the union, ARCH §6.5). The active revision is
// never pruned.
func (u *Updater) pruneConfigsTx(ctx context.Context, tx *storage.Tx, pluginID string) error {
	var maxRev sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(revision) FROM plugin_configs WHERE plugin_id = ?`,
		pluginID).Scan(&maxRev); err != nil {
		return err
	}
	threshold := maxRev.Int64 - int64(u.opts.KeepConfigs)
	if threshold <= 0 {
		return nil
	}
	cutoff := storage.FormatTime(tx.Now().Add(-u.opts.KeepConfigAge))
	rows, err := tx.QueryContext(ctx, `SELECT revision FROM plugin_configs
		WHERE plugin_id = ? AND active = 0 AND revision <= ? AND created_at < ?
		ORDER BY revision`, pluginID, threshold, cutoff)
	if err != nil {
		return err
	}
	var stale []int64
	for rows.Next() {
		var rev int64
		if err := rows.Scan(&rev); err != nil {
			rows.Close()
			return err
		}
		stale = append(stale, rev)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, rev := range stale {
		if _, err := tx.Changed(ctx, storage.Change{Subject: configSubject(pluginID, rev), Kind: storage.Deleted}); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_configs WHERE plugin_id = ? AND revision = ?`,
			pluginID, rev); err != nil {
			return err
		}
	}
	return nil
}

// rejectConfig records the audit event of a rejected snapshot. The snapshot
// itself stays inactive; the active pointer is untouched.
func (u *Updater) rejectConfig(ctx context.Context, pluginID string, revision int64, cause error) {
	var pe *problem.Error
	violations := []problem.Violation(nil)
	text := cause.Error()
	if errors.As(cause, &pe) {
		violations = pe.Violations
		text = fmt.Sprintf("%s: %s", pe.Code, pe.Detail)
	}
	err := u.db.Update(ctx, func(tx *storage.Tx) error {
		return u.appendEventTx(ctx, tx, "plugin.config.rejected", configSubject(pluginID, revision), "", configEvent{
			PluginID:   pluginID,
			Revision:   revision,
			Active:     false,
			Error:      text,
			Violations: violations,
		})
	})
	if err != nil {
		u.log.WarnContext(ctx, "config rejection event could not be recorded",
			"plugin", pluginID, "revision", revision, "err", err)
	}
}

// configProblem preserves a field-level problem from the plugin and otherwise
// reports that the plugin rejected the snapshot.
func configProblem(pluginID string, revision int64, err error) error {
	var pe *problem.Error
	if errors.As(err, &pe) {
		return pe
	}
	return &problem.Error{
		Code:   problem.PluginError,
		Detail: fmt.Sprintf("Plugin %s rejected configuration revision %d.", pluginID, revision),
		Cause:  err,
	}
}

// setActiveConfig updates the in-memory applied configuration.
func (u *Updater) setActiveConfig(c ConfigRevision) {
	u.configMu.Lock()
	defer u.configMu.Unlock()
	u.configs[c.PluginID] = c
}
