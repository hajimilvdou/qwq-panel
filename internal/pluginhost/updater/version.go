// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// canTransition reports whether the version lifecycle may move from -> to.
//
// It follows the state diagram of ARCH §6.1 and adds three edges that only
// recovery uses: DRAINING -> ACTIVE and STOPPED -> ACTIVE for restoring the
// old version after a failure that happened after the route switch, and
// STOPPED/ROLLED_BACK -> STARTING for restarting a retained version during a
// rollback. A transition to the same state is a no-op and always allowed so
// that a retried saga step is idempotent.
func canTransition(from, to VersionStatus) bool {
	if from == to {
		return true
	}
	switch from {
	case VersionStaged:
		return to == VersionStarting || to == VersionRejected || to == VersionRolledBack
	case VersionStarting:
		return to == VersionCandidate || to == VersionRejected || to == VersionRolledBack || to == VersionQuarantined
	case VersionCandidate:
		return to == VersionActive || to == VersionRejected || to == VersionRolledBack ||
			to == VersionStopped || to == VersionQuarantined
	case VersionActive:
		return to == VersionDraining || to == VersionQuarantined
	case VersionDraining:
		return to == VersionStopped || to == VersionActive
	case VersionStopped:
		return to == VersionStarting || to == VersionActive
	case VersionRolledBack:
		return to == VersionStarting
	case VersionQuarantined:
		return to == VersionStarting || to == VersionStopped
	}
	return false
}

// versionStatusProblem renders an illegal transition.
func versionStatusProblem(pluginID, version string, from, to VersionStatus) error {
	return problem.New(problem.StateConflict,
		"The plugin %s version %s cannot move from %s to %s.", pluginID, version, from, to)
}

// insertVersionTx creates a version row and records its create event.
func (u *Updater) insertVersionTx(ctx context.Context, tx *storage.Tx, staged Staged, status VersionStatus, install InstallStatus) error {
	subject := versionSubject(staged.PluginID, staged.Version)
	seq, err := tx.Changed(ctx, storage.Change{Subject: subject, Kind: storage.Created})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_versions
		(plugin_id, version, digest, manifest_json, status, install_status, active,
		 installed_at, activated_at, rejected_reason, revision)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, '', '', ?)`,
		staged.PluginID, staged.Version, staged.Digest, string(staged.ManifestJSON),
		status, install, storage.FormatTime(tx.Now()), seq); err != nil {
		return mapConstraint(err)
	}
	return nil
}

// setVersionStatusTx validates and applies a lifecycle transition.
func (u *Updater) setVersionStatusTx(ctx context.Context, tx *storage.Tx, pluginID, version string, to VersionStatus) error {
	cur, err := loadVersionTx(ctx, tx, pluginID, version)
	if err != nil {
		return err
	}
	if !canTransition(cur.Status, to) {
		return versionStatusProblem(pluginID, version, cur.Status, to)
	}
	if cur.Status == to {
		return nil
	}
	seq, err := tx.Changed(ctx, storage.Change{Subject: versionSubject(pluginID, version), Kind: storage.Updated})
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE plugin_versions SET status = ?, revision = ?
		WHERE plugin_id = ? AND version = ?`, to, seq, pluginID, version)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// setInstallStatusTx applies an installation status.
func (u *Updater) setInstallStatusTx(ctx context.Context, tx *storage.Tx, pluginID, version string, to InstallStatus) error {
	cur, err := loadVersionTx(ctx, tx, pluginID, version)
	if err != nil {
		return err
	}
	if cur.InstallStatus == to {
		return nil
	}
	seq, err := tx.Changed(ctx, storage.Change{Subject: versionSubject(pluginID, version), Kind: storage.Updated})
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE plugin_versions SET install_status = ?, revision = ?
		WHERE plugin_id = ? AND version = ?`, to, seq, pluginID, version)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// setVersionActiveTx sets the committed-active flag of one version. Clearing
// the flag of the old version happens before setting the new one so the
// partial unique index never sees two active rows.
func (u *Updater) setVersionActiveTx(ctx context.Context, tx *storage.Tx, pluginID, version string, active bool) error {
	cur, err := loadVersionTx(ctx, tx, pluginID, version)
	if err != nil {
		return err
	}
	if cur.Active == active {
		return nil
	}
	seq, err := tx.Changed(ctx, storage.Change{Subject: versionSubject(pluginID, version), Kind: storage.Updated})
	if err != nil {
		return err
	}
	flag := 0
	if active {
		flag = 1
	}
	res, err := tx.ExecContext(ctx, `UPDATE plugin_versions SET active = ?, revision = ?
		WHERE plugin_id = ? AND version = ?`, flag, seq, pluginID, version)
	if err != nil {
		return mapConstraint(err)
	}
	return requireOneRow(res)
}

// setVersionActivatedAtTx records the commit time of an activation.
func (u *Updater) setVersionActivatedAtTx(ctx context.Context, tx *storage.Tx, pluginID, version string, at time.Time) error {
	seq, err := tx.Changed(ctx, storage.Change{Subject: versionSubject(pluginID, version), Kind: storage.Updated})
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE plugin_versions SET activated_at = ?, revision = ?
		WHERE plugin_id = ? AND version = ?`, storage.FormatTime(at), seq, pluginID, version)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// setVersionRejectedReasonTx records why a version was not activated.
func (u *Updater) setVersionRejectedReasonTx(ctx context.Context, tx *storage.Tx, pluginID, version, reason string) error {
	seq, err := tx.Changed(ctx, storage.Change{Subject: versionSubject(pluginID, version), Kind: storage.Updated})
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE plugin_versions SET rejected_reason = ?, revision = ?
		WHERE plugin_id = ? AND version = ?`, reason, seq, pluginID, version)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// clearActiveTx clears the active flag of the committed active version when
// it is not exceptVersion.
func (u *Updater) clearActiveTx(ctx context.Context, tx *storage.Tx, pluginID, exceptVersion string) (Version, bool, error) {
	cur, ok, err := loadActiveVersionTx(ctx, tx, pluginID)
	if err != nil || !ok {
		return Version{}, ok, err
	}
	if cur.Version == exceptVersion {
		return cur, true, nil
	}
	if err := u.setVersionActiveTx(ctx, tx, pluginID, cur.Version, false); err != nil {
		return Version{}, true, err
	}
	return cur, true, nil
}

func requireOneRow(res interface{ RowsAffected() (int64, error) }) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("updater: expected to update exactly one row")
	}
	return nil
}

// mapConstraint turns a unique/foreign-key violation into a state conflict so
// callers never see a bare SQLite error.
func mapConstraint(err error) error {
	if storage.IsConstraint(err) {
		return problem.New(problem.StateConflict, "The plugin state changed concurrently; retry the operation.")
	}
	return err
}

// stepEvent is the audit payload of one saga step.
type stepEvent struct {
	SagaID      string `json:"saga_id"`
	PluginID    string `json:"plugin_id"`
	Mode        string `json:"mode"`
	Strategy    string `json:"strategy"`
	Step        string `json:"step"`
	Next        string `json:"next,omitempty"`
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version"`
	Error       string `json:"error,omitempty"`
}

// appendEventTx appends one host audit event.
func (u *Updater) appendEventTx(ctx context.Context, tx *storage.Tx, typ, subject, sagaID string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.AppendEvent(ctx, storage.Event{
		Type:          typ,
		SchemaVersion: eventsSchemaVersion,
		Subject:       subject,
		Payload:       raw,
	})
	return err
}

// sagaEventName maps a saga mode and outcome to its event type.
func sagaEventName(mode sagaMode, outcome string) string {
	if mode == modeInstall {
		return "plugin.install." + outcome
	}
	return "plugin.update." + outcome
}

// recordStepEventTx appends the audit event of one completed step.
func (u *Updater) recordStepEventTx(ctx context.Context, tx *storage.Tx, s *saga, step, next, errMsg string) error {
	return u.appendEventTx(ctx, tx, sagaEventName(s.Mode, "step"), "plugins/"+s.PluginID, s.ID, stepEvent{
		SagaID:      s.ID,
		PluginID:    s.PluginID,
		Mode:        string(s.Mode),
		Strategy:    string(s.Strategy),
		Step:        step,
		Next:        next,
		FromVersion: s.FromVersion,
		ToVersion:   s.ToVersion,
		Error:       errMsg,
	})
}

// sagaErrorText shortens an error for storage in the saga row.
func sagaErrorText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 1000 {
		s = s[:1000]
	}
	return s
}

// problemDetail extracts the detail of a *problem.Error for the saga row.
func problemDetail(err error) string {
	var pe *problem.Error
	if errors.As(err, &pe) {
		return fmt.Sprintf("%s: %s", pe.Code, pe.Detail)
	}
	return err.Error()
}
