// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ============================================================================
// 卸载的文件失败必须保留数据库边界，重启后仍能继续清理。
// ============================================================================

type purgeTestInstaller struct {
	*fakeInstaller
	purge func(context.Context, string) error
}

func (i *purgeTestInstaller) PurgeData(ctx context.Context, pluginID string) error {
	return i.purge(ctx, pluginID)
}

func TestRemovePurgeFailureKeepsRetryableDatabase(t *testing.T) {
	e := newEnv(t)
	calls := 0
	fail := true
	e.opts.Installer = &purgeTestInstaller{fakeInstaller: e.ins, purge: func(_ context.Context, id string) error {
		calls++
		if id != "acme.demo" {
			t.Fatalf("purge id=%s", id)
		}
		if fail {
			return problem.New(problem.Unavailable, "TEST-ONLY: data tree unavailable")
		}
		return nil
	}}
	e.reopen()
	e.mustInstallV1("acme.demo")
	ctx := t.Context()
	if _, err := e.u.ApplyConfig(ctx, ConfigRequest{PluginID: "acme.demo", Config: []byte(`{"a":1}`)}); err != nil {
		t.Fatal(err)
	}
	if err := e.u.SetEnabled(ctx, "acme.demo", false); err != nil {
		t.Fatal(err)
	}
	err := e.u.Remove(ctx, RemoveRequest{PluginID: "acme.demo", PurgeData: true})
	if !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("purge error=%v; want UNAVAILABLE", err)
	}
	for _, table := range []string{"plugin_versions", "plugin_configs", "plugin_states"} {
		if got := purgeRowCount(t, e.db, table, "acme.demo"); got != 1 {
			t.Fatalf("failure lost %s rows: %d", table, got)
		}
	}
	fail = false
	e.reopen()
	if err := e.u.Remove(ctx, RemoveRequest{PluginID: "acme.demo", PurgeData: true}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("purge calls=%d; want retry after restart", calls)
	}
	for _, table := range []string{"plugin_versions", "plugin_configs", "plugin_states"} {
		if got := purgeRowCount(t, e.db, table, "acme.demo"); got != 0 {
			t.Fatalf("retry left %s rows: %d", table, got)
		}
	}
}

func TestRemovePurgeWithoutVersions(t *testing.T) {
	e := newEnv(t)
	calls := 0
	e.opts.Installer = &purgeTestInstaller{fakeInstaller: e.ins, purge: func(_ context.Context, id string) error {
		calls++
		if id != "acme.demo" {
			t.Fatalf("purge id=%s", id)
		}
		return nil
	}}
	e.reopen()
	if err := e.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO plugin_states(plugin_id,enabled,updated_at) VALUES ('acme.demo',0,?)`, storage.FormatTime(tx.Now()))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.u.Remove(t.Context(), RemoveRequest{PluginID: "acme.demo", PurgeData: true}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("purge calls=%d; retained files must be cleaned without version rows", calls)
	}
	if got := purgeRowCount(t, e.db, "plugin_states", "acme.demo"); got != 0 {
		t.Fatalf("purge left %d state rows", got)
	}
}

func TestRemovePurgeCommitFailureRollsBackAllRows(t *testing.T) {
	e := newEnv(t)
	calls := 0
	e.opts.Installer = &purgeTestInstaller{fakeInstaller: e.ins, purge: func(context.Context, string) error { calls++; return nil }}
	e.reopen()
	e.mustInstallV1("acme.demo")
	if _, err := e.u.ApplyConfig(t.Context(), ConfigRequest{PluginID: "acme.demo", Config: []byte(`{"a":1}`)}); err != nil {
		t.Fatal(err)
	}
	if err := e.u.SetEnabled(t.Context(), "acme.demo", false); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `CREATE TRIGGER purge_state_failure BEFORE DELETE ON plugin_states
			WHEN OLD.plugin_id='acme.demo' BEGIN SELECT RAISE(ABORT, 'TEST-ONLY-purge-commit-failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.u.Remove(t.Context(), RemoveRequest{PluginID: "acme.demo", PurgeData: true}); err == nil {
		t.Fatal("purge swallowed the database failure")
	}
	if calls != 1 {
		t.Fatalf("file cleanup calls=%d; expected it before the short database transaction", calls)
	}
	for _, table := range []string{"plugin_versions", "plugin_configs", "plugin_states"} {
		if got := purgeRowCount(t, e.db, table, "acme.demo"); got != 1 {
			t.Fatalf("failed transaction lost %s rows: %d", table, got)
		}
	}
	if err := e.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DROP TRIGGER purge_state_failure`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	if err := e.u.Remove(t.Context(), RemoveRequest{PluginID: "acme.demo", PurgeData: true}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"plugin_versions", "plugin_configs", "plugin_states"} {
		if got := purgeRowCount(t, e.db, table, "acme.demo"); got != 0 {
			t.Fatalf("retry left %s rows: %d", table, got)
		}
	}
}

func purgeRowCount(t *testing.T, db *storage.DB, table, pluginID string) int {
	t.Helper()
	var count int
	if err := db.Reader().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM `+table+` WHERE plugin_id=?`, pluginID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
