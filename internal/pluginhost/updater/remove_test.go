// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// TestRemoveIsIdempotent (GAPS gap 7): the uninstall is a step sequence, not a
// saga, so running it twice — as a retry after a crash would — must succeed and
// leave nothing behind.
func TestRemoveIsIdempotent(t *testing.T) {
	e := newEnv(t)
	e.mustInstallV1("acme.demo")
	ctx := e.t.Context()
	if err := e.u.Remove(ctx, RemoveRequest{PluginID: "acme.demo"}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, ok := e.u.Active("acme.demo"); ok {
		t.Fatal("the plugin is still active")
	}
	if _, ok := e.u.Routes().Lookup("acme.demo"); ok {
		t.Fatal("the plugin is still routed")
	}
	versions, err := e.u.Versions("acme.demo")
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(versions) != 0 {
		t.Fatalf("versions = %d, want 0", len(versions))
	}
	if err := e.u.Remove(ctx, RemoveRequest{PluginID: "acme.demo"}); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

// TestRemovePurgesData: purge_data deletes the retained configuration revisions
// and the plugin token digest; without it they survive the uninstall.
func TestRemovePurgesData(t *testing.T) {
	for _, purge := range []bool{false, true} {
		e := newEnv(t)
		e.mustInstallV1("acme.demo")
		ctx := e.t.Context()
		keys, err := secrets.LoadKeyRing(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		store, err := secrets.New(secrets.Options{DB: e.db, Keys: keys})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.db.Update(ctx, func(tx *storage.Tx) error {
			for _, owner := range []string{"plugins/acme.demo", "plugins/unrelated"} {
				if _, err := store.Put(ctx, tx, owner, "plugin.config", []byte("TEST-ONLY-purge-secret")); err != nil {
					return err
				}
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO plugin_states(plugin_id,enabled,updated_at) VALUES ('unrelated',0,?)`, storage.FormatTime(tx.Now()))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.u.ApplyConfig(ctx, ConfigRequest{
			PluginID: "acme.demo", Config: []byte(`{"a":1}`),
		}); err != nil {
			t.Fatalf("apply config: %v", err)
		}
		if err := e.u.SetEnabled(ctx, "acme.demo", false); err != nil {
			t.Fatal(err)
		}
		if err := e.u.Remove(ctx, RemoveRequest{PluginID: "acme.demo", PurgeData: purge}); err != nil {
			t.Fatalf("remove: %v", err)
		}
		var configs int
		if err := e.db.Reader().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM plugin_configs WHERE plugin_id = 'acme.demo'`).Scan(&configs); err != nil {
			t.Fatalf("count configs: %v", err)
		}
		if purge && configs != 0 {
			t.Fatalf("purge left %d config rows", configs)
		}
		if !purge && configs == 0 {
			t.Fatal("the retained configuration was deleted without purge_data")
		}
		var states int
		if err := e.db.Reader().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM plugin_states WHERE plugin_id = 'acme.demo'`).Scan(&states); err != nil {
			t.Fatal(err)
		}
		if (purge && states != 0) || (!purge && states != 1) {
			t.Errorf("purge=%v left %d state rows", purge, states)
		}
		if got := purgeRowCount(t, e.db, "plugin_states", "unrelated"); got != 1 {
			t.Fatalf("purge changed another plugin's state: %d rows", got)
		}
		e.reopen()
		if enabled, err := e.u.Enabled(ctx, "acme.demo"); err != nil || enabled != purge {
			t.Fatalf("reopened enabled=%v err=%v; purge=%v", enabled, err, purge)
		}
		var own, unrelated int
		if err := e.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE owner='plugins/acme.demo'`).Scan(&own); err != nil {
			t.Fatal(err)
		}
		if err := e.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE owner='plugins/unrelated'`).Scan(&unrelated); err != nil {
			t.Fatal(err)
		}
		if unrelated != 1 || (purge && own != 0) || (!purge && own != 1) {
			t.Fatal("uninstall did not preserve the exact secret owner/purge boundary")
		}
	}
}
