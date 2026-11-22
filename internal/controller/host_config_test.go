// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/storage"
)

// 已提交 SQLite 快照的共享 fixture；生产读取始终经过真实 updater。
func loadStoredPluginUpdater(t *testing.T, db *storage.DB) *updater.Updater {
	t.Helper()
	u, err := updater.New(updater.Options{DB: db, Runtime: &UpdaterRuntime{}, Installer: &PluginInstaller{}, Memory: &HostMemory{}})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func storeAppliedPluginConfig(t *testing.T, db *storage.DB, pluginID string, revision int64, config string) {
	t.Helper()
	stamp := storage.FormatTime(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	if err := db.Update(t.Context(), func(tx *storage.Tx) error {
		if _, err := tx.ExecContext(t.Context(), "UPDATE plugin_configs SET active=0 WHERE plugin_id=? AND active=1", pluginID); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), "INSERT INTO plugin_configs(plugin_id,revision,config_json,active,created_at,applied_at) VALUES (?,?,?,1,?,?)", pluginID, revision, config, stamp, stamp)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// ======================== 快照换代、私有副本与失效上下文 ========================
func TestHostConfigSourceReadsLatestAndCopiesSnapshot(t *testing.T) {
	revision, snapshot := "1", []byte(`{"enabled":true}`)
	source := hostConfigSource{read: func(context.Context) (string, []byte, error) {
		return revision, snapshot, nil
	}}
	got, data, err := source.Current(t.Context())
	if err != nil || got != "1" || string(data) != string(snapshot) {
		t.Fatalf("Current = %q, %q, %v", got, data, err)
	}
	data[0] = 'x'
	if snapshot[0] != '{' {
		t.Fatal("caller modified the producer snapshot")
	}
	revision, snapshot = "2", []byte(`{"enabled":false}`)
	got, data, err = source.Current(t.Context())
	if err != nil || got != "2" || string(data) != string(snapshot) {
		t.Fatal("source returned the previous snapshot")
	}
}

func TestHostConfigSourceCancellationAndErrors(t *testing.T) {
	called := false
	sentinel := errors.New("fixture config unavailable")
	source := hostConfigSource{read: func(context.Context) (string, []byte, error) {
		called = true
		return "", nil, sentinel
	}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := source.Current(ctx); !errors.Is(err, context.Canceled) || called {
		t.Fatal("canceled source invoked its producer")
	}
	if _, _, err := source.Current(t.Context()); !errors.Is(err, sentinel) {
		t.Fatal("source concealed the producer error")
	}
}

func TestControllerHostConfigSourceUsesCurrentUpdater(t *testing.T) {
	c := &Controller{}
	deps := c.HostDeps()
	if deps.Config == nil {
		t.Fatal("controller omitted the host config factory")
	}
	source := deps.Config("alpha")
	if _, _, err := source.Current(t.Context()); err == nil {
		t.Fatal("unwired updater fabricated a snapshot")
	}
	c.SetUpdater(&updater.Updater{})
	revision, snapshot, err := source.Current(t.Context())
	if err != nil || revision != "0" || string(snapshot) != "{}" {
		t.Fatal("existing channel did not observe the newly wired updater")
	}
	c.SetUpdater(nil)
	if _, _, err := source.Current(t.Context()); err == nil {
		t.Fatal("removed updater remained accessible through the channel")
	}
}

func TestControllerHostConfigSourceBindsStoredPluginSnapshots(t *testing.T) {
	db := testDB(t)
	storeAppliedPluginConfig(t, db, "alpha", 1, `{"owner":"alpha"}`)
	storeAppliedPluginConfig(t, db, "bravo", 7, `{"owner":"bravo"}`)
	c := &Controller{db: db}
	c.SetUpdater(loadStoredPluginUpdater(t, db))
	alpha, bravo := c.HostDeps().Config("alpha"), c.HostDeps().Config("bravo")
	if revision, snapshot, err := alpha.Current(t.Context()); err != nil || revision != "1" || string(snapshot) != `{"owner":"alpha"}` {
		t.Fatalf("alpha = %q, %q, %v", revision, snapshot, err)
	}
	if revision, snapshot, err := bravo.Current(t.Context()); err != nil || revision != "7" || string(snapshot) != `{"owner":"bravo"}` {
		t.Fatal("bound source returned another plugin's config")
	}
	storeAppliedPluginConfig(t, db, "alpha", 2, `{"owner":"alpha","next":true}`)
	c.SetUpdater(loadStoredPluginUpdater(t, db))
	if revision, snapshot, err := alpha.Current(t.Context()); err != nil || revision != "2" || string(snapshot) != `{"owner":"alpha","next":true}` {
		t.Fatal("existing source did not observe the replacement updater snapshot")
	}
	if revision, _, err := bravo.Current(t.Context()); err != nil || revision != "7" {
		t.Fatal("updating alpha changed bravo's bound snapshot")
	}
}
