// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/pluginui"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ============================================================================
// 真实版本行驱动静态入口：隔离与拒绝版本不能继续发布可执行页面。
// ============================================================================

func TestPluginUIRejectsUnsafeVersionState(t *testing.T) {
	db, err := storage.Open(t.Context(), storage.Options{Path: filepath.Join(t.TempDir(), "qwq.db"), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root := t.TempDir()
	ui := filepath.Join(root, "acme.demo", "1.2.3", "ui")
	if err := os.MkdirAll(ui, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ui, "index.html"), []byte("<!doctype html><title>retained plugin</title>"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(testManifest("acme.demo", "1.2.3", "Demo", "schemas/config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO plugin_versions(plugin_id,version,digest,manifest_json,status,install_status,installed_at)
			VALUES ('acme.demo','1.2.3',?,?,'STOPPED','INSTALLED',?)`, "sha256:"+strings.Repeat("a", 64), string(manifest), storage.FormatTime(tx.Now()))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	u, err := updater.New(updater.Options{DB: db, Runtime: &controller.UpdaterRuntime{}, Installer: &controller.PluginInstaller{}, Memory: &controller.HostMemory{}})
	if err != nil {
		t.Fatal(err)
	}
	handler := pluginui.NewHandler(newPluginUIResolver(u, root))
	for _, test := range []struct {
		state  updater.VersionStatus
		status int
	}{
		{updater.VersionStopped, http.StatusOK},
		{updater.VersionQuarantined, http.StatusNotFound},
		{updater.VersionRejected, http.StatusNotFound},
		{updater.VersionRolledBack, http.StatusOK},
	} {
		if err := db.Update(t.Context(), func(tx *storage.Tx) error {
			_, err := tx.ExecContext(t.Context(), `UPDATE plugin_versions SET status=? WHERE plugin_id='acme.demo'`, string(test.state))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/plugin-ui/acme.demo/1.2.3/ui/index.html", nil))
		if response.Code != test.status {
			t.Errorf("version state=%s returned %d; want %d", test.state, response.Code, test.status)
		}
	}
}
