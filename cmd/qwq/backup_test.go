// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/storage"
)

// stubControllerActive 让恢复前的"controller 是否在运行"检查返回 active。
func stubControllerActive(t *testing.T, active bool) {
	t.Helper()
	old := controllerActive
	controllerActive = func() bool { return active }
	t.Cleanup(func() { controllerActive = old })
}

// initInstallation 建一个已完成初始化的安装：管理员 admin、一条 secret、
// 一份插件 KV 状态。返回 secret 引用。
func initInstallation(t *testing.T, cfg config.Config) string {
	t.Helper()
	ctx := t.Context()
	c, err := controller.New(ctx, controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("controller: %v", err)
	}
	token, _, err := c.Identity().NewSetupToken(ctx)
	if err != nil {
		t.Fatalf("setup token: %v", err)
	}
	if _, err := c.Identity().CompleteSetup(ctx, identity.CompleteSetupInput{
		SetupToken: token, Username: "admin", Password: "InitialPassword123!",
	}); err != nil {
		t.Fatalf("complete setup: %v", err)
	}
	ref, err := c.Secrets().Seal(ctx, "test.backup", []byte("s3cret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	state := filepath.Join(cfg.DataDir, "plugin-state", "alpha", "state.json")
	if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte(`{"k":"v"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return ref
}

// backupOnce 跑一次 qwq backup，返回生成的归档路径。
func backupOnce(t *testing.T, args ...string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if code := runBackup(args, &out, &errb); code != 0 {
		t.Fatalf("backup exit = %d, stderr %q", code, errb.String())
	}
	p := strings.TrimSpace(out.String())
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("backup output %q: %v", p, err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode %v, want 0600", fi.Mode().Perm())
	}
	return p
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	stubControllerActive(t, false)
	ctx := t.Context()
	cfgPath, cfg := writeLocalConfig(t)
	ref := initInstallation(t, cfg)

	outDir := filepath.Join(t.TempDir(), "backups")
	for range 3 {
		backupOnce(t, "--config", cfgPath, "--out", outDir, "--keep", "2")
	}
	if got, _ := filepath.Glob(filepath.Join(outDir, "qwq-*.tar.gz")); len(got) != 2 {
		t.Fatalf("--keep 2 left %v", got)
	}
	archive := backupOnce(t, "--config", cfgPath, "--out", outDir)

	// 数据目录整个丢失后重新初始化：新库、新主密钥。
	if err := os.RemoveAll(cfg.DataDir); err != nil {
		t.Fatal(err)
	}
	c, err := controller.New(ctx, controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("fresh controller: %v", err)
	}
	c.Close()

	var out, errb bytes.Buffer
	if code := runRestore([]string{"--config", cfgPath, archive}, &out, &errb); code != 0 {
		t.Fatalf("restore exit = %d, stderr %q", code, errb.String())
	}
	for _, p := range []string{".restore-tmp", ".restore-old"} {
		if _, err := os.Stat(filepath.Join(cfg.DataDir, p)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind (%v)", p, err)
		}
	}

	c, err = controller.New(ctx, controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("restored controller: %v", err)
	}
	defer c.Close()
	if _, err := c.Identity().Login(ctx, identity.LoginInput{Username: "admin", Password: "InitialPassword123!"}); err != nil {
		t.Fatalf("login after restore: %v", err)
	}
	if got, err := c.Secrets().Open(ctx, ref); err != nil || string(got) != "s3cret" {
		t.Fatalf("secret after restore = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(cfg.DataDir, "plugin-state", "alpha", "state.json")); err != nil || string(got) != `{"k":"v"}` {
		t.Fatalf("plugin state after restore = %q, %v", got, err)
	}
}

func TestRestoreRefusesNewerSchema(t *testing.T) {
	stubControllerActive(t, false)
	cfgPath, cfg := writeLocalConfig(t)
	initInstallation(t, cfg)

	// 模拟新版本写过的库：多一条本二进制不认识的迁移记录。
	db, err := sql.Open("sqlite", filepath.Join(cfg.DataDir, "qwq.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, 'future', 'x', '2099-01-01T00:00:00.000Z')`,
		storage.LatestSchemaVersion()+1); err != nil {
		t.Fatal(err)
	}
	db.Close()
	archive := backupOnce(t, "--config", cfgPath, "--out", t.TempDir())

	before, err := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runRestore([]string{"--config", cfgPath, archive}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "newer") {
		t.Fatalf("restore exit = %d, stderr %q", code, errb.String())
	}
	after, err := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "master.key"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("refused restore touched the data directory (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, ".restore-tmp")); !os.IsNotExist(err) {
		t.Fatalf(".restore-tmp left behind (%v)", err)
	}
}

func TestRestoreRefusesWhileRunning(t *testing.T) {
	stubControllerActive(t, false)
	cfgPath, cfg := writeLocalConfig(t)
	initInstallation(t, cfg)
	archive := backupOnce(t, "--config", cfgPath, "--out", t.TempDir())

	stubControllerActive(t, true)
	var out, errb bytes.Buffer
	if code := runRestore([]string{"--config", cfgPath, archive}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "systemctl stop qwq-controller") {
		t.Fatalf("restore exit = %d, stderr %q", code, errb.String())
	}
}
