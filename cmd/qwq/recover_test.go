// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/config"
)

func TestReadPassword(t *testing.T) {
	if _, err := readPassword(strings.NewReader("")); err == nil {
		t.Fatal("accepted an empty password")
	}
	if _, err := readPassword(strings.NewReader("two\nlines\n")); err == nil {
		t.Fatal("accepted a multi-line password")
	}
	got, err := readPassword(strings.NewReader("Secret123!\r\n"))
	if err != nil || got != "Secret123!" {
		t.Fatalf("readPassword = %q, %v", got, err)
	}
}

func TestRecoverRequiresFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runRecover(nil, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "--username") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestRecoverMissingConfig(t *testing.T) {
	var out, errb bytes.Buffer
	code := runRecover([]string{
		"--config", filepath.Join(t.TempDir(), "missing.json"),
		"--username", "admin", "--password-stdin",
	}, strings.NewReader("NewPassword123!\n"), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr %q)", code, errb.String())
	}
}

func TestRecoverResetsAdmin(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.RunDir = filepath.Join(dir, "run")
	cfg.Log.Level = "error"

	c, err := controller.New(ctx, controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("controller: %v", err)
	}
	token, _, err := c.Identity().NewSetupToken(ctx)
	if err != nil {
		t.Fatalf("setup token: %v", err)
	}
	if _, err := c.Identity().CompleteSetup(ctx, identity.CompleteSetupInput{
		SetupToken: token,
		Username:   "admin",
		Password:   "InitialPassword123!",
	}); err != nil {
		t.Fatalf("complete setup: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "qwq.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := runRecover([]string{
		"--config", cfgPath,
		"--username", "ADMIN",
		"--password-stdin",
	}, strings.NewReader("NewPassword123!\n"), &out, &errb)
	if code != 0 {
		t.Fatalf("recover exit = %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "administrator admin reset") {
		t.Fatalf("stdout = %q", out.String())
	}

	c2, err := controller.New(ctx, controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer c2.Close()
	if _, err := c2.Identity().Login(ctx, identity.LoginInput{Username: "admin", Password: "NewPassword123!"}); err != nil {
		t.Fatalf("login with the new password: %v", err)
	}
	if _, err := c2.Identity().Login(ctx, identity.LoginInput{Username: "admin", Password: "InitialPassword123!"}); err == nil {
		t.Fatal("login with the old password still succeeds")
	}
}

func TestRecoverRefusesNonRoot(t *testing.T) {
	restore := geteuid
	geteuid = func() int { return 1000 }
	t.Cleanup(func() { geteuid = restore })

	cfgPath, _ := writeLocalConfig(t)
	var out, errb bytes.Buffer
	code := runRecover([]string{"--config", cfgPath, "--username", "admin", "--password-stdin"},
		strings.NewReader("NewPassword123!\n"), &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "sudo") {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
}

func TestRecoverRefusesMissingDatabase(t *testing.T) {
	cfgPath, cfg := writeLocalConfig(t)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := runRecover([]string{"--config", cfgPath, "--username", "admin", "--password-stdin"},
		strings.NewReader("NewPassword123!\n"), &out, &errb)
	if code != 1 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	// 不负责创建：数据库与主密钥都不应出现。
	for _, p := range []string{filepath.Join(cfg.DataDir, "qwq.db"), filepath.Join(cfg.DataDir, "keys", "master.key")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s was created (%v)", p, err)
		}
	}
}

// writeLocalConfig 在临时目录写一份 qwq.json，数据目录尚不存在。
func writeLocalConfig(t *testing.T) (string, config.Config) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.RunDir = filepath.Join(dir, "run")
	cfg.Log.Level = "error"
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "qwq.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, cfg
}
