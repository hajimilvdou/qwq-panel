// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/config"
)

var setupLink = regexp.MustCompile(`https://127\.0\.0\.1:8443/setup#token=(\S+)`)

// initDataDir 启动一次 controller 建好数据目录，再写出 qwq.json。
func initDataDir(t *testing.T) (string, config.Config) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.RunDir = filepath.Join(dir, "run")
	cfg.Log.Level = "error"
	c, err := controller.New(t.Context(), controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("controller: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
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

func issueSetupToken(t *testing.T, cfgPath string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if code := runSetupToken([]string{"--config", cfgPath}, &out, &errb); code != 0 {
		t.Fatalf("setup-token exit = %d, stderr %q", code, errb.String())
	}
	m := setupLink.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no setup link in %q", out.String())
	}
	return m[1]
}

func completeSetup(t *testing.T, cfg config.Config, token string) error {
	t.Helper()
	c, err := controller.New(t.Context(), controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("controller: %v", err)
	}
	defer c.Close()
	_, err = c.Identity().CompleteSetup(t.Context(), identity.CompleteSetupInput{
		SetupToken: token, Username: "admin", Password: "InitialPassword123!",
	})
	return err
}

func TestSetupTokenIssuesAndCompletes(t *testing.T) {
	cfgPath, cfg := initDataDir(t)
	if err := completeSetup(t, cfg, issueSetupToken(t, cfgPath)); err != nil {
		t.Fatalf("complete setup with the printed token: %v", err)
	}
}

func TestSetupTokenReissueInvalidatesOld(t *testing.T) {
	cfgPath, cfg := initDataDir(t)
	old := issueSetupToken(t, cfgPath)
	fresh := issueSetupToken(t, cfgPath)
	if err := completeSetup(t, cfg, old); err == nil {
		t.Fatal("the superseded token still completes setup")
	}
	if err := completeSetup(t, cfg, fresh); err != nil {
		t.Fatalf("complete setup with the new token: %v", err)
	}
}

func TestSetupTokenRefusesWhenInitialized(t *testing.T) {
	cfgPath, cfg := initDataDir(t)
	if err := completeSetup(t, cfg, issueSetupToken(t, cfgPath)); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runSetupToken([]string{"--config", cfgPath}, &out, &errb); code != exitInitialized {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, exitInitialized, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("printed %q after initialization", out.String())
	}
}

func TestDefaultOrigin(t *testing.T) {
	for listen, want := range map[string]string{
		"127.0.0.1:8443": "https://127.0.0.1:8443",
		"0.0.0.0:9443":   "https://127.0.0.1:9443",
		"[::]:8443":      "https://127.0.0.1:8443",
		":8443":          "https://127.0.0.1:8443",
	} {
		if got := defaultOrigin(config.HTTP{Listen: listen}); got != want {
			t.Errorf("defaultOrigin(%q) = %q, want %q", listen, got, want)
		}
	}
	if got := defaultOrigin(config.HTTP{Listen: "127.0.0.1:8443", PublicOrigins: []string{"https://panel.example"}}); got != "https://panel.example" {
		t.Errorf("public origin ignored: %q", got)
	}
}
