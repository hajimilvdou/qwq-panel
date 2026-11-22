// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestRotateMasterKeyCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.RunDir = filepath.Join(dir, "run")

	// 先通过 Controller 初始化数据库、密钥环并写入一条受保护秘密。
	c, err := controller.New(t.Context(), controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("controller.New: %v", err)
	}
	var ref secrets.Ref
	if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		var serr error
		ref, serr = c.Secrets().Put(t.Context(), tx, "plugin:test", "api_key", []byte("top-secret-token"))
		return serr
	}); err != nil {
		t.Fatalf("Secrets.Put: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("c.Close: %v", err)
	}

	cfgPath := filepath.Join(dir, "qwq.json")
	rawCfg, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(cfgPath, rawCfg, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origEUID := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = origEUID })

	// 1. 保留退役密钥轮换。
	var out1, err1 bytes.Buffer
	code := run([]string{"rotate-master-key", "--config", cfgPath, "--json"}, &out1, &err1)
	if code != 0 {
		t.Fatalf("rotate-master-key exit=%d stderr=%s", code, err1.String())
	}
	var r1 rotateMasterKeyResult
	if err := json.Unmarshal(out1.Bytes(), &r1); err != nil {
		t.Fatalf("decode r1: %v (%s)", err, out1.String())
	}
	if r1.PreviousKeyID == "" || r1.NewKeyID == "" || r1.PreviousKeyID == r1.NewKeyID {
		t.Fatalf("unexpected key IDs: %+v", r1)
	}
	if r1.RewrittenRows < 1 {
		t.Fatalf("rewritten = %d, want >= 1", r1.RewrittenRows)
	}
	if len(r1.DroppedKeys) != 0 || len(r1.RemainingKeys) != 2 {
		t.Fatalf("expected retired key retained, got %+v", r1)
	}

	// 2. 再次轮换并开启 --drop-retired，应安全删除所有已归零的退役密钥。
	var out2, err2 bytes.Buffer
	code = run([]string{"rotate-master-key", "--config", cfgPath, "--drop-retired", "--json"}, &out2, &err2)
	if code != 0 {
		t.Fatalf("rotate-master-key --drop-retired exit=%d stderr=%s", code, err2.String())
	}
	var r2 rotateMasterKeyResult
	if err := json.Unmarshal(out2.Bytes(), &r2); err != nil {
		t.Fatalf("decode r2: %v", err)
	}
	if len(r2.DroppedKeys) != 2 || len(r2.RemainingKeys) != 1 || r2.RemainingKeys[0] != r2.NewKeyID {
		t.Fatalf("expected 2 dropped keys and 1 remaining primary key, got %+v", r2)
	}

	// 3. 重开 Controller 验证秘密仍可正常解密。
	c2, err := controller.New(t.Context(), controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("reopen controller: %v", err)
	}
	defer c2.Close()
	got, err := c2.Secrets().RevealOwned(t.Context(), ref, "plugin:test", "api_key")
	if err != nil {
		t.Fatalf("RevealOwned after rotation: %v", err)
	}
	defer got.Clear()
	if string(got.Bytes()) != "top-secret-token" {
		t.Fatalf("revealed secret mismatch after rotation")
	}
}
