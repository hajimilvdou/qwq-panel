// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRunPluginBootstrapInstallNoopUpdateAndRejectUntrusted(t *testing.T) {
	dir := t.TempDir()
	secPkg := filepath.Join(dir, "security.basic.qwqpkg")
	monPkg := filepath.Join(dir, "monitor.basic.qwqpkg")
	badPkg := filepath.Join(dir, "untrusted.qwqpkg")
	for _, p := range []string{secPkg, monPkg, badPkg} {
		if err := os.WriteFile(p, []byte("fake-signed-archive"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	installedVer := map[string]string{
		"monitor.basic": "0.1.0",
	}
	var installCalls, updateCalls, closed atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-boot-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/plugin-packages":
			f, hdr, err := r.FormFile("package")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = f.Close()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"upload_id": "upl_" + strings.TrimSuffix(hdr.Filename, ".qwqpkg"),
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/plugin-packages/upl_"):
			name := strings.TrimPrefix(r.URL.Path, "/api/v1/plugin-packages/upl_")
			if name == "untrusted" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"upload_id": "upl_untrusted",
					"signature": map[string]any{"valid": false, "trusted": false, "key_id": "ed25519:dead"},
				})
				return
			}
			ver := "0.1.0"
			if name == "monitor.basic" {
				ver = "0.2.0"
			}
			resp := map[string]any{
				"upload_id": "upl_" + name,
				"signature": map[string]any{"valid": true, "trusted": true, "key_id": "ed25519:ok"},
				"manifest": map[string]any{
					"id":      name,
					"version": ver,
					"capabilities": []map[string]string{
						{"name": "system.firewall.manage", "scope": "self"},
					},
				},
				"compatibility": map[string]any{"ok": true},
			}
			mu.Lock()
			cur, ok := installedVer[name]
			mu.Unlock()
			if ok {
				resp["installed"] = map[string]string{"version": cur, "revision": "rev_1"}
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/plugins":
			installCalls.Add(1)
			mu.Lock()
			installedVer["security.basic"] = "0.1.0"
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"plugin_id":"security.basic","version":"0.1.0"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/plugins/monitor.basic/update":
			updateCalls.Add(1)
			mu.Lock()
			installedVer["monitor.basic"] = "0.2.0"
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"plugin_id":"monitor.basic","to_version":"0.2.0"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	factory := func(_ context.Context, _ string, _ io.Writer) (*bootstrapSession, error) {
		return &bootstrapSession{
			Client:  srv.Client(),
			BaseURL: srv.URL,
			Token:   "test-boot-token",
			Close:   func() { closed.Add(1) },
		}, nil
	}

	// 1. 首次执行：安装 security.basic，升级 monitor.basic
	var out, errBuf bytes.Buffer
	rc := runPluginBootstrap([]string{secPkg, monPkg}, &out, &errBuf, factory)
	if rc != 0 {
		t.Fatalf("first bootstrap rc = %d, stderr = %s", rc, errBuf.String())
	}
	if installCalls.Load() != 1 || updateCalls.Load() != 1 || closed.Load() != 1 {
		t.Fatalf("unexpected counts install=%d update=%d closed=%d", installCalls.Load(), updateCalls.Load(), closed.Load())
	}
	if !strings.Contains(out.String(), "[installed]") || !strings.Contains(out.String(), "[updated]") {
		t.Fatalf("unexpected stdout: %s", out.String())
	}

	// 2. 重复执行：两者均已是最新激活版本，完全幂等 noop！
	out.Reset()
	errBuf.Reset()
	rc = runPluginBootstrap([]string{secPkg, monPkg}, &out, &errBuf, factory)
	if rc != 0 {
		t.Fatalf("second bootstrap rc = %d, stderr = %s", rc, errBuf.String())
	}
	if installCalls.Load() != 1 || updateCalls.Load() != 1 {
		t.Fatalf("repeat bootstrap was not idempotent: install=%d update=%d", installCalls.Load(), updateCalls.Load())
	}
	if strings.Count(out.String(), "[noop_already_active]") != 2 {
		t.Fatalf("expected 2 noop_already_active, got: %s", out.String())
	}

	// 3. 篡改或未受信任签名包必须立即拒绝返回 1
	out.Reset()
	errBuf.Reset()
	rc = runPluginBootstrap([]string{badPkg}, &out, &errBuf, factory)
	if rc != 1 || !strings.Contains(errBuf.String(), "signature verification failed") {
		t.Fatalf("expected signature rejection rc=1, got rc=%d stderr=%s", rc, errBuf.String())
	}
}
