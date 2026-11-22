// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/capability/pluginconfig"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
)

func TestRuntimePluginConfigBackendAndPublicGateway(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(t.Context(), storage.Options{Path: filepath.Join(dir, "qwq.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keys, err := secrets.LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	secStore, err := secrets.New(secrets.Options{DB: db, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}

	pluginsRoot := filepath.Join(dir, "plugins")
	coreSchemaDir := filepath.Join(pluginsRoot, "core.xray", "0.1.0", "schemas")
	if err := os.MkdirAll(coreSchemaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	schema := `{"type":"object","properties":{"token":{"x-secret":true,"writeOnly":true,"anyOf":[{"type":"string"},{"type":"object","properties":{"$secret":{"type":"string"}},"required":["$secret"]}]},"name":{"type":"string"}}}`
	if err := os.WriteFile(filepath.Join(coreSchemaDir, "config.schema.json"), []byte(schema), 0o600); err != nil {
		t.Fatal(err)
	}

	rt, err := NewPluginRuntime(PluginRuntimeOptions{
		Units:       UnitManagerAdapter{Systemctl: &fakeSystemctl{}},
		PluginDir:   PluginDirResolver(pluginsRoot),
		PluginsRoot: pluginsRoot,
		RunDir:      filepath.Join(dir, "run"),
		StateDir:    filepath.Join(dir, "state"),
		Clock:       clock.System{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rt.HasCapabilityService("traffic") || !rt.HasCapabilityService("pluginconfig") {
		t.Fatal("default capability router must register traffic and pluginconfig")
	}

	rt.mu.Lock()
	rt.deps = HostDeps{DB: db, Secrets: secStore}
	rt.mu.Unlock()

	// 先写入一条带已提取密文引用的 core.xray 初始配置
	initialRedacted, _, err := secStore.ExtractSecrets(t.Context(), []byte(schema), []byte(`{"token":"old-secret-value","name":"v1"}`), secrets.ExtractOptions{
		Owner:   "plugins/core.xray",
		Purpose: pluginSecretPurpose,
	})
	if err != nil {
		t.Fatal(err)
	}
	storeAppliedPluginConfig(t, db, "core.xray", 1, string(initialRedacted))

	fwd := pluginconfig.Forwarder{Backend: &runtimePluginConfigBackend{rt: rt}}

	// 1. GetConfig 必须脱敏真实 sec_ 引用
	getRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "pluginconfig",
		Method:  "GetConfig",
		Request: &pluginconfigv1.GetConfigRequest{TargetPluginId: "core.xray"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if getRes.Error != nil {
		t.Fatalf("unexpected GetConfig domain error: %+v", getRes.Error)
	}
	getResp := getRes.Response.(*pluginconfigv1.GetConfigResponse)
	if getResp.GetRevision() != "1" || !strings.Contains(string(getResp.GetRedactedConfigJson()), `"$secret_present":true`) {
		t.Fatalf("unexpected redacted GetConfig: %+v %s", getResp, string(getResp.GetRedactedConfigJson()))
	}

	// 2. PutConfig 使用 $keep_secret 保留原密文并更新非秘密字段
	putRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "pluginconfig",
		Method:  "PutConfig",
		Request: &pluginconfigv1.PutConfigRequest{
			TargetPluginId:   "core.xray",
			ConfigJson:       []byte(`{"token":{"$keep_secret":true},"name":"v2"}`),
			ExpectedRevision: "1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if putRes.Error != nil {
		t.Fatalf("unexpected PutConfig domain error: %+v", putRes.Error)
	}
	putResp := putRes.Response.(*pluginconfigv1.PutConfigResponse)
	if putResp.GetRevision() != "2" {
		t.Fatalf("unexpected PutConfig result: %+v", putResp)
	}

	// 3. PublicGateway 未注册路由返回 404
	rec := httptest.NewRecorder()
	rt.PublicGateway().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/p/proxy.advanced/sub/unknown", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unregistered public route, got %d", rec.Code)
	}
}
