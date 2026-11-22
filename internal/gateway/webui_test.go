// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestShellFallbackPreservesHTTPBoundary(t *testing.T) {
	g := testGateway(t)
	g.MountShell(staticPluginUI("shell bytes"))
	g.MountPluginUI(staticPluginUI("plugin bytes"))
	if response := do(t, g, newRequest(http.MethodGet, "/login", "")); response.code != 200 || string(response.body) != "shell bytes" || response.header.Get("X-Request-Id") == "" {
		t.Fatal("Shell skipped the gateway")
	}
	for _, path := range []string{"/api", "/api/v1/missing", "/plugin-ui/missing", "/p/missing", "/healthz/missing", "/readyz/missing"} {
		if path == "/plugin-ui/missing" {
			continue // 已挂载的插件静态处理器独立分派。
		}
		response := do(t, g, newRequest(http.MethodGet, path, ""))
		if response.code != 404 || response.problem(t).Code != problem.NotFound {
			t.Fatalf("reserved path %s reached the Shell", path)
		}
	}
	request := newRequest(http.MethodGet, "/login", "")
	request.Host = "evil.invalid"
	if response := do(t, g, request); response.code != 403 {
		t.Fatal("Shell accepted an untrusted Host")
	}
	request = newRequest(http.MethodGet, "/login", "")
	request.Header.Set("Origin", "null")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	if response := do(t, g, request); response.code != 403 {
		t.Fatal("plugin opaque-origin allowance leaked to the Shell")
	}
	request = newRequest(http.MethodGet, "/plugin-ui/example/1.0.0/ui/index.html", "")
	request.Header.Set("Origin", "null")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	if response := do(t, g, request); response.code != 200 || string(response.body) != "plugin bytes" {
		t.Fatal("Shell displaced the plugin static mount")
	}
}
