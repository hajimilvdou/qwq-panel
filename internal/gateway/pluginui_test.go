// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"net/http"
	"testing"
)

// staticPluginUI stands in for the plugin static handler.
func staticPluginUI(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
}

// TestPluginUIMountPassesSandboxedFetch: the sandboxed plugin iframe fetches
// its own assets with the opaque origin (Origin: null) and a cross-site
// fetch-metadata header (ADR-0018). The mount must pass those through while
// still enforcing the Host allow-list; nothing else is relaxed.
func TestPluginUIMountPassesSandboxedFetch(t *testing.T) {
	g := testGateway(t)
	g.MountPluginUI(staticPluginUI("plugin bytes"))

	req := newRequest(http.MethodGet, "/plugin-ui/acme.plugin/1.2.3/ui/index.html", "")
	req.Header.Set("Origin", "null")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp := do(t, g, req)
	if resp.code != http.StatusOK || string(resp.body) != "plugin bytes" {
		t.Fatalf("sandboxed fetch = %d %q", resp.code, resp.body)
	}

	// HEAD is tolerated the same way; the mount answers other methods.
	req = newRequest(http.MethodHead, "/plugin-ui/acme.plugin/1.2.3/ui/index.html", "")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp := do(t, g, req); resp.code != http.StatusOK {
		t.Fatalf("HEAD = %d", resp.code)
	}

	// The Host check still applies to the prefix.
	req = newRequest(http.MethodGet, "/plugin-ui/acme.plugin/1.2.3/ui/index.html", "")
	req.Host = "evil.example.com"
	if resp := do(t, g, req); resp.code != http.StatusForbidden {
		t.Fatalf("foreign Host = %d, want 403", resp.code)
	}

	// Outside the prefix the relaxation does not apply.
	req = newRequest(http.MethodGet, "/healthz", "")
	req.Header.Set("Origin", "null")
	if resp := do(t, g, req); resp.code != http.StatusForbidden {
		t.Fatalf("null origin elsewhere = %d, want 403", resp.code)
	}
}

// TestPluginUIUnmounted: without a mount the prefix stays on the fallback.
func TestPluginUIUnmounted(t *testing.T) {
	g := testGateway(t)
	req := newRequest(http.MethodGet, "/plugin-ui/acme.plugin/1.2.3/ui/index.html", "")
	if resp := do(t, g, req); resp.code != http.StatusNotFound {
		t.Fatalf("unmounted prefix = %d, want 404", resp.code)
	}
}
