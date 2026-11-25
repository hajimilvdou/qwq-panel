// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
)

func TestPluginCatalogOnlineCacheAndFallback(t *testing.T) {
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		arch = "amd64"
	}
	platform := "linux/" + arch
	var fetchHits atomic.Int32

	indexJSON := `{
  "schema_version": "1.0",
  "release": "v0.1.11",
  "mandatory_base": ["security.basic"],
  "optional_plugins": [
    {
      "id": "proxy.advanced",
      "version": "0.1.11",
      "name": "高级代理工作台",
      "summary": "多用户配额与订阅分发",
      "dependencies": ["core.xray"],
      "memory_max_mb": 32,
      "packages": {
        "` + platform + `": {
          "file": "proxy.advanced-v0.1.11-linux-` + arch + `.qwqpkg",
          "size": 4194304,
          "sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
      }
    },
    {
      "id": "containers.docker",
      "version": "0.1.11",
      "name": "轻量容器管理",
      "summary": "五分页容器设置工作台",
      "dependencies": [],
      "memory_max_mb": 32,
      "packages": {
        "` + platform + `": {
          "file": "containers.docker-v0.1.11-linux-` + arch + `.qwqpkg",
          "size": 3145728,
          "sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      }
    }
  ]
}`

	e := newEnvWith(t, func(d *api.Deps) {
		d.PackageFetchTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			fetchHits.Add(1)
			// Simulate GitHub Releases redirecting plugins-index.json to a signed
			// release-assets.githubusercontent.com blob URL; download_url must
			// still point to the canonical release download base, not the blob host.
			finalReq := r.Clone(r.Context())
			finalReq.URL, _ = finalReq.URL.Parse("https://release-assets.githubusercontent.com/github-production-release-asset/123456/asset-uuid?sig=test")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(indexJSON)),
				Request:    finalReq,
			}, nil
		})
	})
	admin := e.setupAdmin(adminUser)

	// 1. First request fetches online index and returns exact download_url + sha256.
	var cat1 struct {
		Release  string `json:"release"`
		Platform string `json:"platform"`
		Source   string `json:"source"`
		Online   bool   `json:"online"`
		Items    []struct {
			PluginID     string   `json:"plugin_id"`
			Version      string   `json:"version"`
			DownloadURL  string   `json:"download_url"`
			SHA256       string   `json:"sha256"`
			Size         int64    `json:"size"`
			Dependencies []string `json:"dependencies"`
		} `json:"items"`
	}
	res := e.do(admin.sign(http.MethodGet, "/api/v1/plugin-catalog", "")).expect(t, http.StatusOK)
	res.decode(t, &cat1)
	if !cat1.Online || cat1.Source != "github_release" || cat1.Release != "v0.1.11" || cat1.Platform != platform {
		t.Fatalf("unexpected catalog metadata: %+v", cat1)
	}
	if len(cat1.Items) != 2 {
		t.Fatalf("expected 2 catalog items, got %d", len(cat1.Items))
	}
	// Official default order places proxy.advanced first, then containers.docker.
	if cat1.Items[0].PluginID != "proxy.advanced" || cat1.Items[1].PluginID != "containers.docker" {
		t.Fatalf("unexpected item ordering: %+v", cat1.Items)
	}
	wantURL := "https://github.com/hajimilvdou/qwq-panel/releases/download/v0.1.11/containers.docker-v0.1.11-linux-" + arch + ".qwqpkg"
	if cat1.Items[1].DownloadURL != wantURL || cat1.Items[1].Size != 3145728 {
		t.Fatalf("unexpected item[1] download info: got=%q want=%q size=%d", cat1.Items[1].DownloadURL, wantURL, cat1.Items[1].Size)
	}
	if len(cat1.Items[0].Dependencies) != 1 || cat1.Items[0].Dependencies[0] != "core.xray" {
		t.Fatalf("expected index dependencies preserved on item[0], got %+v", cat1.Items[0].Dependencies)
	}
	if fetchHits.Load() != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", fetchHits.Load())
	}

	// 2. Second request serves from 5-minute cache without hitting upstream again.
	e.do(admin.sign(http.MethodGet, "/api/v1/plugin-catalog", "")).expect(t, http.StatusOK)
	if fetchHits.Load() != 1 {
		t.Fatalf("expected cached catalog hit, hits=%d", fetchHits.Load())
	}

	// 3. ?refresh=1 forces re-fetch.
	e.do(admin.sign(http.MethodGet, "/api/v1/plugin-catalog?refresh=1", "")).expect(t, http.StatusOK)
	if fetchHits.Load() != 2 {
		t.Fatalf("expected refresh=1 to re-fetch, hits=%d", fetchHits.Load())
	}

	// 4. Offline failure degrades cleanly to builtin_fallback with all 8 official optional plugins.
	eOff := newEnvWith(t, func(d *api.Deps) {
		d.PackageFetchTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("simulated network offline")
		})
	})
	adminOff := eOff.setupAdmin(adminUser)
	resOff := eOff.do(adminOff.sign(http.MethodGet, "/api/v1/plugin-catalog", "")).expect(t, http.StatusOK)
	var catOff struct {
		Source string            `json:"source"`
		Online bool              `json:"online"`
		Items  []json.RawMessage `json:"items"`
	}
	resOff.decode(t, &catOff)
	if catOff.Online || catOff.Source != "builtin_fallback" || len(catOff.Items) != 8 {
		t.Fatalf("unexpected offline fallback: online=%v source=%q count=%d", catOff.Online, catOff.Source, len(catOff.Items))
	}
}
