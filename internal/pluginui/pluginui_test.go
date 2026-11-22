// SPDX-License-Identifier: AGPL-3.0-only

package pluginui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeResolver serves one version of one plugin.
type fakeResolver struct {
	versions map[string]Version
}

func (f fakeResolver) Version(pluginID, version string) (Version, bool) {
	v, ok := f.versions[pluginID+"/"+version]
	return v, ok
}

// writeTree fills dir with the given package files.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o444); err != nil {
			t.Fatal(err)
		}
	}
}

// newTestHandler builds a handler over one published version.
func newTestHandler(t *testing.T) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"ui/index.html":       "<!doctype html><title>plugin</title>",
		"ui/app.js":           "console.log('plugin')",
		"ui/sub/style.css":    "body{color:red}",
		"assets/icon.svg":     "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
		"schemas/config.json": `{"type":"object"}`,
	})
	h := NewHandler(fakeResolver{versions: map[string]Version{
		"acme.plugin/1.2.3": {
			Dir:            dir,
			Icon:           "assets/icon.svg",
			ConnectSources: []string{"https://api.example.com"},
		},
		"plain.plugin/0.1.0": {Dir: dir},
	}})
	return h, dir
}

func do(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestServeUIAndIcon(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := do(t, h, http.MethodGet, "/plugin-ui/acme.plugin/1.2.3/ui/index.html")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>plugin</title>") {
		t.Fatalf("index: %d %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Fatalf("cache-control = %q", cc)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}
	want := "sandbox allow-scripts allow-forms allow-downloads; default-src 'none'; script-src 'self'; " +
		"style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src https://api.example.com; " +
		"frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
	if got := rec.Header().Get("Content-Security-Policy"); got != want {
		t.Fatalf("csp = %q, want %q", got, want)
	}

	rec = do(t, h, http.MethodGet, "/plugin-ui/acme.plugin/1.2.3/ui/app.js")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Fatalf("app.js: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = do(t, h, http.MethodGet, "/plugin-ui/acme.plugin/1.2.3/ui/sub/style.css")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("style.css: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	// The manifest icon is the one file outside ui/ that is served.
	rec = do(t, h, http.MethodGet, "/plugin-ui/acme.plugin/1.2.3/assets/icon.svg")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("icon: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}

	// HEAD answers headers without a body.
	rec = do(t, h, http.MethodHead, "/plugin-ui/acme.plugin/1.2.3/ui/index.html")
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("HEAD: %d body %q", rec.Code, rec.Body.String())
	}
}

func TestServeNoConnectSources(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, "/plugin-ui/plain.plugin/0.1.0/ui/app.js")
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "connect-src 'none';") {
		t.Fatalf("csp = %q", got)
	}
	// A plugin without an icon serves nothing outside ui/.
	if rec := do(t, h, http.MethodGet, "/plugin-ui/plain.plugin/0.1.0/assets/icon.svg"); rec.Code != http.StatusNotFound {
		t.Fatalf("icon without a declaration: %d", rec.Code)
	}
}

func TestServeNotFound(t *testing.T) {
	h, _ := newTestHandler(t)
	cases := []string{
		"/plugin-ui/acme.plugin/1.2.3/schemas/config.json", // outside ui/
		"/plugin-ui/acme.plugin/1.2.3/ui/missing.js",       // missing file
		"/plugin-ui/acme.plugin/1.2.3/ui",                  // directory, not a file
		"/plugin-ui/acme.plugin/9.9.9/ui/index.html",       // unknown version
		"/plugin-ui/ghost/1.2.3/ui/index.html",             // unknown plugin
		"/plugin-ui/acme.plugin/1.2.3/ui/../assets/icon.svg",
		"/plugin-ui/ACME.plugin/1.2.3/ui/index.html", // id grammar
		"/plugin-ui/acme.plugin/../../etc/passwd",
		"/plugin-ui/acme.plugin",  // no version
		"/plugin-ui/acme.plugin/", // no version
	}
	for _, target := range cases {
		if rec := do(t, h, http.MethodGet, target); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, rec.Code)
		}
	}
}

func TestServeRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need a privilege on Windows")
	}
	h, dir := newTestHandler(t)
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "ui", "link.js")); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, http.MethodGet, "/plugin-ui/acme.plugin/1.2.3/ui/link.js")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("symlink = %d, want 404", rec.Code)
	}
}

func TestServeMethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := do(t, h, http.MethodPost, "/plugin-ui/acme.plugin/1.2.3/ui/index.html")
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST = %d allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestSplitPath(t *testing.T) {
	if id, v, rel, ok := splitPath("/plugin-ui/a/1/ui/x/y.js"); !ok || id != "a" || v != "1" || rel != "ui/x/y.js" {
		t.Fatalf("split = %q %q %q %v", id, v, rel, ok)
	}
	for _, bad := range []string{"/plugin-ui/", "/plugin-ui/a", "/plugin-ui/a/1", "/plugin-ui/a/1/", "/other/a/1/ui/x"} {
		if _, _, _, ok := splitPath(bad); ok {
			t.Errorf("splitPath(%q) accepted", bad)
		}
	}
}
