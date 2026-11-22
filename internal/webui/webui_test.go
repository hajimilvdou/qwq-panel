// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// TestEmbeddedBundleServesWhenPresent 验证真实嵌入文件，补充 MapFS 夹具覆盖。
func TestEmbeddedBundleServesWhenPresent(t *testing.T) {
	files, err := fs.Sub(embedded, "dist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(files, "index.html"); err != nil {
		t.Skip("此编译未嵌入 Web 发布产物")
	}
	handler, err := newBundle(files)
	if err != nil {
		t.Fatalf("真实嵌入产物无法加载: %v", err)
	}
	for _, path := range []string{"/login", "/boot.js"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || response.Body.Len() == 0 {
			t.Fatalf("真实嵌入请求 %s 返回 %d", path, response.Code)
		}
	}
}

func testBundle(t *testing.T) (*handler, fstest.MapFS) {
	t.Helper()
	var zipped bytes.Buffer
	writer := gzip.NewWriter(&zipped)
	_, _ = writer.Write([]byte("asset bytes"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	manifest := bundleManifest{CSP: ".csp", Files: map[string]asset{
		"index.html":        {Type: "text/html; charset=utf-8"},
		"assets/app-123.js": {Type: "text/javascript; charset=utf-8", Immutable: true, Brotli: true, Gzip: true},
	}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{
		"manifest.json":        {Data: raw},
		".csp":                 {Data: []byte("default-src 'none'; script-src 'self'; frame-src 'self'; frame-ancestors 'none'\n")},
		"index.html":           {Data: []byte("<html>shell</html>")},
		"assets/app-123.js":    {Data: []byte("asset bytes")},
		"assets/app-123.js.br": {Data: []byte("fixture brotli bytes")},
		"assets/app-123.js.gz": {Data: zipped.Bytes()},
		"unlisted.txt":         {Data: []byte("not public")},
	}
	h, err := newBundle(files)
	if err != nil {
		t.Fatal(err)
	}
	return h, files
}

func TestShellRoutesAndPrivateFiles(t *testing.T) {
	h, _ := testBundle(t)
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/", 200}, {"/login", 200}, {"/apps/monitor.basic", 200},
		{"/plugins/monitor.basic/monitor", 200}, {"/not-a-page", 200},
		{"/.csp", 404}, {"/manifest.json", 404}, {"/unlisted.txt", 404},
		{"/assets/missing.js", 404}, {"/assets/app-123.js.gz", 404},
		{"/../index.html", 404}, {"/assets//app-123.js", 404}, {"/assets/../index.html", 404},
	} {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != test.status {
				t.Fatalf("status %d, want %d", response.Code, test.status)
			}
			if test.status == 200 && (!strings.Contains(response.Header().Get("Content-Security-Policy"), "frame-src 'self'") || response.Header().Get("Cache-Control") != "no-cache") {
				t.Fatal("Shell policy or cache header missing")
			}
		})
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/login", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("Shell accepted a mutation")
	}
}

func TestCompressionHeadRangeAndValidation(t *testing.T) {
	h, _ := testBundle(t)
	request := func(method, encoding string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/assets/app-123.js", nil)
		r.Header.Set("Accept-Encoding", encoding)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, r)
		return response
	}
	for _, test := range []struct{ accept, encoding string }{
		{"br, gzip", "br"}, {"br;q=0, gzip", "gzip"},
		{"br;q=0.2,gzip;q=1", "gzip"}, {"br;q=0,gzip;q=0", ""}, {"gzip;q=invalid", ""},
	} {
		response := request(http.MethodGet, test.accept)
		if response.Code != 200 || response.Header().Get("Content-Encoding") != test.encoding || response.Header().Get("Vary") != "Accept-Encoding" || !strings.Contains(response.Header().Get("Cache-Control"), "immutable") {
			t.Fatalf("negotiation failed for %q", test.accept)
		}
	}
	zipped := request(http.MethodGet, "gzip")
	reader, err := gzip.NewReader(zipped.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(decoded) != "asset bytes" {
		t.Fatal("gzip response does not decode")
	}
	head := request(http.MethodHead, "gzip")
	if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") == "" {
		t.Fatal("HEAD sent a body or omitted its length")
	}
	r := httptest.NewRequest(http.MethodGet, "/assets/app-123.js", nil)
	r.Header.Set("Range", "bytes=0-4")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, r)
	if response.Code != 206 || response.Body.String() != "asset" {
		t.Fatal("range response is invalid")
	}
	r = httptest.NewRequest(http.MethodGet, "/assets/app-123.js", nil)
	r.Header.Set("If-None-Match", request(http.MethodGet, "").Header().Get("ETag"))
	response = httptest.NewRecorder()
	h.ServeHTTP(response, r)
	if response.Code != 304 || response.Body.Len() != 0 {
		t.Fatal("ETag did not revalidate")
	}
	if response := request(http.MethodGet, "*;q=0"); response.Code != 406 {
		t.Fatal("forbidden identity encoding was served")
	}
}

func TestBrokenBundleFailsClosed(t *testing.T) {
	for _, mutate := range []func(fstest.MapFS){
		func(files fstest.MapFS) { delete(files, "index.html") },
		func(files fstest.MapFS) { delete(files, "assets/app-123.js.gz") },
		func(files fstest.MapFS) {
			files[".csp"] = &fstest.MapFile{Data: []byte("script-src 'self'\r\nInjected: value")}
		},
		func(files fstest.MapFS) {
			files["manifest.json"] = &fstest.MapFile{Data: []byte(`{"csp":".csp","files":{"../private":{"type":"text/plain"}}}`)}
		},
		func(files fstest.MapFS) {
			files["manifest.json"].Data = append(files["manifest.json"].Data, []byte(`{}`)...)
		},
	} {
		_, files := testBundle(t)
		mutate(files)
		if _, err := newBundle(files); err == nil {
			t.Fatal("broken bundle was accepted")
		}
	}
}
