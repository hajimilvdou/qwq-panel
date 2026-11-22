// SPDX-License-Identifier: AGPL-3.0-only

// Package webui 提供发布包内的 Web Shell；页面和 API 共用宿主信任边界。
package webui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

//go:embed all:dist
var embedded embed.FS

const maxAssetBytes = 8 << 20

type asset struct {
	Type      string `json:"type"`
	Immutable bool   `json:"immutable"`
	Brotli    bool   `json:"br"`
	Gzip      bool   `json:"gz"`
}

type bundleManifest struct {
	CSP   string           `json:"csp"`
	Files map[string]asset `json:"files"`
}

type handler struct {
	files fs.FS
	index map[string]asset
	etags map[string]string
	csp   string
}

// Handler 返回只读嵌入页面。未构建前端时返回稳定的 503，宿主 API 仍可运行。
func Handler() http.Handler {
	files, err := fs.Sub(embedded, "dist")
	if err == nil {
		var h *handler
		h, err = newBundle(files)
		if err == nil {
			return h
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeProblem(w, r, problem.MethodNotAllowed, "The Web Shell is read-only.")
			return
		}
		writeProblem(w, r, problem.Unavailable, "The Web Shell bundle is unavailable.")
	})
}

// ---- 构建清单 --------------------------------------------------------------

func newBundle(files fs.FS) (*handler, error) {
	raw, err := readBounded(files, "manifest.json", 1<<20)
	if err != nil {
		return nil, err
	}
	var manifest bundleManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF || manifest.CSP != ".csp" || len(manifest.Files) == 0 || len(manifest.Files) > 4096 {
		return nil, errors.New("webui: invalid manifest")
	}
	csp, err := readBounded(files, manifest.CSP, 8192)
	if err != nil {
		return nil, err
	}
	policy := strings.TrimSpace(string(csp))
	if policy == "" || strings.ContainsAny(policy, "\r\n\x00") {
		return nil, errors.New("webui: invalid CSP")
	}
	h := &handler{files: files, index: manifest.Files, etags: map[string]string{}, csp: policy}
	if index, ok := h.index["index.html"]; !ok || index.Type != "text/html; charset=utf-8" || index.Immutable {
		return nil, errors.New("webui: missing index")
	}
	for name, item := range h.index {
		if !publicFile(name) || item.Immutable && !strings.HasPrefix(name, "assets/") || strings.ContainsAny(item.Type, "\r\n\x00") {
			return nil, errors.New("webui: invalid asset")
		}
		if _, _, err := mime.ParseMediaType(item.Type); err != nil {
			return nil, errors.New("webui: invalid content type")
		}
		variants := []string{name}
		if item.Brotli {
			variants = append(variants, name+".br")
		}
		if item.Gzip {
			variants = append(variants, name+".gz")
		}
		for _, variant := range variants {
			sum, err := digestFile(files, variant)
			if err != nil {
				return nil, err
			}
			h.etags[variant] = "\"" + sum + "\""
		}
	}
	return h, nil
}

func publicFile(name string) bool {
	if !fs.ValidPath(name) || name == "." || name == "manifest.json" || strings.Contains(name, "..") || strings.ContainsAny(name, "\\\x00") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

func readBounded(files fs.FS, name string, limit int64) ([]byte, error) {
	f, err := files.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("webui: invalid file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("webui: file exceeds bound")
	}
	return data, nil
}

func digestFile(files fs.FS, name string) (string, error) {
	f, err := files.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxAssetBytes {
		return "", errors.New("webui: invalid asset file")
	}
	digest := sha256.New()
	size, err := io.Copy(digest, io.LimitReader(f, maxAssetBytes+1))
	if err != nil || size > maxAssetBytes {
		return "", errors.New("webui: asset exceeds bound")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// ---- 请求处理 --------------------------------------------------------------

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProblem(w, r, problem.MethodNotAllowed, "The Web Shell is read-only.")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if r.URL.Path != "/" && (!publicFile(name) || path.Clean(r.URL.Path) != r.URL.Path) {
		writeProblem(w, r, problem.NotFound, "The requested page was not found.")
		return
	}
	item, ok := h.index[name]
	if !ok {
		if path.Ext(name) != "" && !pageWithResourceID(r.URL.Path) {
			writeProblem(w, r, problem.NotFound, "The requested asset was not found.")
			return
		}
		name, item = "index.html", h.index["index.html"]
	}
	variant, encoding := selectEncoding(name, item, r.Header.Get("Accept-Encoding"))
	if encoding == "unacceptable" {
		http.Error(w, "No acceptable content encoding.", http.StatusNotAcceptable)
		return
	}
	f, err := h.files.Open(variant)
	if err != nil {
		writeProblem(w, r, problem.Unavailable, "The Web Shell asset is unavailable.")
		return
	}
	defer f.Close()
	content, ok := f.(io.ReadSeeker)
	if !ok {
		writeProblem(w, r, problem.Unavailable, "The Web Shell asset is unavailable.")
		return
	}
	info, err := f.Stat()
	if err != nil {
		writeProblem(w, r, problem.Unavailable, "The Web Shell asset is unavailable.")
		return
	}
	head := w.Header()
	head.Set("Content-Type", item.Type)
	head.Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	head.Set("Content-Security-Policy", h.csp)
	head.Set("Referrer-Policy", "no-referrer")
	head.Set("X-Content-Type-Options", "nosniff")
	head.Set("Vary", "Accept-Encoding")
	head.Set("ETag", h.etags[variant])
	head.Set("Cache-Control", "no-cache")
	if item.Immutable {
		head.Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if encoding != "" {
		head.Set("Content-Encoding", encoding)
	}
	http.ServeContent(w, r, name, time.Time{}, content)
}

// pageWithResourceID 保留带点的插件 ID 路由，避免把 /apps/monitor.basic 当成文件。
func pageWithResourceID(p string) bool {
	for _, prefix := range []string{"/apps/", "/plugins/", "/activity/", "/agent/", "/settings/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// selectEncoding 遵守 q=0 拒绝项；质量相同时优先使用构建好的 Brotli。
func selectEncoding(name string, item asset, header string) (string, string) {
	quality := map[string]float64{}
	for _, token := range strings.Split(strings.ToLower(header), ",") {
		parts := strings.Split(token, ";")
		coding, q := strings.TrimSpace(parts[0]), 1.0
		for _, parameter := range parts[1:] {
			key, value, found := strings.Cut(strings.TrimSpace(parameter), "=")
			if key == "q" && found {
				parsed, err := strconv.ParseFloat(value, 64)
				q = 0
				if err == nil && parsed >= 0 && parsed <= 1 {
					q = parsed
				}
			}
		}
		quality[coding] = q
	}
	get := func(coding string) float64 {
		if q, ok := quality[coding]; ok {
			return q
		}
		return quality["*"]
	}
	br, gz := get("br"), get("gzip")
	if item.Brotli && br > 0 && (!item.Gzip || br >= gz) {
		return name + ".br", "br"
	}
	if item.Gzip && gz > 0 {
		return name + ".gz", "gzip"
	}
	if q, ok := quality["identity"]; ok && q == 0 || !ok && quality["*"] == 0 && strings.Contains(header, "*") {
		return "", "unacceptable"
	}
	return name, ""
}

func writeProblem(w http.ResponseWriter, r *http.Request, code problem.Code, detail string) {
	problem.Write(w, problem.New(code, "%s", detail), w.Header().Get("X-Request-Id"), r.URL.Path)
}
