// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func buildTestZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func loginTestAdmin(t *testing.T, gw *PortalGateway, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"password": password})
	code, _, resp := gw.ServePortalHTTP("portal", http.MethodPost, "/api/admin/login", "203.0.113.10", nil, body)
	if code != http.StatusOK {
		t.Fatalf("admin login failed: status=%d body=%s", code, string(resp))
	}
	var out struct {
		AdminToken string `json:"admin_token"`
	}
	if err := json.Unmarshal(resp, &out); err != nil || out.AdminToken == "" {
		t.Fatalf("missing admin token: %s", string(resp))
	}
	return out.AdminToken
}

func TestProbeManifestDigestsMatchFiles(t *testing.T) {
	parsed, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatalf("manifest.Parse failed: %v", err)
	}
	for relPath, wantDigest := range parsed.Files {
		if relPath == "bin/plugin" {
			continue
		}
		raw, err := os.ReadFile(relPath)
		if err != nil {
			t.Fatalf("read manifest file %s: %v", relPath, err)
		}
		sum := sha256.Sum256(raw)
		gotDigest := "sha256:" + hex.EncodeToString(sum[:])
		if gotDigest != wantDigest {
			t.Fatalf("digest mismatch for %s: got %s want %s", relPath, gotDigest, wantDigest)
		}
	}
}

func TestThemeZipInstallValidationAndAutoUnwrap(t *testing.T) {
	tm := NewThemeManager(t.TempDir())

	// 1. 合法带单层顶层目录的压缩包自动解包安装
	validZip := buildTestZip(t, map[string][]byte{
		"cyber-pkg/theme.json": []byte(`{
			"id": "my-cyber-theme",
			"name": "Cyberpunk Glass",
			"version": "1.2.0",
			"author": "alice",
			"description": "Neon cyber showcase",
			"api_version": "1",
			"entry": "index.html",
			"settings_schema": [
				{"key": "accent", "label": "强调色", "type": "color", "default": "#38bdf8"}
			]
		}`),
		"cyber-pkg/index.html": []byte(`<!doctype html><html><body>CYBER_CUSTOM_HOME</body></html>`),
		"cyber-pkg/style.css":  []byte(`body { color: cyan; }`),
	})
	m, err := tm.InstallZip(validZip)
	if err != nil {
		t.Fatalf("valid InstallZip failed: %v", err)
	}
	if m.ID != "my-cyber-theme" || m.Version != "1.2.0" || m.Builtin {
		t.Fatalf("unexpected installed manifest: %+v", m)
	}

	// 2. Zip-Slip 路径穿越必须拒绝
	slipZip := buildTestZip(t, map[string][]byte{
		"../escape.html": []byte(`evil`),
		"theme.json":     []byte(`{"id":"slip-test","name":"x","version":"1.0","entry":"index.html"}`),
		"index.html":     []byte(`ok`),
	})
	if _, err := tm.InstallZip(slipZip); !errors.Is(err, ErrThemeZipSlip) {
		t.Fatalf("expected ErrThemeZipSlip, got %v", err)
	}

	// 3. 禁止的可执行/服务端脚本扩展名必须拒绝
	for _, badFile := range []string{"exploit.sh", "backdoor.php", "dropper.exe"} {
		badZip := buildTestZip(t, map[string][]byte{
			"theme.json": []byte(`{"id":"bad-ext","name":"Bad","version":"1.0","entry":"index.html"}`),
			"index.html": []byte(`ok`),
			badFile:      []byte(`#!/bin/sh`),
		})
		if _, err := tm.InstallZip(badZip); !errors.Is(err, ErrThemeDisallowedExt) {
			t.Fatalf("file %s expected ErrThemeDisallowedExt, got %v", badFile, err)
		}
	}

	// 4. 非法主题 ID (builtin: 前缀 / 大写) 必须拒绝
	for _, badID := range []string{"builtin:hijack", "UpperCase", "a"} {
		badIDZip := buildTestZip(t, map[string][]byte{
			"theme.json": []byte(`{"id":"` + badID + `","name":"Bad","version":"1.0","entry":"index.html"}`),
			"index.html": []byte(`ok`),
		})
		if _, err := tm.InstallZip(badIDZip); !errors.Is(err, ErrInvalidThemeManifest) {
			t.Fatalf("id %q expected ErrInvalidThemeManifest, got %v", badID, err)
		}
	}
}

func TestStrictAdminIsolationStarterZipAndFallback(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenProbeStore(dir)
	if err != nil {
		t.Fatalf("OpenProbeStore: %v", err)
	}
	defer store.Close()

	gw := NewPortalGateway(store, NewDomainBindingCoordinator(dir, []byte("seed"), nil, nil), nil, "adm-pass-123", time.Now)
	defer gw.Close()
	admTok := loginTestAdmin(t, gw, "adm-pass-123")
	admHdr := map[string]string{"X-Probe-Admin-Token": admTok}

	// 1. 下载官方 starter.zip 并通过 Content-Type: application/zip 原始二进制上传安装
	code, hdrs, starterBytes := gw.ServePortalHTTP("portal", http.MethodGet, "/api/admin/themes/starter.zip", "203.0.113.10", admHdr, nil)
	if code != http.StatusOK || hdrs["Content-Type"] != "application/zip" || len(starterBytes) < 100 {
		t.Fatalf("starter.zip failed: code=%d hdrs=%+v len=%d", code, hdrs, len(starterBytes))
	}
	rawZipHdr := map[string]string{
		"X-Probe-Admin-Token": admTok,
		"Content-Type":        "application/zip",
		"X-Theme-Filename":    "starter.qwqtheme.zip",
	}
	code, _, uploadResp := gw.ServePortalHTTP("portal", http.MethodPost, "/api/admin/themes/upload", "203.0.113.10", rawZipHdr, starterBytes)
	if code != http.StatusCreated {
		t.Fatalf("upload starter.zip failed: code=%d body=%s", code, string(uploadResp))
	}

	// 2. 安装一个企图冒充 /admin 的自定义主题并激活
	spoofZip := buildTestZip(t, map[string][]byte{
		"theme.json":       []byte(`{"id":"spoof-theme","name":"Spoof","version":"1.0.0","entry":"index.html"}`),
		"index.html":       []byte(`<!doctype html><html><head><title>Spoof</title></head><body>SPOOF_PUBLIC_SHOWCASE</body></html>`),
		"custom.css":       []byte(`body { background: black; }`),
		"admin.html":       []byte(`EVIL_FAKE_ADMIN_ROOT`),
		"admin/index.html": []byte(`EVIL_FAKE_ADMIN_SUB`),
	})
	uploadJSON, _ := json.Marshal(map[string]string{
		"filename":   "spoof.qwqtheme.zip",
		"zip_base64": base64.StdEncoding.EncodeToString(spoofZip),
	})
	code, _, body := gw.ServePortalHTTP("portal", http.MethodPost, "/api/admin/themes/upload", "203.0.113.10", admHdr, uploadJSON)
	if code != http.StatusCreated {
		t.Fatalf("upload spoof theme failed: code=%d body=%s", code, string(body))
	}

	actJSON := []byte(`{"theme_id":"spoof-theme","theme_settings":{"accent":"#00ffaa"}}`)
	code, _, body = gw.ServePortalHTTP("portal", http.MethodPost, "/api/admin/themes/activate", "203.0.113.10", admHdr, actJSON)
	if code != http.StatusOK {
		t.Fatalf("activate spoof-theme failed: code=%d body=%s", code, string(body))
	}

	// 3. 验证不透明源沙箱隔离：/ 返回官方 theme-sandbox.html（iframe sandbox="allow-scripts"），绝不直接在同源输出第三方 HTML/CSS
	code, _, hostHTML := gw.ServePortalHTTP("portal", http.MethodGet, "/", "203.0.113.20", nil, nil)
	if code != http.StatusOK || !strings.Contains(string(hostHTML), `sandbox="allow-scripts"`) || strings.Contains(string(hostHTML), "SPOOF_PUBLIC_SHOWCASE") {
		t.Fatalf("expected official sandbox host HTML at /, got code=%d body=%s", code, string(hostHTML))
	}
	code, _, directCSS := gw.ServePortalHTTP("portal", http.MethodGet, "/custom.css", "203.0.113.20", nil, nil)
	if code != http.StatusNotFound {
		t.Fatalf("custom theme assets must NOT be served outside /theme-frame/*, got code=%d body=%s", code, string(directCSS))
	}
	code, hdrs, frameHTML := gw.ServePortalHTTP("portal", http.MethodGet, "/theme-frame/index.html", "203.0.113.20", nil, nil)
	if code != http.StatusOK || hdrs["X-QWQ-Theme-Sandbox"] != "1" ||
		!strings.Contains(string(frameHTML), `<script src="./__qwq_bridge.js"></script>`) ||
		!strings.Contains(string(frameHTML), "SPOOF_PUBLIC_SHOWCASE") {
		t.Fatalf("expected sandboxed custom HTML with bridge injection, got code=%d hdrs=%+v body=%s", code, hdrs, string(frameHTML))
	}
	code, hdrs, pubCSS := gw.ServePortalHTTP("portal", http.MethodGet, "/theme-frame/custom.css", "203.0.113.20", nil, nil)
	if code != http.StatusOK || hdrs["X-QWQ-Theme-Sandbox"] != "1" || !strings.Contains(hdrs["Content-Type"], "text/css") || !strings.Contains(string(pubCSS), "background: black") {
		t.Fatalf("expected sandboxed custom CSS, got code=%d hdrs=%+v", code, hdrs)
	}
	code, hdrs, bridgeJS := gw.ServePortalHTTP("portal", http.MethodGet, "/theme-frame/__qwq_bridge.js", "203.0.113.20", nil, nil)
	if code != http.StatusOK || hdrs["X-QWQ-Theme-Sandbox"] != "1" || !strings.Contains(string(bridgeJS), "qwq-probe:fetch") {
		t.Fatalf("expected official __qwq_bridge.js, got code=%d hdrs=%+v", code, hdrs)
	}

	// 4. 严格隔离验证：/admin、/admin/、/admin/admin.css、/admin.js 永远由官方内置提供，绝不被自定义主题劫持！
	for _, adminPath := range []string{"/admin", "/admin/", "/admin/index.html"} {
		code, _, adminHTML := gw.ServePortalHTTP("portal", http.MethodGet, adminPath, "203.0.113.20", nil, nil)
		if code != http.StatusOK || !strings.Contains(string(adminHTML), "官方隔离后台") || strings.Contains(string(adminHTML), "EVIL_FAKE_ADMIN") {
			t.Fatalf("admin path %s isolation breached! code=%d", adminPath, code)
		}
	}
	for _, assetPath := range []string{"/admin.css", "/admin/admin.css", "/admin.js", "/admin/admin.js"} {
		code, _, raw := gw.ServePortalHTTP("portal", http.MethodGet, assetPath, "203.0.113.20", nil, nil)
		if code != http.StatusOK || len(raw) == 0 {
			t.Fatalf("admin asset %s failed: code=%d", assetPath, code)
		}
	}

	// 5. 模拟自定义主题目录损坏删除 -> 前台自动无缝降级至官方内置门户
	_ = os.RemoveAll(filepath.Join(dir, "themes", "spoof-theme"))
	code, _, fallbackHTML := gw.ServePortalHTTP("portal", http.MethodGet, "/", "203.0.113.20", nil, nil)
	if code != http.StatusOK || !strings.Contains(string(fallbackHTML), "qwq Probe") {
		t.Fatalf("expected graceful fallback to builtin portal, got code=%d", code)
	}

	// 6. 禁止删除内置主题
	code, _, _ = gw.ServePortalHTTP("portal", http.MethodDelete, "/api/admin/themes/builtin:liquid-glass", "203.0.113.10", admHdr, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("deleting builtin theme must return 400, got %d", code)
	}
}

func TestThemeRemoteURLSSRFBlocked(t *testing.T) {
	dir := t.TempDir()
	store := NewProbeStore()
	gw := NewPortalGateway(store, NewDomainBindingCoordinator(dir, []byte("seed"), nil, nil), nil, "pw", time.Now)
	defer gw.Close()
	admTok := loginTestAdmin(t, gw, "pw")
	admHdr := map[string]string{"X-Probe-Admin-Token": admTok}

	for _, badURL := range []string{
		"http://example.com/theme.zip",
		"https://127.0.0.1/theme.zip",
		"https://169.254.169.254/latest/meta-data/",
		"https://100.64.0.10/theme.zip",
		"https://192.168.1.5/theme.zip",
		"https://user:pass@example.com/theme.zip",
	} {
		payload, _ := json.Marshal(map[string]string{"url": badURL})
		code, _, body := gw.ServePortalHTTP("portal", http.MethodPost, "/api/admin/themes/install-url", "203.0.113.10", admHdr, payload)
		if code != http.StatusBadRequest {
			t.Fatalf("url %s must be blocked with 400, got code=%d body=%s", badURL, code, string(body))
		}
	}
}

func TestWallpaperMagicBytesServeAndSQLitePersistence(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenProbeStore(dir)
	if err != nil {
		t.Fatalf("OpenProbeStore: %v", err)
	}
	gw := NewPortalGateway(store, NewDomainBindingCoordinator(dir, []byte("seed"), nil, nil), nil, "pw", time.Now)
	admTok := loginTestAdmin(t, gw, "pw")
	admHdr := map[string]string{"X-Probe-Admin-Token": admTok}

	// 1. 伪造图片字节必须拒绝（魔数校验）
	fakePayload, _ := json.Marshal(map[string]any{
		"mode":         "local",
		"mime_type":    "image/webp",
		"image_base64": base64.StdEncoding.EncodeToString([]byte("<html><script>alert(1)</script></html>")),
	})
	code, _, _ := gw.ServePortalHTTP("portal", http.MethodPost, "/api/admin/background", "203.0.113.10", admHdr, fakePayload)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("fake image bytes must be rejected with 422, got %d", code)
	}

	// 2. 合法 WebP 魔数上传成功并可通过 GET /api/public/bg 输出
	webpBytes := append([]byte("RIFF\x24\x00\x00\x00WEBP"), make([]byte, 24)...)
	okPayload, _ := json.Marshal(map[string]any{
		"mode":          "local",
		"image_base64":  "data:image/webp;base64," + base64.StdEncoding.EncodeToString(webpBytes),
		"lqip_data_url": "data:image/jpeg;base64,/9j/4AAQ",
		"focal_x":       100,
		"focal_y":       0,
		"luminance":     188,
		"dominant_rgb":  "210,225,240",
	})
	code, _, body := gw.ServePortalHTTP("portal", http.MethodPost, "/api/admin/background", "203.0.113.10", admHdr, okPayload)
	if code != http.StatusOK {
		t.Fatalf("valid WebP upload failed: code=%d body=%s", code, string(body))
	}

	// 启用 Liquid Glass 并保存光学参数
	actPayload := []byte(`{"theme_id":"builtin:liquid-glass","appearance":{"glass_opacity":0.32,"glass_blur_px":24,"glass_tint":"light","veil_opacity":0.28,"motion_enabled":false,"accent_color":"#38bdf8"}}`)
	code, _, body = gw.ServePortalHTTP("portal", http.MethodPost, "/api/admin/themes/activate", "203.0.113.10", admHdr, actPayload)
	if code != http.StatusOK {
		t.Fatalf("activate liquid glass failed: code=%d body=%s", code, string(body))
	}

	// 验证公开壁纸端点响应头与内容
	code, hdrs, gotImg := gw.ServePortalHTTP("portal", http.MethodGet, "/api/public/bg?v=r3", "203.0.113.20", nil, nil)
	if code != http.StatusOK || hdrs["Content-Type"] != "image/webp" || hdrs["X-Content-Type-Options"] != "nosniff" || hdrs["Cache-Control"] != "public, max-age=3600" || !bytes.Equal(gotImg, webpBytes) {
		t.Fatalf("GET /api/public/bg mismatch: code=%d hdrs=%+v len=%d", code, hdrs, len(gotImg))
	}

	// 验证公开快照携带主题、外观、焦点、bg_url 与 admin_path
	code, _, snapRaw := gw.ServePortalHTTP("portal", http.MethodGet, "/api/public/snapshot", "203.0.113.20", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("snapshot failed: %d", code)
	}
	var snap struct {
		ActiveTheme string           `json:"active_theme"`
		BGURL       string           `json:"bg_url"`
		AdminPath   string           `json:"admin_path"`
		Appearance  AppearanceConfig `json:"appearance"`
	}
	if err := json.Unmarshal(snapRaw, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if snap.ActiveTheme != BuiltinThemeLiquidGlass || !strings.HasPrefix(snap.BGURL, "./api/public/bg?v=") || snap.AdminPath != "./admin" ||
		snap.Appearance.GlassBlurPx != 24 || snap.Appearance.Background.FocalX != 100 || snap.Appearance.Background.Luminance != 188 || snap.Appearance.MotionEnabled {
		t.Fatalf("unexpected snapshot appearance payload: %+v", snap)
	}

	// 3. 重启 SQLite 验证持久化完整保留
	_ = gw.Close()
	_ = store.Close()

	reopened, err := OpenProbeStore(dir)
	if err != nil {
		t.Fatalf("reopen probe store: %v", err)
	}
	defer reopened.Close()
	if reopened.settings.ActiveThemeID != BuiltinThemeLiquidGlass || reopened.settings.Appearance.GlassBlurPx != 24 || reopened.settings.Appearance.Background.LocalFile != "bg.webp" {
		t.Fatalf("reopened settings mismatch: %+v", reopened.settings)
	}

	// 4. DELETE /api/admin/background 清除背景
	gw2 := NewPortalGateway(reopened, NewDomainBindingCoordinator(dir, []byte("seed"), nil, nil), nil, "pw", time.Now)
	defer gw2.Close()
	admTok2 := loginTestAdmin(t, gw2, "pw")
	code, _, _ = gw2.ServePortalHTTP("portal", http.MethodDelete, "/api/admin/background", "203.0.113.10", map[string]string{"X-Probe-Admin-Token": admTok2}, nil)
	if code != http.StatusOK {
		t.Fatalf("delete background failed: %d", code)
	}
	code, _, _ = gw2.ServePortalHTTP("portal", http.MethodGet, "/api/public/bg", "203.0.113.20", nil, nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete background, got %d", code)
	}
}

type testJobStream struct {
	ctx      context.Context
	messages []*pb.RunJobResponse
}

func (s *testJobStream) Send(msg *pb.RunJobResponse) error {
	s.messages = append(s.messages, msg)
	return nil
}
func (s *testJobStream) SetHeader(metadata.MD) error  { return nil }
func (s *testJobStream) SendHeader(metadata.MD) error { return nil }
func (s *testJobStream) SetTrailer(metadata.MD)       {}
func (s *testJobStream) Context() context.Context     { return s.ctx }
func (s *testJobStream) SendMsg(any) error            { return nil }
func (s *testJobStream) RecvMsg(any) error            { return nil }

func runProbeJob(t *testing.T, srv *pluginsdk.Server, op string, payload any) []byte {
	t.Helper()
	raw, _ := json.Marshal(payload)
	stream := &testJobStream{ctx: t.Context()}
	if err := srv.RunJob(&pb.RunJobRequest{
		Context:     &pb.RequestContext{InstanceId: "default", NodeId: "local", OperationId: "job-" + op, Locale: "zh-CN"},
		Operation:   op,
		ApiVersion:  "v1",
		PayloadJson: raw,
	}, stream); err != nil {
		t.Fatalf("RunJob(%s) transport error: %v", op, err)
	}
	if len(stream.messages) == 0 || stream.messages[len(stream.messages)-1].GetProgress() == nil {
		t.Fatalf("RunJob(%s) missing terminal progress", op)
	}
	prog := stream.messages[len(stream.messages)-1].GetProgress()
	if prog.GetError() != nil {
		t.Fatalf("RunJob(%s) error: %+v", op, prog.GetError())
	}
	return prog.GetResultJson()
}

func TestThemeAndBackgroundPluginRPCOperations(t *testing.T) {
	srv, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{
		Plugin:             New(),
		Manifest:           Manifest(),
		Registrar:          grpc.NewServer(),
		DefaultGracePeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("pluginsdk.Serve: %v", err)
	}
	t.Cleanup(srv.Close)

	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv.Initialize(t.Context(), &pb.InitializeRequest{
		Context:        rc,
		InstanceHandle: "probe-test-handle",
		DataDir:        t.TempDir(),
		ConfigJson:     []byte(`{"collect_local_host":false}`),
		ConfigRevision: "1",
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := srv.Start(t.Context(), &pb.StartRequest{Context: rc}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// 1. probe.themes.list 应返回内置两种主题
	listResp, err := srv.Invoke(t.Context(), &pb.InvokeRequest{
		Context:     rc,
		Operation:   "probe.themes.list",
		ApiVersion:  "v1",
		PayloadJson: []byte(`{}`),
	})
	if err != nil || listResp.GetError() != nil {
		t.Fatalf("probe.themes.list failed: err=%v respErr=%+v", err, listResp.GetError())
	}
	if !strings.Contains(string(listResp.GetPayloadJson()), BuiltinThemeLiquidGlass) {
		t.Fatalf("expected liquid-glass in themes list: %s", string(listResp.GetPayloadJson()))
	}

	// 2. probe.themes.install 通过 zip_base64 安装自定义主题
	starter, err := BuildStarterThemeZip()
	if err != nil {
		t.Fatalf("BuildStarterThemeZip: %v", err)
	}
	instRes := runProbeJob(t, srv, "probe.themes.install", map[string]any{
		"filename":   "starter.qwqtheme.zip",
		"zip_base64": base64.StdEncoding.EncodeToString(starter),
	})
	if !strings.Contains(string(instRes), "starter-glass-demo") {
		t.Fatalf("unexpected install result: %s", string(instRes))
	}

	// 3. probe.themes.activate 激活并写入 theme_settings
	actRes := runProbeJob(t, srv, "probe.themes.activate", map[string]any{
		"theme_id":       "starter-glass-demo",
		"theme_settings": map[string]any{"accent": "#22d3ee"},
	})
	if !strings.Contains(string(actRes), "starter-glass-demo") {
		t.Fatalf("unexpected activate result: %s", string(actRes))
	}

	// 4. probe.background.set 上传合法 PNG 魔数壁纸
	pngHeader := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 0, 0, 0, 0}
	bgRes := runProbeJob(t, srv, "probe.background.set", map[string]any{
		"mode":         "local",
		"image_base64": base64.StdEncoding.EncodeToString(pngHeader),
		"focal_x":      50,
		"focal_y":      0,
		"luminance":    90,
	})
	if !strings.Contains(string(bgRes), "./api/public/bg?v=") {
		t.Fatalf("unexpected background set result: %s", string(bgRes))
	}

	// 5. probe.themes.delete 卸载自定义主题并自动回退至 builtin:classic
	delRes := runProbeJob(t, srv, "probe.themes.delete", map[string]any{"theme_id": "starter-glass-demo"})
	if !strings.Contains(string(delRes), BuiltinThemeClassic) {
		t.Fatalf("expected fallback to builtin:classic on delete: %s", string(delRes))
	}
}

func TestSanitizeCustomCSSUTF8AndCaseInsensitiveStyleClose(t *testing.T) {
	// 混合大小写 </StYlE> 必须被中和
	got := sanitizeCustomCSS(`body{color:red}</StYlE><script>alert(1)</script></Style>`)
	if strings.Contains(strings.ToLower(got), "</style") {
		t.Fatalf("mixed-case closing style tag not neutralized: %q", got)
	}
	// 超长多字节 UTF-8 截断不得破坏 UTF-8 完整性
	longCJK := strings.Repeat("水玻璃", 3000) // 27000 bytes > 16384
	truncated := sanitizeCustomCSS(longCJK)
	if len(truncated) > 16384 || len(truncated) < 16380 {
		t.Fatalf("unexpected truncated byte length: %d", len(truncated))
	}
	if !strings.HasSuffix(truncated, "水") && !strings.HasSuffix(truncated, "玻") && !strings.HasSuffix(truncated, "璃") {
		t.Fatalf("UTF-8 rune split during truncation")
	}
}
