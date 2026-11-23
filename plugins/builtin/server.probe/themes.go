// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

var htmlHeadOpenRe = regexp.MustCompile(`(?i)<head\b[^>]*>`)

const (
	BuiltinThemeClassic     = "builtin:classic"
	BuiltinThemeLiquidGlass = "builtin:liquid-glass"

	MaxThemeZipBytes        = 16 << 20 // 16 MiB 压缩包 / 解压总大小硬上限
	MaxThemeSingleFileBytes = 4 << 20  // 4 MiB 单文件硬上限
	MaxThemeFileCount       = 256      // 最多 256 个静态文件
	MaxBackgroundBytes      = 2 << 20  // 2 MiB 本地壁纸上限
)

var (
	ErrInvalidThemeArchive  = errors.New("INVALID_THEME_ARCHIVE")
	ErrThemeZipSlip         = errors.New("THEME_PATH_TRAVERSAL_REJECTED")
	ErrThemeDisallowedExt   = errors.New("DISALLOWED_FILE_EXTENSION")
	ErrThemeSizeExceeded    = errors.New("THEME_SIZE_LIMIT_EXCEEDED")
	ErrInvalidThemeManifest = errors.New("INVALID_THEME_MANIFEST")
	ErrThemeNotFound        = errors.New("THEME_NOT_FOUND")
	ErrBuiltinThemeLocked   = errors.New("CANNOT_DELETE_BUILTIN_THEME")
	ErrInvalidThemeURL      = errors.New("INVALID_THEME_URL")
	ErrUnsupportedImage     = errors.New("UNSUPPORTED_IMAGE_FORMAT")
)

var allowedThemeExtensions = map[string]string{
	".html":  "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "application/javascript; charset=utf-8",
	".mjs":   "application/javascript; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".webp":  "image/webp",
	".gif":   "image/gif",
	".ico":   "image/x-icon",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".otf":   "font/otf",
	".txt":   "text/plain; charset=utf-8",
	".map":   "application/json; charset=utf-8",
}

// ThemeSettingField 描述主题在 theme.json 中声明的可视化配置项（自动在后台生成表单）。
type ThemeSettingField struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Type        string   `json:"type"` // text | color | number | boolean | select
	Default     any      `json:"default,omitempty"`
	Options     []string `json:"options,omitempty"`
	Description string   `json:"description,omitempty"`
}

// ThemeManifest 是 .qwqtheme.zip 内 theme.json 的标准清单结构。
type ThemeManifest struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Version        string              `json:"version"`
	Author         string              `json:"author,omitempty"`
	Description    string              `json:"description,omitempty"`
	APIVersion     string              `json:"api_version"`
	Entry          string              `json:"entry"`
	SettingsSchema []ThemeSettingField `json:"settings_schema,omitempty"`
	Builtin        bool                `json:"builtin"`
	InstalledAt    int64               `json:"installed_at,omitempty"`
	SizeBytes      int64               `json:"size_bytes,omitempty"`
}

// ThemeManager 管理内置风格、自定义 .qwqtheme.zip 主题包与本地壁纸资产。
type ThemeManager struct {
	mu      sync.RWMutex
	baseDir string
	isTemp  bool
	client  *http.Client
}

func NewThemeManager(dataDir string) *ThemeManager {
	dir := strings.TrimSpace(dataDir)
	isTemp := false
	if dir == "" {
		if tmp, err := os.MkdirTemp("", "qwq-probe-themes-*"); err == nil {
			dir = tmp
			isTemp = true
		}
	}
	return &ThemeManager{
		baseDir: dir,
		isTemp:  isTemp,
		client: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext:         dialVerifiedPublicContext,
				MaxIdleConns:        8,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 8 * time.Second,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 4 {
					return errors.New("too many redirects")
				}
				if req.URL.Scheme != "https" || req.URL.User != nil {
					return ErrInvalidThemeURL
				}
				return nil
			},
		},
	}
}

func (tm *ThemeManager) Close() error {
	if tm != nil && tm.isTemp && tm.baseDir != "" {
		return os.RemoveAll(tm.baseDir)
	}
	return nil
}

func (tm *ThemeManager) themesRoot() string {
	return filepath.Join(tm.baseDir, "themes")
}

func (tm *ThemeManager) assetsRoot() string {
	return filepath.Join(tm.baseDir, "assets")
}

// BuiltinThemes 返回官方内置的两种前台展示风格（永久可用、无法删除）。
func BuiltinThemes() []ThemeManifest {
	return []ThemeManifest{
		{
			ID:          BuiltinThemeClassic,
			Name:        "经典暖润卡片（Classic）",
			Version:     "1.0.0",
			Author:      "qwq official",
			Description: "燕麦奶白与可可深色双模暖润卡片、极简列表与极客 TTY 终端三视图。",
			APIVersion:  "1",
			Entry:       "index.html",
			Builtin:     true,
		},
		{
			ID:          BuiltinThemeLiquidGlass,
			Name:        "动态透明水玻璃（Liquid Glass）",
			Version:     "1.0.0",
			Author:      "qwq official",
			Description: "多层次动态光影水玻璃、LQIP 渐进加载高清壁纸、自适应护眼遮罩与流动性微光折射。",
			APIVersion:  "1",
			Entry:       "index.html",
			Builtin:     true,
		},
	}
}

// ListThemes 返回所有可用主题（内置主题置顶 + 已安装自定义主题按 ID 排序）。
func (tm *ThemeManager) ListThemes() []ThemeManifest {
	out := BuiltinThemes()
	if tm == nil || tm.baseDir == "" {
		return out
	}
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	entries, err := os.ReadDir(tm.themesRoot())
	if err != nil {
		return out
	}
	custom := make([]ThemeManifest, 0, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() || !isValidThemeID(ent.Name()) {
			continue
		}
		m, err := tm.loadCustomManifestLocked(ent.Name())
		if err != nil {
			continue
		}
		custom = append(custom, m)
	}
	slices.SortFunc(custom, func(a, b ThemeManifest) int {
		return strings.Compare(a.ID, b.ID)
	})
	return append(out, custom...)
}

// Exists 检查主题 ID 是否有效且存在（内置或已安装自定义主题）。
func (tm *ThemeManager) Exists(themeID string) bool {
	if themeID == BuiltinThemeClassic || themeID == BuiltinThemeLiquidGlass {
		return true
	}
	if tm == nil || !isValidThemeID(themeID) {
		return false
	}
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	_, err := tm.loadCustomManifestLocked(themeID)
	return err == nil
}

func (tm *ThemeManager) loadCustomManifestLocked(themeID string) (ThemeManifest, error) {
	dir := filepath.Join(tm.themesRoot(), themeID)
	raw, err := os.ReadFile(filepath.Join(dir, "theme.json"))
	if err != nil {
		return ThemeManifest{}, err
	}
	var m ThemeManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return ThemeManifest{}, err
	}
	m.ID = themeID
	m.Builtin = false
	if m.APIVersion == "" {
		m.APIVersion = "1"
	}
	if m.Entry == "" {
		m.Entry = "index.html"
	}
	if info, err := os.Stat(filepath.Join(dir, "theme.json")); err == nil {
		m.InstalledAt = info.ModTime().Unix()
	}
	return m, nil
}

// InstallZip 严格校验并解压安装 .qwqtheme.zip 前台主题包。
func (tm *ThemeManager) InstallZip(zipBytes []byte) (ThemeManifest, error) {
	if tm == nil || tm.baseDir == "" {
		return ThemeManifest{}, errors.New("THEME_STORAGE_UNAVAILABLE")
	}
	if len(zipBytes) == 0 || len(zipBytes) > MaxThemeZipBytes {
		return ThemeManifest{}, fmt.Errorf("%w: archive must be 1..%d bytes", ErrThemeSizeExceeded, MaxThemeZipBytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return ThemeManifest{}, fmt.Errorf("%w: %v", ErrInvalidThemeArchive, err)
	}

	type rawEntry struct {
		cleanPath string
		file      *zip.File
	}
	candidates := make([]rawEntry, 0, len(zr.File))
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		// 跳过 macOS 归档元数据噪音
		if name == "" || strings.HasPrefix(name, "__MACOSX/") || path.Base(name) == ".DS_Store" {
			continue
		}
		if f.FileInfo().IsDir() || strings.HasSuffix(name, "/") {
			if strings.Contains(name, "..") || strings.HasPrefix(name, "/") || strings.Contains(name, ":") {
				return ThemeManifest{}, ErrThemeZipSlip
			}
			continue
		}
		// 严禁符号链接或特殊设备文件
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 || (mode&os.ModeType) != 0 {
			return ThemeManifest{}, fmt.Errorf("%w: symlink or special file %q rejected", ErrThemeZipSlip, name)
		}
		if !isSafeArchiveRelPath(name) {
			return ThemeManifest{}, fmt.Errorf("%w: unsafe path %q", ErrThemeZipSlip, name)
		}
		candidates = append(candidates, rawEntry{cleanPath: name, file: f})
	}
	if len(candidates) == 0 {
		return ThemeManifest{}, fmt.Errorf("%w: archive contains no files", ErrInvalidThemeArchive)
	}

	// 支持单层顶级目录自动解包（如 my-theme/theme.json -> theme.json）
	hasRootManifest := false
	topPrefix := ""
	allSharePrefix := true
	for _, c := range candidates {
		if c.cleanPath == "theme.json" {
			hasRootManifest = true
		}
		seg, _, hasSlash := strings.Cut(c.cleanPath, "/")
		if !hasSlash || seg == "" {
			allSharePrefix = false
		} else if topPrefix == "" {
			topPrefix = seg + "/"
		} else if !strings.HasPrefix(c.cleanPath, topPrefix) {
			allSharePrefix = false
		}
	}
	stripPrefix := ""
	if !hasRootManifest && allSharePrefix && topPrefix != "" {
		stripPrefix = topPrefix
	}

	if len(candidates) > MaxThemeFileCount {
		return ThemeManifest{}, fmt.Errorf("%w: too many files (max %d)", ErrThemeSizeExceeded, MaxThemeFileCount)
	}

	extracted := make(map[string][]byte, len(candidates))
	var totalBytes int64
	for _, c := range candidates {
		rel := strings.TrimPrefix(c.cleanPath, stripPrefix)
		if !isSafeArchiveRelPath(rel) {
			return ThemeManifest{}, fmt.Errorf("%w: unsafe path %q", ErrThemeZipSlip, rel)
		}
		ext := strings.ToLower(path.Ext(rel))
		if _, ok := allowedThemeExtensions[ext]; !ok {
			return ThemeManifest{}, fmt.Errorf("%w: %s (%s)", ErrThemeDisallowedExt, ext, rel)
		}
		if c.file.UncompressedSize64 > MaxThemeSingleFileBytes {
			return ThemeManifest{}, fmt.Errorf("%w: %s exceeds 4 MiB", ErrThemeSizeExceeded, rel)
		}
		rc, err := c.file.Open()
		if err != nil {
			return ThemeManifest{}, fmt.Errorf("%w: cannot read %s", ErrInvalidThemeArchive, rel)
		}
		data, err := io.ReadAll(io.LimitReader(rc, MaxThemeSingleFileBytes+1))
		_ = rc.Close()
		if err != nil {
			return ThemeManifest{}, fmt.Errorf("%w: read error on %s", ErrInvalidThemeArchive, rel)
		}
		if int64(len(data)) > MaxThemeSingleFileBytes {
			return ThemeManifest{}, fmt.Errorf("%w: %s exceeds 4 MiB uncompressed", ErrThemeSizeExceeded, rel)
		}
		totalBytes += int64(len(data))
		if totalBytes > MaxThemeZipBytes {
			return ThemeManifest{}, fmt.Errorf("%w: total uncompressed size exceeds 16 MiB", ErrThemeSizeExceeded)
		}
		extracted[rel] = data
	}

	manifestRaw, ok := extracted["theme.json"]
	if !ok {
		return ThemeManifest{}, fmt.Errorf("%w: missing theme.json", ErrInvalidThemeManifest)
	}
	var manifest ThemeManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return ThemeManifest{}, fmt.Errorf("%w: invalid theme.json: %v", ErrInvalidThemeManifest, err)
	}
	if err := validateThemeManifest(&manifest, extracted); err != nil {
		return ThemeManifest{}, err
	}
	manifest.Builtin = false
	manifest.InstalledAt = time.Now().Unix()
	manifest.SizeBytes = totalBytes

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if err := os.MkdirAll(tm.themesRoot(), 0o750); err != nil {
		return ThemeManifest{}, err
	}
	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	stageDir := filepath.Join(tm.themesRoot(), ".stage-"+manifest.ID+"-"+hex.EncodeToString(rnd))
	if err := os.MkdirAll(stageDir, 0o750); err != nil {
		return ThemeManifest{}, err
	}
	cleanupStage := true
	defer func() {
		if cleanupStage {
			_ = os.RemoveAll(stageDir)
		}
	}()

	for rel, data := range extracted {
		dst := filepath.Join(stageDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return ThemeManifest{}, err
		}
		if err := os.WriteFile(dst, data, 0o640); err != nil {
			return ThemeManifest{}, err
		}
	}

	finalDir := filepath.Join(tm.themesRoot(), manifest.ID)
	_ = os.RemoveAll(finalDir)
	if err := os.Rename(stageDir, finalDir); err != nil {
		return ThemeManifest{}, err
	}
	cleanupStage = false
	return manifest, nil
}

// InstallFromURL 从受防 SSRF 拨号器保护的 HTTPS URL 拉取 .qwqtheme.zip 并安装。
func (tm *ThemeManager) InstallFromURL(ctx context.Context, rawURL string) (ThemeManifest, error) {
	rawURL = strings.TrimSpace(rawURL)
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return ThemeManifest{}, fmt.Errorf("%w: only https:// URLs without credentials are allowed", ErrInvalidThemeURL)
	}
	if err := ValidatePublicProbeTarget(ctx, "https", rawURL, false); err != nil {
		return ThemeManifest{}, fmt.Errorf("%w: %v", ErrSSRFTargetBlocked, err)
	}

	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ThemeManifest{}, fmt.Errorf("%w: %v", ErrInvalidThemeURL, err)
	}
	req.Header.Set("User-Agent", "qwq-server-probe-theme-installer/1.0")
	req.Header.Set("Accept", "application/zip, application/octet-stream, */*")

	resp, err := tm.client.Do(req)
	if err != nil {
		return ThemeManifest{}, fmt.Errorf("THEME_FETCH_FAILED: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ThemeManifest{}, fmt.Errorf("THEME_FETCH_HTTP_%d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxThemeZipBytes+1))
	if err != nil {
		return ThemeManifest{}, fmt.Errorf("THEME_FETCH_READ_FAILED: %v", err)
	}
	if len(data) > MaxThemeZipBytes {
		return ThemeManifest{}, fmt.Errorf("%w: remote zip exceeds 16 MiB", ErrThemeSizeExceeded)
	}
	return tm.InstallZip(data)
}

// DeleteTheme 删除指定的自定义主题目录（严禁删除内置主题）。
func (tm *ThemeManager) DeleteTheme(themeID string) error {
	if strings.HasPrefix(themeID, "builtin:") {
		return ErrBuiltinThemeLocked
	}
	if !isValidThemeID(themeID) {
		return ErrThemeNotFound
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	dir := filepath.Join(tm.themesRoot(), themeID)
	if _, err := os.Stat(dir); err != nil {
		return ErrThemeNotFound
	}
	return os.RemoveAll(dir)
}

// EntryFile 检查自定义主题是否存在且入口 HTML 可读，返回其规范相对入口路径。
func (tm *ThemeManager) EntryFile(themeID string) (string, bool) {
	if tm == nil || !isValidThemeID(themeID) {
		return "", false
	}
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	manifest, err := tm.loadCustomManifestLocked(themeID)
	if err != nil {
		return "", false
	}
	entry := strings.TrimPrefix(manifest.Entry, "/")
	if !isSafeArchiveRelPath(entry) {
		return "", false
	}
	themeDir, err := filepath.Abs(filepath.Join(tm.themesRoot(), themeID))
	if err != nil {
		return "", false
	}
	absPath, err := filepath.Abs(filepath.Join(themeDir, filepath.FromSlash(entry)))
	if err != nil || !strings.HasPrefix(absPath, themeDir+string(filepath.Separator)) {
		return "", false
	}
	info, err := os.Lstat(absPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxThemeSingleFileBytes {
		return "", false
	}
	return entry, true
}

func injectThemeBridgeScript(htmlBytes []byte, relPath string) []byte {
	depth := strings.Count(strings.TrimPrefix(relPath, "/"), "/")
	prefix := "./"
	if depth > 0 {
		prefix = strings.Repeat("../", depth)
	}
	tag := []byte(`<script src="` + prefix + `__qwq_bridge.js"></script>`)
	if loc := htmlHeadOpenRe.FindIndex(htmlBytes); loc != nil {
		out := make([]byte, 0, len(htmlBytes)+len(tag))
		out = append(out, htmlBytes[:loc[1]]...)
		out = append(out, tag...)
		out = append(out, htmlBytes[loc[1]:]...)
		return out
	}
	out := make([]byte, 0, len(tag)+len(htmlBytes))
	out = append(out, tag...)
	out = append(out, htmlBytes...)
	return out
}

// ServeThemeAsset 安全读取当前激活自定义主题的静态文件；若主题损坏/缺失则返回 fallbackToBuiltin=true。
func (tm *ThemeManager) ServeThemeAsset(themeID, cleanSub string) (status int, headers map[string]string, body []byte, fallbackToBuiltin bool) {
	if tm == nil || !isValidThemeID(themeID) {
		return 0, nil, nil, true
	}
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	manifest, err := tm.loadCustomManifestLocked(themeID)
	if err != nil {
		return 0, nil, nil, true
	}
	themeDir, err := filepath.Abs(filepath.Join(tm.themesRoot(), themeID))
	if err != nil {
		return 0, nil, nil, true
	}

	rel := strings.TrimPrefix(cleanSub, "/")
	if rel == "" || strings.HasSuffix(rel, "/") || !strings.Contains(path.Base(rel), ".") {
		rel = manifest.Entry
	}
	if !isSafeArchiveRelPath(rel) {
		return http.StatusNotFound, map[string]string{"Content-Type": "application/json; charset=utf-8"}, []byte(`{"error":"ASSET_NOT_FOUND"}`), false
	}
	ext := strings.ToLower(path.Ext(rel))
	ctype, ok := allowedThemeExtensions[ext]
	if !ok {
		return http.StatusNotFound, map[string]string{"Content-Type": "application/json; charset=utf-8"}, []byte(`{"error":"ASSET_NOT_FOUND"}`), false
	}

	absPath, err := filepath.Abs(filepath.Join(themeDir, filepath.FromSlash(rel)))
	if err != nil || !strings.HasPrefix(absPath, themeDir+string(filepath.Separator)) {
		return http.StatusNotFound, map[string]string{"Content-Type": "application/json; charset=utf-8"}, []byte(`{"error":"ASSET_NOT_FOUND"}`), false
	}
	info, err := os.Lstat(absPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxThemeSingleFileBytes {
		if rel == manifest.Entry {
			return 0, nil, nil, true
		}
		return http.StatusNotFound, map[string]string{"Content-Type": "application/json; charset=utf-8"}, []byte(`{"error":"ASSET_NOT_FOUND"}`), false
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		if rel == manifest.Entry {
			return 0, nil, nil, true
		}
		return http.StatusNotFound, map[string]string{"Content-Type": "application/json; charset=utf-8"}, []byte(`{"error":"ASSET_NOT_FOUND"}`), false
	}

	cacheCtl := "public, max-age=3600"
	if ext == ".html" {
		cacheCtl = "no-cache"
		data = injectThemeBridgeScript(data, rel)
	}
	sum := sha256.Sum256(data)
	return http.StatusOK, map[string]string{
		"Content-Type":        ctype,
		"Cache-Control":       cacheCtl,
		"ETag":                `"` + hex.EncodeToString(sum[:8]) + `"`,
		"X-QWQ-Theme-Sandbox": "1",
	}, data, false
}

// SaveBackground 使用魔数头校验（不信任客户端声明 MIME）将壁纸安全保存至 <DataDir>/assets/bg.<ext>。
func (tm *ThemeManager) SaveBackground(data []byte) (filename, mimeType string, err error) {
	if tm == nil || tm.baseDir == "" {
		return "", "", errors.New("ASSET_STORAGE_UNAVAILABLE")
	}
	if len(data) == 0 || len(data) > MaxBackgroundBytes {
		return "", "", fmt.Errorf("%w: image must be 1..%d bytes", ErrUnsupportedImage, MaxBackgroundBytes)
	}
	switch {
	case len(data) >= 12 && bytes.Equal(data[0:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")):
		filename, mimeType = "bg.webp", "image/webp"
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF:
		filename, mimeType = "bg.jpg", "image/jpeg"
	case len(data) >= 8 && bytes.Equal(data[0:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}):
		filename, mimeType = "bg.png", "image/png"
	default:
		return "", "", fmt.Errorf("%w: only WebP, JPEG, and PNG magic bytes are accepted", ErrUnsupportedImage)
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()
	if err := os.MkdirAll(tm.assetsRoot(), 0o750); err != nil {
		return "", "", err
	}
	for _, old := range []string{"bg.webp", "bg.jpg", "bg.png"} {
		if old != filename {
			_ = os.Remove(filepath.Join(tm.assetsRoot(), old))
		}
	}
	if err := os.WriteFile(filepath.Join(tm.assetsRoot(), filename), data, 0o640); err != nil {
		return "", "", err
	}
	return filename, mimeType, nil
}

// ReadBackground 读取本地已保存壁纸并附带精确 MIME 与 ETag。
func (tm *ThemeManager) ReadBackground(filename string) (data []byte, mimeType, etag string, err error) {
	if tm == nil || tm.baseDir == "" {
		return nil, "", "", os.ErrNotExist
	}
	switch filename {
	case "bg.webp":
		mimeType = "image/webp"
	case "bg.jpg":
		mimeType = "image/jpeg"
	case "bg.png":
		mimeType = "image/png"
	default:
		return nil, "", "", os.ErrNotExist
	}
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	raw, err := os.ReadFile(filepath.Join(tm.assetsRoot(), filename))
	if err != nil {
		return nil, "", "", err
	}
	sum := sha256.Sum256(raw)
	return raw, mimeType, `"` + hex.EncodeToString(sum[:8]) + `"`, nil
}

// DeleteBackground 清除所有本地壁纸文件。
func (tm *ThemeManager) DeleteBackground() {
	if tm == nil || tm.baseDir == "" {
		return
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, name := range []string{"bg.webp", "bg.jpg", "bg.png"} {
		_ = os.Remove(filepath.Join(tm.assetsRoot(), name))
	}
}

// BackgroundURL 计算前端可访问的壁纸 URL（本地壁纸附带 revision 缓存版本）。
func BackgroundURL(cfg PortalSettings) string {
	bg := cfg.Appearance.Background
	switch bg.Mode {
	case "local":
		if bg.LocalFile != "" {
			rev := cfg.Revision
			if rev == "" {
				rev = "r1"
			}
			return "./api/public/bg?v=" + url.QueryEscape(rev)
		}
	case "url":
		return bg.ExternalURL
	}
	return ""
}

// DecodeBase64Payload 支持纯 Base64 或带 data:*;base64, 前缀的数据 URL 解码。
func DecodeBase64Payload(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if idx := strings.Index(s, ";base64,"); idx >= 0 {
		s = s[idx+8:]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("EMPTY_BASE64_PAYLOAD")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// BuildStarterThemeZip 动态打包可直接编辑并重新上传安装的官方起步主题模板 .zip。
func BuildStarterThemeZip() ([]byte, error) {
	files := map[string]string{
		"theme.json": `{
  "id": "starter-glass-demo",
  "name": "起步水玻璃自定义主题",
  "version": "1.0.0",
  "author": "your-name",
  "description": "基于 qwq 公开数据契约与 appearance 光学参数的极简自定义前台主题模板。",
  "api_version": "1",
  "entry": "index.html",
  "settings_schema": [
    { "key": "accent", "label": "品牌强调色", "type": "color", "default": "#38bdf8" },
    { "key": "show_subtitle", "label": "显示站点副标题", "type": "boolean", "default": true }
  ]
}
`,
		"index.html": `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>qwq Custom Probe Theme</title>
  <link rel="stylesheet" href="style.css">
  <script src="app.js" defer></script>
</head>
<body>
  <div id="bg-stage" aria-hidden="true"></div>
  <div id="bg-veil" aria-hidden="true"></div>
  <main class="shell">
    <header class="bar">
      <div>
        <h1 id="title">qwq Probe</h1>
        <p id="subtitle"></p>
      </div>
      <div class="actions">
        <span id="summary" class="chip">加载中…</span>
        <a id="admin-link" class="chip accent" href="./admin">管理后台</a>
      </div>
    </header>
    <section id="grid" class="grid"></section>
  </main>
</body>
</html>
`,
		"style.css": `:root {
  --accent: #38bdf8;
  --glass-opacity: 0.28;
  --glass-blur: 20px;
  --veil-opacity: 0.24;
  --bg-fx: 50%;
  --bg-fy: 50%;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  color: #f8fafc;
  background: #0f172a;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", sans-serif;
}
#bg-stage {
  position: fixed;
  inset: 0;
  z-index: -2;
  background: radial-gradient(circle at 20% 20%, #0ea5e9 0%, transparent 45%),
              radial-gradient(circle at 80% 75%, #8b5cf6 0%, transparent 50%), #0f172a;
  background-size: cover;
  background-position: var(--bg-fx) var(--bg-fy);
}
#bg-veil {
  position: fixed;
  inset: 0;
  z-index: -1;
  background: rgba(15, 23, 42, var(--veil-opacity));
}
.shell { max-width: 1120px; margin: 0 auto; padding: 24px 18px 48px; }
.bar, .node {
  background: rgba(15, 23, 42, var(--glass-opacity));
  backdrop-filter: blur(var(--glass-blur)) saturate(160%);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 18px;
}
.bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  padding: 16px 20px;
  margin-bottom: 18px;
}
.bar h1 { margin: 0; font-size: 20px; }
.bar p { margin: 4px 0 0; font-size: 13px; opacity: 0.8; }
.actions { display: flex; gap: 8px; align-items: center; }
.chip {
  padding: 6px 12px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.14);
  color: inherit;
  text-decoration: none;
  font-size: 12.5px;
  font-weight: 600;
}
.chip.accent { background: var(--accent); color: #0f172a; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(290px, 1fr)); gap: 14px; }
.node { padding: 16px; }
.node-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.metrics { font-size: 13px; opacity: 0.9; line-height: 1.7; }
`,
		"app.js": `(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  async function refresh() {
    try {
      const resp = await fetch('./api/public/snapshot');
      if (!resp.ok) return;
      const snap = await resp.json();
      const root = document.documentElement;
      const app = snap.appearance || {};
      const ts = snap.theme_settings || {};
      if (ts.accent) root.style.setProperty('--accent', ts.accent);
      if (app.glass_opacity) root.style.setProperty('--glass-opacity', String(app.glass_opacity));
      if (Number.isFinite(app.glass_blur_px)) root.style.setProperty('--glass-blur', app.glass_blur_px + 'px');
      if (Number.isFinite(app.veil_opacity)) root.style.setProperty('--veil-opacity', String(app.veil_opacity));
      if (app.background) {
        root.style.setProperty('--bg-fx', (app.background.focal_x ?? 50) + '%');
        root.style.setProperty('--bg-fy', (app.background.focal_y ?? 50) + '%');
      }
      if (snap.bg_url) {
        $('bg-stage').style.backgroundImage = 'url("' + snap.bg_url.replace(/"/g, '%22') + '")';
      }
      $('title').textContent = snap.site_title || 'qwq Probe';
      $('subtitle').textContent = snap.site_subtitle || '';
      $('subtitle').hidden = ts.show_subtitle === false;
      if (snap.admin_path) $('admin-link').setAttribute('href', snap.admin_path);

      const nodes = Array.isArray(snap.nodes) ? snap.nodes : [];
      const up = nodes.filter((n) => n.online).length;
      $('summary').textContent = '在线 ' + up + ' / ' + nodes.length;
      $('grid').innerHTML = nodes.map((n) => {
        const cpu = Number(n.live?.cpu_pct || 0).toFixed(1);
        const rx = (Number(n.live?.net_rx_bps || 0) / 1e6).toFixed(2);
        const tx = (Number(n.live?.net_tx_bps || 0) / 1e6).toFixed(2);
        return '<article class="node">' +
          '<div class="node-top"><strong>[' + esc(n.region_code) + '] ' + esc(n.name) + '</strong>' +
          '<span class="chip">' + (n.online ? '在线' : '离线') + '</span></div>' +
          '<div class="metrics">CPU ' + cpu + '% · ↓ ' + rx + ' Mbps / ↑ ' + tx + ' Mbps<br>' +
          '90天 SLA ' + Number(n.uptime_90d_pct || 100).toFixed(2) + '%</div></article>';
      }).join('');
    } catch {
      // ignore transient network errors
    }
  }
  void refresh();
  setInterval(() => { if (!document.hidden) void refresh(); }, 3000);
})();
`,
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		w, err := zw.Create(k)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(files[k])); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func validateThemeManifest(m *ThemeManifest, files map[string][]byte) error {
	m.ID = strings.TrimSpace(m.ID)
	if !isValidThemeID(m.ID) {
		return fmt.Errorf("%w: invalid theme id %q (must match ^[a-z0-9][a-z0-9._-]{1,47}$)", ErrInvalidThemeManifest, m.ID)
	}
	m.Name = truncateSafe(m.Name, 80)
	if m.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidThemeManifest)
	}
	m.Version = truncateSafe(m.Version, 32)
	if m.Version == "" {
		return fmt.Errorf("%w: version is required", ErrInvalidThemeManifest)
	}
	m.Author = truncateSafe(m.Author, 64)
	m.Description = truncateSafe(m.Description, 240)
	if m.APIVersion == "" {
		m.APIVersion = "1"
	}
	if m.APIVersion != "1" {
		return fmt.Errorf("%w: unsupported api_version %q (expected \"1\")", ErrInvalidThemeManifest, m.APIVersion)
	}
	m.Entry = strings.TrimPrefix(strings.ReplaceAll(strings.TrimSpace(m.Entry), "\\", "/"), "./")
	if m.Entry == "" {
		m.Entry = "index.html"
	}
	if !isSafeArchiveRelPath(m.Entry) || !strings.HasSuffix(strings.ToLower(m.Entry), ".html") {
		return fmt.Errorf("%w: entry must be a safe relative .html path", ErrInvalidThemeManifest)
	}
	if _, ok := files[m.Entry]; !ok {
		return fmt.Errorf("%w: entry file %q not found in archive", ErrInvalidThemeManifest, m.Entry)
	}
	if len(m.SettingsSchema) > 32 {
		return fmt.Errorf("%w: settings_schema max 32 entries", ErrInvalidThemeManifest)
	}
	for idx := range m.SettingsSchema {
		f := &m.SettingsSchema[idx]
		f.Key = strings.TrimSpace(f.Key)
		if !isValidSettingKey(f.Key) {
			return fmt.Errorf("%w: invalid settings_schema key %q", ErrInvalidThemeManifest, f.Key)
		}
		f.Label = truncateSafe(f.Label, 48)
		if f.Label == "" {
			f.Label = f.Key
		}
		switch f.Type {
		case "text", "color", "number", "boolean", "select":
		default:
			return fmt.Errorf("%w: unsupported setting type %q", ErrInvalidThemeManifest, f.Type)
		}
		f.Description = truncateSafe(f.Description, 140)
	}
	return nil
}

func isValidThemeID(id string) bool {
	if len(id) < 2 || len(id) > 48 || strings.HasPrefix(id, "builtin:") || strings.Contains(id, "..") {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		isLowerAlnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i == 0 && !isLowerAlnum {
			return false
		}
		if !isLowerAlnum && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isValidSettingKey(key string) bool {
	if len(key) < 1 || len(key) > 48 {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func isSafeArchiveRelPath(p string) bool {
	if p == "" || len(p) > 240 || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.Contains(p, ":") || strings.ContainsRune(p, 0) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for _, r := range seg {
			if r < 0x20 || r == 0x7f {
				return false
			}
		}
	}
	return true
}
