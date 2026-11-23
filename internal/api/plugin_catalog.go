// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

const (
	defaultReleaseMirror     = "https://github.com/hajimilvdou/qwq-panel/releases/download"
	defaultLatestIndexURL    = "https://github.com/hajimilvdou/qwq-panel/releases/latest/download/plugins-index.json"
	pluginCatalogCacheTTL    = 5 * time.Minute
	pluginCatalogFetchLimit  = 1 << 20 // 1 MiB max for plugins-index.json
	pluginCatalogHTTPTimeout = 12 * time.Second
)

var releaseTagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// pluginCatalogItemDTO is one entry in GET /api/v1/plugin-catalog.
type pluginCatalogItemDTO struct {
	PluginID          string   `json:"plugin_id"`
	Name              string   `json:"name"`
	Summary           string   `json:"summary"`
	Version           string   `json:"version"`
	Category          string   `json:"category"`
	MemoryMaxMB       int      `json:"memory_max_mb"`
	Dependencies      []string `json:"dependencies"`
	DownloadURL       string   `json:"download_url"`
	SHA256            string   `json:"sha256,omitempty"`
	Size              int64    `json:"size"`
	Installed         bool     `json:"installed"`
	InstalledVersion  string   `json:"installed_version,omitempty"`
	InstalledRevision string   `json:"installed_revision,omitempty"`
	UpdateAvailable   bool     `json:"update_available"`
}

// pluginCatalogResponseDTO is the response body of GET /api/v1/plugin-catalog.
type pluginCatalogResponseDTO struct {
	Release   string                 `json:"release"`
	Platform  string                 `json:"platform"`
	Source    string                 `json:"source"`
	Online    bool                   `json:"online"`
	FetchedAt string                 `json:"fetched_at"`
	Items     []pluginCatalogItemDTO `json:"items"`
}

// releasePluginsIndex matches the JSON emitted by scripts/release.sh into plugins-index.json.
type releasePluginsIndex struct {
	SchemaVersion   string                      `json:"schema_version"`
	Release         string                      `json:"release"`
	MandatoryBase   []string                    `json:"mandatory_base"`
	OptionalPlugins []releasePluginsIndexRecord `json:"optional_plugins"`
}

type releasePluginsIndexRecord struct {
	ID           string                              `json:"id"`
	Version      string                              `json:"version"`
	Name         string                              `json:"name"`
	Summary      string                              `json:"summary"`
	Dependencies []string                            `json:"dependencies"`
	MemoryMaxMB  int                                 `json:"memory_max_mb"`
	Packages     map[string]releasePluginsIndexAsset `json:"packages"`
}

type releasePluginsIndexAsset struct {
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type cachedPluginCatalog struct {
	mu        sync.Mutex
	release   string
	source    string
	online    bool
	fetchedAt time.Time
	items     []pluginCatalogItemDTO
}

type builtinOfficialPluginMeta struct {
	ID           string
	Name         string
	Summary      string
	Category     string
	MemoryMaxMB  int
	Dependencies []string
}

var officialCatalogDefaults = []builtinOfficialPluginMeta{
	{
		ID:          "monitor.basic",
		Name:        "基础系统监控",
		Summary:     "CPU、内存、磁盘与网络实时趋势微件与历史曲线，轻量常驻（~18 MiB）",
		Category:    "observe",
		MemoryMaxMB: 18,
	},
	{
		ID:          "web.ingress",
		Name:        "反向代理与站点托管",
		Summary:     "内置零依赖 Go 反代网关、Caddy/Nginx 配置渲染、HTTPS 自动续期、大文件上传限额与快照回滚",
		Category:    "network",
		MemoryMaxMB: 32,
	},
	{
		ID:          "tls.certificates",
		Name:        "TLS 证书与 ACME 管理",
		Summary:     "ACME DNS-01 自动签发与泛域名证书集中续期，一键热分发至反代、代理与探针",
		Category:    "security",
		MemoryMaxMB: 24,
	},
	{
		ID:          "domain.dns",
		Name:        "域名与 DNS 解析托管",
		Summary:     "Cloudflare、阿里云等主流 DNS 服务商解析记录管理与证书自动验证支持",
		Category:    "network",
		MemoryMaxMB: 24,
	},
	{
		ID:          "containers.docker",
		Name:        "轻量容器与 Compose 管理",
		Summary:     "五分页容器设置工作台、隔离网络热插拔、无损换端口回滚、一键反代绑域名与受管 Compose 编排",
		Category:    "infra",
		MemoryMaxMB: 32,
	},
	{
		ID:          "server.probe",
		Name:        "服务器探针中心",
		Summary:     "单向安全多机探针、90 天 SLA 与三网延迟曲线、经典与液态水玻璃双风格、支持自定义主题沙箱",
		Category:    "observe",
		MemoryMaxMB: 32,
	},
	{
		ID:          "core.xray",
		Name:        "全协议代理核心驱动",
		Summary:     "托管 Xray 核心与原生硬化 AnyTLS v2（含 UoT）、9 大协议支持、Reality 测速与 WARP 分流",
		Category:    "proxy",
		MemoryMaxMB: 64,
	},
	{
		ID:           "proxy.advanced",
		Name:         "高级代理工作台与订阅中心",
		Summary:      "多用户流量配额、HTB 限速、可视化节点构建器与 Base64/Clash/Sing-box 订阅分发（连带 core.xray）",
		Category:     "proxy",
		MemoryMaxMB:  32,
		Dependencies: []string{"core.xray"},
	},
	{
		ID:          "ai.relay",
		Name:        "AI API 聚合中转站",
		Summary:     "OpenAI / Anthropic / Gemini 协议互转、渠道负载均衡、令牌配额计费与独立自服务门户",
		Category:    "ai",
		MemoryMaxMB: 48,
	},
	{
		ID:          "notify.hub",
		Name:        "统一告警与通知中枢",
		Summary:     "Telegram、飞书、钉钉、企业微信、Discord、SMTP 与签名 Webhook 告警聚合与静默去重",
		Category:    "observe",
		MemoryMaxMB: 24,
	},
}

func officialCategoryFor(pluginID string) string {
	for _, meta := range officialCatalogDefaults {
		if meta.ID == pluginID {
			return meta.Category
		}
	}
	return "other"
}

func hostTargetPlatform() (platform, arch string) {
	arch = runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		arch = "amd64"
	}
	return "linux/" + arch, arch
}

func configuredReleaseMirror() string {
	raw := strings.TrimRight(strings.TrimSpace(os.Getenv("QWQ_RELEASE_MIRROR")), "/")
	if raw != "" {
		if u, err := validateRemotePackageURL(raw); err == nil {
			return strings.TrimRight(u.String(), "/")
		}
	}
	return defaultReleaseMirror
}

func (a *api) getPluginCatalog(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}

	forceRefresh := r.URL.Query().Get("refresh") == "1" || strings.EqualFold(r.URL.Query().Get("refresh"), "true")
	platform, arch := hostTargetPlatform()

	release, source, online, fetchedAt, baseItems := a.loadOfficialPluginCatalog(r.Context(), platform, arch, forceRefresh)

	installedByID := map[string]Plugin{}
	if a.d.Plugins != nil {
		if list, lerr := a.d.Plugins.List(r.Context()); lerr == nil {
			for _, p := range list {
				installedByID[p.PluginID] = p
			}
		}
	}

	items := make([]pluginCatalogItemDTO, 0, len(baseItems))
	for _, item := range baseItems {
		cp := item
		cp.Dependencies = append([]string(nil), item.Dependencies...)
		if cp.Dependencies == nil {
			cp.Dependencies = []string{}
		}
		if inst, ok := installedByID[item.PluginID]; ok {
			cp.Installed = true
			cp.InstalledVersion = inst.ActiveVersion
			if inst.Revision > 0 {
				cp.InstalledRevision = strconv.FormatInt(inst.Revision, 10)
			}
			if cp.Version != "" && inst.ActiveVersion != "" && strings.TrimPrefix(inst.ActiveVersion, "v") != strings.TrimPrefix(cp.Version, "v") {
				cp.UpdateAvailable = true
			}
		}
		items = append(items, cp)
	}

	a.writeResource(w, r, http.StatusOK, pluginCatalogResponseDTO{
		Release:   release,
		Platform:  platform,
		Source:    source,
		Online:    online,
		FetchedAt: fetchedAt.UTC().Format(time.RFC3339),
		Items:     items,
	}, nil)
}

func (a *api) loadOfficialPluginCatalog(
	ctx context.Context,
	platform, arch string,
	forceRefresh bool,
) (release, source string, online bool, fetchedAt time.Time, items []pluginCatalogItemDTO) {
	now := a.d.Clock.Now().UTC()
	if !forceRefresh {
		a.catalogCache.mu.Lock()
		if len(a.catalogCache.items) > 0 && now.Sub(a.catalogCache.fetchedAt) < pluginCatalogCacheTTL {
			release = a.catalogCache.release
			source = a.catalogCache.source
			online = a.catalogCache.online
			fetchedAt = a.catalogCache.fetchedAt
			items = append([]pluginCatalogItemDTO(nil), a.catalogCache.items...)
			a.catalogCache.mu.Unlock()
			return release, source, online, fetchedAt, items
		}
		a.catalogCache.mu.Unlock()
	}

	mirror := configuredReleaseMirror()
	hostVer := strings.TrimSpace(buildinfo.Read().Version)
	if hostVer != "" && !strings.HasPrefix(hostVer, "v") && releaseTagPattern.MatchString("v"+hostVer) {
		hostVer = "v" + hostVer
	}

	candidates := make([]string, 0, 2)
	if releaseTagPattern.MatchString(hostVer) {
		candidates = append(candidates, fmt.Sprintf("%s/%s/plugins-index.json", mirror, hostVer))
	}
	if mirror == defaultReleaseMirror {
		candidates = append(candidates, defaultLatestIndexURL)
	}

	for _, indexURL := range candidates {
		idx, resolvedBase, err := a.fetchRemotePluginsIndex(ctx, indexURL)
		if err != nil {
			continue
		}
		built := buildCatalogItemsFromIndex(idx, resolvedBase, mirror, platform, arch)
		if len(built) == 0 {
			continue
		}
		rel := strings.TrimSpace(idx.Release)
		if rel == "" {
			rel = hostVer
		}
		a.catalogCache.mu.Lock()
		a.catalogCache.release = rel
		a.catalogCache.source = "github_release"
		a.catalogCache.online = true
		a.catalogCache.fetchedAt = now
		a.catalogCache.items = append([]pluginCatalogItemDTO(nil), built...)
		a.catalogCache.mu.Unlock()
		return rel, "github_release", true, now, built
	}

	// Offline / unavailable fallback: return built-in metadata with target release URLs.
	fallbackRel := hostVer
	if !releaseTagPattern.MatchString(fallbackRel) {
		fallbackRel = "latest"
	}
	fallback := buildFallbackCatalogItems(mirror, fallbackRel, arch)
	a.catalogCache.mu.Lock()
	a.catalogCache.release = fallbackRel
	a.catalogCache.source = "builtin_fallback"
	a.catalogCache.online = false
	a.catalogCache.fetchedAt = now
	a.catalogCache.items = append([]pluginCatalogItemDTO(nil), fallback...)
	a.catalogCache.mu.Unlock()
	return fallbackRel, "builtin_fallback", false, now, fallback
}

func (a *api) fetchRemotePluginsIndex(ctx context.Context, rawURL string) (releasePluginsIndex, string, error) {
	targetURL, err := validateRemotePackageURL(rawURL)
	if err != nil {
		return releasePluginsIndex{}, "", err
	}
	fctx, cancel := context.WithTimeout(ctx, pluginCatalogHTTPTimeout)
	defer cancel()

	client := a.packageFetchClient()
	req, err := http.NewRequestWithContext(fctx, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return releasePluginsIndex{}, "", err
	}
	req.Header.Set("User-Agent", "qwq-panel/plugin-catalog")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return releasePluginsIndex{}, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return releasePluginsIndex{}, "", problem.New(problem.Unavailable, "catalog HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, pluginCatalogFetchLimit+1))
	if err != nil {
		return releasePluginsIndex{}, "", err
	}
	if len(body) > pluginCatalogFetchLimit {
		return releasePluginsIndex{}, "", problem.New(problem.Unavailable, "catalog index exceeds size limit")
	}
	var idx releasePluginsIndex
	if err := json.Unmarshal(body, &idx); err != nil {
		return releasePluginsIndex{}, "", err
	}
	resolvedBase := ""
	if resp.Request != nil && resp.Request.URL != nil {
		u := *resp.Request.URL
		if slash := strings.LastIndex(u.Path, "/"); slash > 0 {
			u.Path = u.Path[:slash]
			u.RawQuery = ""
			u.Fragment = ""
			resolvedBase = strings.TrimRight(u.String(), "/")
		}
	}
	return idx, resolvedBase, nil
}

func buildCatalogItemsFromIndex(
	idx releasePluginsIndex,
	resolvedBase, mirror, platform, arch string,
) []pluginCatalogItemDTO {
	rel := strings.TrimSpace(idx.Release)
	baseURL := ""
	if rel != "" && releaseTagPattern.MatchString(rel) {
		baseURL = fmt.Sprintf("%s/%s", strings.TrimRight(mirror, "/"), rel)
	}
	if baseURL == "" {
		baseURL = resolvedBase
	}
	orderMap := make(map[string]int, len(officialCatalogDefaults))
	for i, d := range officialCatalogDefaults {
		orderMap[d.ID] = i
	}

	out := make([]pluginCatalogItemDTO, 0, len(idx.OptionalPlugins))
	for _, rec := range idx.OptionalPlugins {
		pid := strings.TrimSpace(rec.ID)
		if pid == "" {
			continue
		}
		asset, ok := rec.Packages[platform]
		if !ok || strings.TrimSpace(asset.File) == "" {
			// Construct expected filename when arch key is omitted.
			if rel != "" {
				asset.File = fmt.Sprintf("%s-%s-linux-%s.qwqpkg", pid, rel, arch)
			} else {
				continue
			}
		}
		downloadURL := ""
		if baseURL != "" {
			downloadURL = baseURL + "/" + strings.TrimLeft(asset.File, "/")
		}
		deps := make([]string, 0, len(rec.Dependencies))
		for _, dep := range rec.Dependencies {
			if d := strings.TrimSpace(dep); d != "" {
				deps = append(deps, d)
			}
		}
		name := strings.TrimSpace(rec.Name)
		if name == "" {
			name = pid
		}
		out = append(out, pluginCatalogItemDTO{
			PluginID:     pid,
			Name:         name,
			Summary:      strings.TrimSpace(rec.Summary),
			Version:      strings.TrimPrefix(strings.TrimSpace(rec.Version), "v"),
			Category:     officialCategoryFor(pid),
			MemoryMaxMB:  rec.MemoryMaxMB,
			Dependencies: deps,
			DownloadURL:  downloadURL,
			SHA256:       strings.TrimSpace(asset.SHA256),
			Size:         asset.Size,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		oi, okI := orderMap[out[i].PluginID]
		oj, okJ := orderMap[out[j].PluginID]
		if okI && okJ {
			return oi < oj
		}
		if okI != okJ {
			return okI
		}
		return out[i].PluginID < out[j].PluginID
	})
	return out
}

func buildFallbackCatalogItems(mirror, rel, arch string) []pluginCatalogItemDTO {
	cleanVer := strings.TrimPrefix(rel, "v")
	if rel == "latest" {
		cleanVer = ""
	}
	out := make([]pluginCatalogItemDTO, 0, len(officialCatalogDefaults))
	for _, meta := range officialCatalogDefaults {
		downloadURL := ""
		if rel != "" && rel != "latest" {
			downloadURL = fmt.Sprintf("%s/%s/%s-%s-linux-%s.qwqpkg", strings.TrimRight(mirror, "/"), rel, meta.ID, rel, arch)
		}
		deps := append([]string(nil), meta.Dependencies...)
		if deps == nil {
			deps = []string{}
		}
		out = append(out, pluginCatalogItemDTO{
			PluginID:     meta.ID,
			Name:         meta.Name,
			Summary:      meta.Summary,
			Version:      cleanVer,
			Category:     meta.Category,
			MemoryMaxMB:  meta.MemoryMaxMB,
			Dependencies: deps,
			DownloadURL:  downloadURL,
		})
	}
	return out
}
