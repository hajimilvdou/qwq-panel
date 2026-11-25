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
	defaultReleaseMirror          = "https://github.com/hajimilvdou/qwq-panel/releases/download"
	pluginCatalogCacheTTL         = 5 * time.Minute
	pluginCatalogNegativeCacheTTL = 15 * time.Second
	pluginCatalogRefreshCooldown  = 15 * time.Second
	pluginCatalogFetchLimit       = 1 << 20 // 1 MiB max for plugins-index.json
	pluginCatalogHTTPTimeout      = 12 * time.Second
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
	mu               sync.Mutex
	release          string
	source           string
	online           bool
	fetchedAt        time.Time
	lastForceRefresh time.Time
	items            []pluginCatalogItemDTO
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
		ID:          "proxy.advanced",
		Name:        "代理与订阅中心",
		Summary:     "内置 Xray 核心的一站式科学上网工作台：可视化搭建 VLESS Reality / Hysteria2 / Trojan / SS2022 / AnyTLS 节点，多用户流量限速与 Clash / sing-box / Base64 订阅",
		Category:    "proxy",
		MemoryMaxMB: 256,
	},
	{
		ID:          "web.ingress",
		Name:        "反向代理与建站",
		Summary:     "把域名反向代理到本机端口或 Docker 容器、托管静态网站，自动配好 HTTPS 与访问限流",
		Category:    "network",
		MemoryMaxMB: 32,
	},
	{
		ID:          "tls.certificates",
		Name:        "SSL / TLS 证书",
		Summary:     "免费自动申请和续期单域名 / 泛域名 HTTPS 证书，自动同步给反代、代理节点和探针使用",
		Category:    "security",
		MemoryMaxMB: 32,
	},
	{
		ID:          "domain.dns",
		Name:        "域名 DNS 解析",
		Summary:     "直接在面板内管理 Cloudflare、阿里云等域名解析记录，配合自动签发泛域名证书",
		Category:    "network",
		MemoryMaxMB: 32,
	},
	{
		ID:          "containers.docker",
		Name:        "Docker 容器管理",
		Summary:     "可视化管理 Docker 容器、镜像、日志、端口与 Compose 项目，支持一键绑定域名反代",
		Category:    "infra",
		MemoryMaxMB: 32,
	},
	{
		ID:          "server.probe",
		Name:        "多机服务器探针",
		Summary:     "汇总监控多台 VPS 的实时状态、90 天在线率与三网延迟测速，自带公开状态页与自定义主题",
		Category:    "observe",
		MemoryMaxMB: 32,
	},
	{
		ID:          "ai.relay",
		Name:        "AI API 中转站",
		Summary:     "聚合 OpenAI / Claude / Gemini 密钥与订阅账号，支持协议互转、负载均衡与分发额度计费",
		Category:    "ai",
		MemoryMaxMB: 64,
	},
	{
		ID:          "notify.hub",
		Name:        "告警与消息通知",
		Summary:     "把服务器异常、防爆破、证书到期等提醒推送到 Telegram、飞书、钉钉、企业微信或邮箱",
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

func buildCatalogIndexCandidates(mirror, hostVer string) []string {
	mirror = strings.TrimRight(strings.TrimSpace(mirror), "/")
	if mirror == "" {
		return nil
	}
	out := make([]string, 0, 3)
	if releaseTagPattern.MatchString(hostVer) {
		out = append(out, fmt.Sprintf("%s/%s/plugins-index.json", mirror, hostVer))
	}
	if strings.HasSuffix(mirror, "/releases/download") {
		base := strings.TrimSuffix(mirror, "/releases/download")
		out = append(out, base+"/releases/latest/download/plugins-index.json")
	} else {
		out = append(out, mirror+"/latest/plugins-index.json", mirror+"/plugins-index.json")
	}
	return out
}

func (a *api) buildPluginCatalogResponse(ctx context.Context, forceRefresh bool) pluginCatalogResponseDTO {
	platform, arch := hostTargetPlatform()
	release, source, online, fetchedAt, baseItems := a.loadOfficialPluginCatalog(ctx, platform, arch, forceRefresh)

	installedByID := map[string]Plugin{}
	if a.d.Plugins != nil {
		if list, lerr := a.d.Plugins.List(ctx); lerr == nil {
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

	return pluginCatalogResponseDTO{
		Release:   release,
		Platform:  platform,
		Source:    source,
		Online:    online,
		FetchedAt: fetchedAt.UTC().Format(time.RFC3339),
		Items:     items,
	}
}

func (a *api) pluginCatalogSnapshot(ctx context.Context, forceRefresh bool) (any, error) {
	return a.buildPluginCatalogResponse(ctx, forceRefresh), nil
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
	a.writeResource(w, r, http.StatusOK, a.buildPluginCatalogResponse(r.Context(), forceRefresh), nil)
}

func (a *api) loadOfficialPluginCatalog(
	ctx context.Context,
	platform, arch string,
	forceRefresh bool,
) (release, source string, online bool, fetchedAt time.Time, items []pluginCatalogItemDTO) {
	now := a.d.Clock.Now().UTC()
	a.catalogCache.mu.Lock()
	if !forceRefresh {
		ttl := pluginCatalogCacheTTL
		if !a.catalogCache.online {
			ttl = pluginCatalogNegativeCacheTTL
		}
		if len(a.catalogCache.items) > 0 && now.Sub(a.catalogCache.fetchedAt) < ttl {
			release = a.catalogCache.release
			source = a.catalogCache.source
			online = a.catalogCache.online
			fetchedAt = a.catalogCache.fetchedAt
			items = append([]pluginCatalogItemDTO(nil), a.catalogCache.items...)
			a.catalogCache.mu.Unlock()
			return release, source, online, fetchedAt, items
		}
	} else if len(a.catalogCache.items) > 0 && !a.catalogCache.lastForceRefresh.IsZero() &&
		now.Sub(a.catalogCache.lastForceRefresh) < pluginCatalogRefreshCooldown {
		release = a.catalogCache.release
		source = a.catalogCache.source
		online = a.catalogCache.online
		fetchedAt = a.catalogCache.fetchedAt
		items = append([]pluginCatalogItemDTO(nil), a.catalogCache.items...)
		a.catalogCache.mu.Unlock()
		return release, source, online, fetchedAt, items
	} else {
		a.catalogCache.lastForceRefresh = now
	}
	a.catalogCache.mu.Unlock()

	mirror := configuredReleaseMirror()
	hostVer := strings.TrimSpace(buildinfo.Read().Version)
	if hostVer != "" && !strings.HasPrefix(hostVer, "v") && releaseTagPattern.MatchString("v"+hostVer) {
		hostVer = "v" + hostVer
	}

	candidates := buildCatalogIndexCandidates(mirror, hostVer)

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
		if pid == "" || pid == "core.xray" || pid == "monitor.basic" {
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
		if len(deps) == 0 {
			for _, def := range officialCatalogDefaults {
				if def.ID == pid && len(def.Dependencies) > 0 {
					deps = append(deps, def.Dependencies...)
					break
				}
			}
		}
		name := strings.TrimSpace(rec.Name)
		summary := strings.TrimSpace(rec.Summary)
		for _, def := range officialCatalogDefaults {
			if def.ID == pid {
				if def.Name != "" {
					name = def.Name
				}
				if def.Summary != "" {
					summary = def.Summary
				}
				break
			}
		}
		if name == "" {
			name = pid
		}
		out = append(out, pluginCatalogItemDTO{
			PluginID:     pid,
			Name:         name,
			Summary:      summary,
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
