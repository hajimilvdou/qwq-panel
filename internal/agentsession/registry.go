// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Official Agent Skills & MCP Server Registry (1C1G-optimized):
//   - Ships an instant curated index of official repositories:
//       1. anthropics/skills           (Anthropic Official Claude Code Agent Skills)
//       2. openai/skills               (OpenAI Official Codex Skills)
//       3. modelcontextprotocol/servers (MCP Official Reference & First-Party Servers)
//   - Supports on-demand live refresh from GitHub API with a 10-minute in-memory
//     TTL cache (bounded < 300 entries, 10s HTTP timeout, 2 MiB body cap).
//   - One-click download & install directly into agent-workspace/skills/<slug>/
//     or agent-workspace/mcp/servers.json.

const (
	registryCacheTTL       = 10 * time.Minute
	registryHTTPTimeout    = 10 * time.Second
	registryMaxBodyBytes   = 2 << 20
	registryMaxSkillBytes  = 512 << 10
	registryMaxCachedItems = 300
)

// RegistrySourceMeta describes one built-in official repository.
type RegistrySourceMeta struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"` // skill | mcp
	Repo        string `json:"repo"` // owner/repo
	URL         string `json:"url"`
	Description string `json:"description"`
}

// RegistryItem describes one searchable, installable official Skill or MCP server.
type RegistryItem struct {
	ID          string          `json:"id"`
	Slug        string          `json:"slug"`
	Kind        string          `json:"kind"` // skill | mcp
	Source      string          `json:"source"`
	SourceName  string          `json:"source_name"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Repo        string          `json:"repo"`
	RepoPath    string          `json:"repo_path,omitempty"`
	RepoURL     string          `json:"repo_url"`
	RawURL      string          `json:"raw_url,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Installed   bool            `json:"installed"`
	MCPTemplate *MCPServerEntry `json:"mcp_template,omitempty"`
}

// RegistryQuery filters GET /api/v1/agent/registry.
type RegistryQuery struct {
	Kind    string // all | skill | mcp
	Source  string
	Query   string
	Refresh bool
}

// RegistrySearchResult is returned by GET /api/v1/agent/registry.
type RegistrySearchResult struct {
	Sources       []RegistrySourceMeta `json:"sources"`
	Items         []RegistryItem       `json:"items"`
	LiveRefreshed bool                 `json:"live_refreshed"`
	CachedAt      string               `json:"cached_at,omitempty"`
}

// RegistryInstallInput is the body of POST /api/v1/agent/registry/install.
type RegistryInstallInput struct {
	ID string `json:"id"`
}

// RegistryInstallResult is returned by POST /api/v1/agent/registry/install.
type RegistryInstallResult struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Installed bool   `json:"installed"`
	Target    string `json:"target"`
	FromLive  bool   `json:"from_live"`
	Message   string `json:"message"`
}

// OfficialRegistrySources lists the built-in official repositories.
var OfficialRegistrySources = []RegistrySourceMeta{
	{
		ID:          "anthropic-skills",
		Name:        "Anthropic Official Skills",
		Kind:        "skill",
		Repo:        "anthropics/skills",
		URL:         "https://github.com/anthropics/skills",
		Description: "Anthropic 官方维护的 Claude Code Agent Skills 标准技能仓库",
	},
	{
		ID:          "openai-skills",
		Name:        "OpenAI Codex Skills",
		Kind:        "skill",
		Repo:        "openai/skills",
		URL:         "https://github.com/openai/skills",
		Description: "OpenAI 官方维护的 Codex 精选技能仓库（skills/.curated）",
	},
	{
		ID:          "mcp-official",
		Name:        "MCP Official Servers",
		Kind:        "mcp",
		Repo:        "modelcontextprotocol/servers",
		URL:         "https://github.com/modelcontextprotocol/servers",
		Description: "Model Context Protocol 官方参考服务与主流官方 MCP 生态",
	},
}

// RegistryManager manages curated + cached live official Skills & MCP catalogs.
type RegistryManager struct {
	ws     *WorkspaceManager
	client *http.Client

	mu        sync.RWMutex
	liveItems []RegistryItem
	fetchedAt time.Time
}

// NewRegistryManager builds a memory-bounded official registry manager.
func NewRegistryManager(ws *WorkspaceManager, client *http.Client) *RegistryManager {
	if client == nil {
		client = &http.Client{Timeout: registryHTTPTimeout}
	}
	return &RegistryManager{ws: ws, client: client}
}

// Search searches built-in and cached live official Skills & MCP servers.
func (r *RegistryManager) Search(ctx context.Context, q RegistryQuery) RegistrySearchResult {
	liveRefreshed := false
	if q.Refresh {
		liveRefreshed = r.refreshLive(ctx)
	}
	r.mu.RLock()
	live := append([]RegistryItem(nil), r.liveItems...)
	cachedAt := r.fetchedAt
	r.mu.RUnlock()

	merged := mergeRegistryItems(curatedOfficialRegistry(), live)

	mcpInstalled := map[string]bool{}
	if r.ws != nil {
		mcpInstalled = r.ws.MCPInstalledSet()
	}

	kindFilter := strings.ToLower(strings.TrimSpace(q.Kind))
	srcFilter := strings.ToLower(strings.TrimSpace(q.Source))
	needle := strings.ToLower(strings.TrimSpace(q.Query))

	out := make([]RegistryItem, 0, len(merged))
	for _, it := range merged {
		if kindFilter != "" && kindFilter != "all" && it.Kind != kindFilter {
			continue
		}
		if srcFilter != "" && srcFilter != "all" && it.Source != srcFilter {
			continue
		}
		if needle != "" {
			hay := strings.ToLower(it.Name + " " + it.Slug + " " + it.Description + " " + it.SourceName + " " + strings.Join(it.Tags, " "))
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		if it.Kind == "skill" && r.ws != nil {
			it.Installed = r.ws.SkillInstalled(it.Slug)
		} else if it.Kind == "mcp" {
			it.Installed = mcpInstalled[it.Slug]
		}
		out = append(out, it)
	}

	res := RegistrySearchResult{
		Sources:       append([]RegistrySourceMeta(nil), OfficialRegistrySources...),
		Items:         out,
		LiveRefreshed: liveRefreshed,
	}
	if !cachedAt.IsZero() {
		res.CachedAt = cachedAt.UTC().Format(time.RFC3339)
	}
	return res
}

// Install downloads and installs an official Skill or MCP server into the workspace.
func (r *RegistryManager) Install(ctx context.Context, id string) (RegistryInstallResult, error) {
	if r.ws == nil || r.ws.RootDir() == "" {
		return RegistryInstallResult{}, problem.New(problem.Unavailable, "Agent workspace directory is not configured.")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return RegistryInstallResult{}, problem.Validation(problem.Violation{Pointer: "/id", Code: "REQUIRED", Message: "Registry item id is required."})
	}

	r.mu.RLock()
	live := append([]RegistryItem(nil), r.liveItems...)
	r.mu.RUnlock()
	all := mergeRegistryItems(curatedOfficialRegistry(), live)

	var found *RegistryItem
	for i := range all {
		if all[i].ID == id {
			cp := all[i]
			found = &cp
			break
		}
	}
	if found == nil {
		return RegistryInstallResult{}, problem.New(problem.NotFound, "Official registry item %q not found.", id)
	}

	if found.Kind == "mcp" {
		if found.MCPTemplate == nil {
			return RegistryInstallResult{}, problem.New(problem.Internal, "MCP template missing for %q.", id)
		}
		tpl := *found.MCPTemplate
		tpl.Enabled = true
		if _, err := r.ws.UpsertMCPServer(tpl); err != nil {
			return RegistryInstallResult{}, err
		}
		return RegistryInstallResult{
			ID:        found.ID,
			Kind:      "mcp",
			Installed: true,
			Target:    "mcp/servers.json",
			FromLive:  false,
			Message:   fmt.Sprintf("已将官方 MCP 服务「%s」写入 mcp/servers.json 并启用", found.Name),
		}, nil
	}

	// Skill installation: try live download from official raw.githubusercontent.com first.
	fromLive := false
	content := ""
	if found.RawURL != "" && isAllowedOfficialRawURL(found.RawURL) {
		if raw, ok := r.fetchText(ctx, found.RawURL, registryMaxSkillBytes); ok && strings.TrimSpace(raw) != "" {
			content = raw
			fromLive = true
		}
	}
	if content == "" {
		content = fmt.Sprintf(`---
name: %s
description: %s
source: %s
---

# %s

%s

> 来源仓库：[%s](%s)
> 说明：当前服务器未能直连 GitHub 原始内容，已生成官方标准 SKILL.md 骨架；您可随时联网后重新下载，或在「Skills 技能目录」内直接编辑或拖拽上传完整技能文件。
`, found.Slug, found.Description, found.RepoURL, found.Name, found.Description, found.Repo, found.RepoURL)
	}
	relTarget := found.Slug + "/SKILL.md"
	if _, err := r.ws.WriteFile(WorkspaceWriteInput{
		Area:    WorkspaceAreaSkills,
		Path:    relTarget,
		Content: content,
	}); err != nil {
		return RegistryInstallResult{}, err
	}
	msg := fmt.Sprintf("已从官方仓库 %s 下载技能「%s」到 skills/%s", found.Repo, found.Name, relTarget)
	if !fromLive {
		msg = fmt.Sprintf("已安装技能「%s」到 skills/%s（离线标准模板，联网后可重新同步上游）", found.Name, relTarget)
	}
	return RegistryInstallResult{
		ID:        found.ID,
		Kind:      "skill",
		Installed: true,
		Target:    "skills/" + relTarget,
		FromLive:  fromLive,
		Message:   msg,
	}, nil
}

func isAllowedOfficialRawURL(u string) bool {
	return strings.HasPrefix(u, "https://raw.githubusercontent.com/anthropics/skills/") ||
		strings.HasPrefix(u, "https://raw.githubusercontent.com/openai/skills/") ||
		strings.HasPrefix(u, "https://raw.githubusercontent.com/modelcontextprotocol/servers/")
}

func (r *RegistryManager) fetchText(ctx context.Context, targetURL string, maxBytes int64) (string, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, registryHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "qwq-panel-registry/1.0")
	req.Header.Set("Accept", "application/vnd.github+json, text/plain, */*")
	resp, err := r.client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", false
	}
	return string(b), true
}

func (r *RegistryManager) refreshLive(ctx context.Context) bool {
	r.mu.RLock()
	fresh := !r.fetchedAt.IsZero() && time.Since(r.fetchedAt) < registryCacheTTL && len(r.liveItems) > 0
	r.mu.RUnlock()
	if fresh {
		return true
	}

	type repoFetch struct {
		sourceID   string
		sourceName string
		repo       string
		dirPath    string
	}
	targets := []repoFetch{
		{sourceID: "anthropic-skills", sourceName: "Anthropic Official Skills", repo: "anthropics/skills", dirPath: "skills"},
		{sourceID: "openai-skills", sourceName: "OpenAI Codex Skills", repo: "openai/skills", dirPath: "skills/.curated"},
	}

	var fetched []RegistryItem
	anyOK := false
	for _, t := range targets {
		apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", t.repo, t.dirPath)
		raw, ok := r.fetchText(ctx, apiURL, registryMaxBodyBytes)
		if !ok {
			continue
		}
		var entries []struct {
			Name    string `json:"name"`
			Path    string `json:"path"`
			Type    string `json:"type"`
			HTMLURL string `json:"html_url"`
		}
		if json.Unmarshal([]byte(raw), &entries) != nil {
			continue
		}
		anyOK = true
		for _, e := range entries {
			if e.Type != "dir" || strings.HasPrefix(e.Name, ".") {
				continue
			}
			slug := FormatSlug(e.Name)
			fetched = append(fetched, RegistryItem{
				ID:          t.sourceID + ":" + slug,
				Slug:        slug,
				Kind:        "skill",
				Source:      t.sourceID,
				SourceName:  t.sourceName,
				Name:        e.Name,
				Description: fmt.Sprintf("来自官方仓库 %s (%s) 的标准 Agent Skill", t.repo, e.Path),
				Repo:        t.repo,
				RepoPath:    e.Path,
				RepoURL:     e.HTMLURL,
				RawURL:      fmt.Sprintf("https://raw.githubusercontent.com/%s/main/%s/SKILL.md", t.repo, e.Path),
				Tags:        []string{"official", t.sourceID},
			})
			if len(fetched) >= registryMaxCachedItems {
				break
			}
		}
	}

	if anyOK {
		r.mu.Lock()
		r.liveItems = fetched
		r.fetchedAt = time.Now().UTC()
		r.mu.Unlock()
	}
	return anyOK
}

func mergeRegistryItems(base, live []RegistryItem) []RegistryItem {
	byID := make(map[string]RegistryItem, len(base)+len(live))
	order := make([]string, 0, len(base)+len(live))
	for _, it := range base {
		byID[it.ID] = it
		order = append(order, it.ID)
	}
	for _, it := range live {
		if _, exists := byID[it.ID]; !exists {
			byID[it.ID] = it
			order = append(order, it.ID)
		}
	}
	out := make([]RegistryItem, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func curatedOfficialRegistry() []RegistryItem {
	return []RegistryItem{
		// ── Anthropic Official Agent Skills (anthropics/skills) ──
		{
			ID:          "anthropic-skills:skill-creator",
			Slug:        "skill-creator",
			Kind:        "skill",
			Source:      "anthropic-skills",
			SourceName:  "Anthropic Official Skills",
			Name:        "skill-creator",
			Description: "Anthropic 官方技能创建规范：指导 Agent 编写高质量 SKILL.md、脚本与触发条件",
			Repo:        "anthropics/skills",
			RepoPath:    "skills/skill-creator",
			RepoURL:     "https://github.com/anthropics/skills/tree/main/skills/skill-creator",
			RawURL:      "https://raw.githubusercontent.com/anthropics/skills/main/skills/skill-creator/SKILL.md",
			Tags:        []string{"claude-code", "authoring", "official"},
		},
		{
			ID:          "anthropic-skills:mcp-builder",
			Slug:        "mcp-builder",
			Kind:        "skill",
			Source:      "anthropic-skills",
			SourceName:  "Anthropic Official Skills",
			Name:        "mcp-builder",
			Description: "Anthropic 官方 MCP 构建技能：设计、开发与测试高质量 Model Context Protocol 服务",
			Repo:        "anthropics/skills",
			RepoPath:    "skills/mcp-builder",
			RepoURL:     "https://github.com/anthropics/skills/tree/main/skills/mcp-builder",
			RawURL:      "https://raw.githubusercontent.com/anthropics/skills/main/skills/mcp-builder/SKILL.md",
			Tags:        []string{"claude-code", "mcp", "official"},
		},
		{
			ID:          "anthropic-skills:webapp-testing",
			Slug:        "webapp-testing",
			Kind:        "skill",
			Source:      "anthropic-skills",
			SourceName:  "Anthropic Official Skills",
			Name:        "webapp-testing",
			Description: "Anthropic 官方 Web 应用自动化测试技能（Playwright 本地探测、截图与日志排查）",
			Repo:        "anthropics/skills",
			RepoPath:    "skills/webapp-testing",
			RepoURL:     "https://github.com/anthropics/skills/tree/main/skills/webapp-testing",
			RawURL:      "https://raw.githubusercontent.com/anthropics/skills/main/skills/webapp-testing/SKILL.md",
			Tags:        []string{"claude-code", "testing", "playwright"},
		},
		{
			ID:          "anthropic-skills:frontend-design",
			Slug:        "frontend-design",
			Kind:        "skill",
			Source:      "anthropic-skills",
			SourceName:  "Anthropic Official Skills",
			Name:        "frontend-design",
			Description: "Anthropic 官方高审美前端界面设计技能，避免模板化 AI 风格",
			Repo:        "anthropics/skills",
			RepoPath:    "skills/frontend-design",
			RepoURL:     "https://github.com/anthropics/skills/tree/main/skills/frontend-design",
			RawURL:      "https://raw.githubusercontent.com/anthropics/skills/main/skills/frontend-design/SKILL.md",
			Tags:        []string{"claude-code", "ui", "frontend"},
		},
		{
			ID:          "anthropic-skills:pdf",
			Slug:        "pdf",
			Kind:        "skill",
			Source:      "anthropic-skills",
			SourceName:  "Anthropic Official Skills",
			Name:        "pdf",
			Description: "Anthropic 官方 PDF 文档提取、合并、拆分、表单填写与生成技能",
			Repo:        "anthropics/skills",
			RepoPath:    "skills/pdf",
			RepoURL:     "https://github.com/anthropics/skills/tree/main/skills/pdf",
			RawURL:      "https://raw.githubusercontent.com/anthropics/skills/main/skills/pdf/SKILL.md",
			Tags:        []string{"claude-code", "documents", "pdf"},
		},
		{
			ID:          "anthropic-skills:docx",
			Slug:        "docx",
			Kind:        "skill",
			Source:      "anthropic-skills",
			SourceName:  "Anthropic Official Skills",
			Name:        "docx",
			Description: "Anthropic 官方 Word (.docx) 读写、修订与排版处理技能",
			Repo:        "anthropics/skills",
			RepoPath:    "skills/docx",
			RepoURL:     "https://github.com/anthropics/skills/tree/main/skills/docx",
			RawURL:      "https://raw.githubusercontent.com/anthropics/skills/main/skills/docx/SKILL.md",
			Tags:        []string{"claude-code", "documents", "word"},
		},

		// ── OpenAI Official Codex Skills (openai/skills) ──
		{
			ID:          "openai-skills:security-best-practices",
			Slug:        "security-best-practices",
			Kind:        "skill",
			Source:      "openai-skills",
			SourceName:  "OpenAI Codex Skills",
			Name:        "security-best-practices",
			Description: "OpenAI 官方安全审查最佳实践技能：系统性排查漏洞与加固代码及配置",
			Repo:        "openai/skills",
			RepoPath:    "skills/.curated/security-best-practices",
			RepoURL:     "https://github.com/openai/skills/tree/main/skills/.curated/security-best-practices",
			RawURL:      "https://raw.githubusercontent.com/openai/skills/main/skills/.curated/security-best-practices/SKILL.md",
			Tags:        []string{"codex", "security", "audit"},
		},
		{
			ID:          "openai-skills:gh-fix-ci",
			Slug:        "gh-fix-ci",
			Kind:        "skill",
			Source:      "openai-skills",
			SourceName:  "OpenAI Codex Skills",
			Name:        "gh-fix-ci",
			Description: "OpenAI 官方 GitHub Actions CI 故障自动排查与修复技能",
			Repo:        "openai/skills",
			RepoPath:    "skills/.curated/gh-fix-ci",
			RepoURL:     "https://github.com/openai/skills/tree/main/skills/.curated/gh-fix-ci",
			RawURL:      "https://raw.githubusercontent.com/openai/skills/main/skills/.curated/gh-fix-ci/SKILL.md",
			Tags:        []string{"codex", "github", "ci"},
		},
		{
			ID:          "openai-skills:playwright",
			Slug:        "playwright",
			Kind:        "skill",
			Source:      "openai-skills",
			SourceName:  "OpenAI Codex Skills",
			Name:        "playwright",
			Description: "OpenAI 官方 Playwright 浏览器自动化与端到端页面核验技能",
			Repo:        "openai/skills",
			RepoPath:    "skills/.curated/playwright",
			RepoURL:     "https://github.com/openai/skills/tree/main/skills/.curated/playwright",
			RawURL:      "https://raw.githubusercontent.com/openai/skills/main/skills/.curated/playwright/SKILL.md",
			Tags:        []string{"codex", "browser", "testing"},
		},
		{
			ID:          "openai-skills:cloudflare-deploy",
			Slug:        "cloudflare-deploy",
			Kind:        "skill",
			Source:      "openai-skills",
			SourceName:  "OpenAI Codex Skills",
			Name:        "cloudflare-deploy",
			Description: "OpenAI 官方 Cloudflare Workers / Pages 部署与 DNS 排障技能",
			Repo:        "openai/skills",
			RepoPath:    "skills/.curated/cloudflare-deploy",
			RepoURL:     "https://github.com/openai/skills/tree/main/skills/.curated/cloudflare-deploy",
			RawURL:      "https://raw.githubusercontent.com/openai/skills/main/skills/.curated/cloudflare-deploy/SKILL.md",
			Tags:        []string{"codex", "cloudflare", "deploy"},
		},

		// ── MCP Official Reference & First-Party Servers (modelcontextprotocol/servers) ──
		{
			ID:          "mcp-official:fetch",
			Slug:        "fetch",
			Kind:        "mcp",
			Source:      "mcp-official",
			SourceName:  "MCP Official Servers",
			Name:        "MCP Fetch (网页抓取与 Markdown 转换)",
			Description: "MCP 官方参考服务：安全抓取网页内容并转为适合大模型阅读的 Markdown",
			Repo:        "modelcontextprotocol/servers",
			RepoPath:    "src/fetch",
			RepoURL:     "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch",
			Tags:        []string{"mcp", "web", "http"},
			MCPTemplate: &MCPServerEntry{
				ID:          "fetch",
				Name:        "MCP Fetch",
				Description: "官方网页抓取与 Markdown 转换服务",
				Transport:   "stdio",
				Command:     "uvx",
				Args:        []string{"mcp-server-fetch"},
				Enabled:     true,
				Source:      "modelcontextprotocol/servers",
			},
		},
		{
			ID:          "mcp-official:filesystem",
			Slug:        "filesystem",
			Kind:        "mcp",
			Source:      "mcp-official",
			SourceName:  "MCP Official Servers",
			Name:        "MCP Filesystem (受限目录文件读写)",
			Description: "MCP 官方参考服务：在白名单目录范围内安全读写和搜索文件",
			Repo:        "modelcontextprotocol/servers",
			RepoPath:    "src/filesystem",
			RepoURL:     "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
			Tags:        []string{"mcp", "files", "official"},
			MCPTemplate: &MCPServerEntry{
				ID:          "filesystem",
				Name:        "MCP Filesystem",
				Description: "官方白名单目录文件读写服务",
				Transport:   "stdio",
				Command:     "npx",
				Args:        []string{"-y", "@modelcontextprotocol/server-filesystem", "/srv"},
				Enabled:     true,
				Source:      "modelcontextprotocol/servers",
			},
		},
		{
			ID:          "mcp-official:git",
			Slug:        "git",
			Kind:        "mcp",
			Source:      "mcp-official",
			SourceName:  "MCP Official Servers",
			Name:        "MCP Git (代码仓库检索与 Diff)",
			Description: "MCP 官方参考服务：查看 Git 仓库状态、日志、分支与代码差异",
			Repo:        "modelcontextprotocol/servers",
			RepoPath:    "src/git",
			RepoURL:     "https://github.com/modelcontextprotocol/servers/tree/main/src/git",
			Tags:        []string{"mcp", "git", "code"},
			MCPTemplate: &MCPServerEntry{
				ID:          "git",
				Name:        "MCP Git",
				Description: "官方 Git 仓库管理与分析服务",
				Transport:   "stdio",
				Command:     "uvx",
				Args:        []string{"mcp-server-git"},
				Enabled:     true,
				Source:      "modelcontextprotocol/servers",
			},
		},
		{
			ID:          "mcp-official:memory",
			Slug:        "memory",
			Kind:        "mcp",
			Source:      "mcp-official",
			SourceName:  "MCP Official Servers",
			Name:        "MCP Memory (跨会话知识图谱记忆)",
			Description: "MCP 官方参考服务：为 Agent 提供持久化实体关系记忆库",
			Repo:        "modelcontextprotocol/servers",
			RepoPath:    "src/memory",
			RepoURL:     "https://github.com/modelcontextprotocol/servers/tree/main/src/memory",
			Tags:        []string{"mcp", "memory", "knowledge"},
			MCPTemplate: &MCPServerEntry{
				ID:          "memory",
				Name:        "MCP Memory",
				Description: "官方知识图谱持久化记忆服务",
				Transport:   "stdio",
				Command:     "npx",
				Args:        []string{"-y", "@modelcontextprotocol/server-memory"},
				Enabled:     true,
				Source:      "modelcontextprotocol/servers",
			},
		},
		{
			ID:          "mcp-official:sequentialthinking",
			Slug:        "sequentialthinking",
			Kind:        "mcp",
			Source:      "mcp-official",
			SourceName:  "MCP Official Servers",
			Name:        "MCP Sequential Thinking (分步深度推理)",
			Description: "MCP 官方参考服务：结构化分步推理、反思与复杂排障拆解",
			Repo:        "modelcontextprotocol/servers",
			RepoPath:    "src/sequentialthinking",
			RepoURL:     "https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking",
			Tags:        []string{"mcp", "reasoning", "planning"},
			MCPTemplate: &MCPServerEntry{
				ID:          "sequentialthinking",
				Name:        "MCP Sequential Thinking",
				Description: "官方结构化深度推理服务",
				Transport:   "stdio",
				Command:     "npx",
				Args:        []string{"-y", "@modelcontextprotocol/server-sequential-thinking"},
				Enabled:     true,
				Source:      "modelcontextprotocol/servers",
			},
		},
		{
			ID:          "mcp-official:time",
			Slug:        "time",
			Kind:        "mcp",
			Source:      "mcp-official",
			SourceName:  "MCP Official Servers",
			Name:        "MCP Time (时区与时间换算)",
			Description: "MCP 官方参考服务：精准获取服务器/指定时区时间与 cron 排期换算",
			Repo:        "modelcontextprotocol/servers",
			RepoPath:    "src/time",
			RepoURL:     "https://github.com/modelcontextprotocol/servers/tree/main/src/time",
			Tags:        []string{"mcp", "time", "timezone"},
			MCPTemplate: &MCPServerEntry{
				ID:          "time",
				Name:        "MCP Time",
				Description: "官方时区查询与时间换算服务",
				Transport:   "stdio",
				Command:     "uvx",
				Args:        []string{"mcp-server-time"},
				Enabled:     true,
				Source:      "modelcontextprotocol/servers",
			},
		},
		{
			ID:          "mcp-official:playwright",
			Slug:        "playwright",
			Kind:        "mcp",
			Source:      "mcp-official",
			SourceName:  "MCP Official Servers",
			Name:        "Playwright MCP (Microsoft 官方浏览器自动化)",
			Description: "Microsoft 官方维护的 Playwright MCP：无障碍快照驱动浏览器交互与验收",
			Repo:        "microsoft/playwright-mcp",
			RepoURL:     "https://github.com/microsoft/playwright-mcp",
			Tags:        []string{"mcp", "browser", "microsoft"},
			MCPTemplate: &MCPServerEntry{
				ID:          "playwright",
				Name:        "Playwright MCP",
				Description: "Microsoft 官方浏览器自动化 MCP 服务",
				Transport:   "stdio",
				Command:     "npx",
				Args:        []string{"-y", "@playwright/mcp@latest"},
				Enabled:     true,
				Source:      "microsoft/playwright-mcp",
			},
		},
		{
			ID:          "mcp-official:context7",
			Slug:        "context7",
			Kind:        "mcp",
			Source:      "mcp-official",
			SourceName:  "MCP Official Servers",
			Name:        "Context7 MCP (实时最新开发文档检索)",
			Description: "Upstash 官方 Context7 MCP：拉取任意框架/库的最新版本文档，避免模型幻觉",
			Repo:        "upstash/context7",
			RepoURL:     "https://github.com/upstash/context7",
			Tags:        []string{"mcp", "docs", "upstash"},
			MCPTemplate: &MCPServerEntry{
				ID:          "context7",
				Name:        "Context7 MCP",
				Description: "实时版本文档查询 MCP 服务",
				Transport:   "stdio",
				Command:     "npx",
				Args:        []string{"-y", "@upstash/context7-mcp@latest"},
				Enabled:     true,
				Source:      "upstash/context7",
			},
		},
	}
}
