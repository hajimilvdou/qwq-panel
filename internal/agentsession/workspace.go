// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Agent Workspace Resource Manager:
// Strictly separates three user-managed directories under <DataDir>/agent-workspace/:
//   - mcp/       -> MCP server definitions (servers.json + optional config files)
//   - skills/    -> Agent Skills folders (<slug>/SKILL.md + optional scripts/refs)
//   - prompts/   -> Per-core custom instructions strictly isolated by agent family:
//       * claude-code/CLAUDE.md
//       * codex/AGENTS.md
//       * opencode/AGENTS.md
//       * native/SYSTEM.md

const (
	WorkspaceAreaMCP     = "mcp"
	WorkspaceAreaSkills  = "skills"
	WorkspaceAreaPrompts = "prompts"

	maxWorkspaceFileBytes   = 2 << 20 // 2 MiB per uploaded file
	maxWorkspaceReadBytes   = 512 << 10
	maxWorkspaceFilesListed = 500
	maxInjectedPromptBytes  = 16 << 10
)

// CorePromptTarget describes the canonical custom instruction file for each agent core.
type CorePromptTarget struct {
	Core        CoreName `json:"core"`
	DisplayName string   `json:"display_name"`
	RelPath     string   `json:"rel_path"`  // relative to prompts/
	FileName    string   `json:"file_name"` // e.g. CLAUDE.md, AGENTS.md, SYSTEM.md
	Description string   `json:"description"`
}

// CorePromptTargets lists every supported agent core's dedicated prompt file.
var CorePromptTargets = []CorePromptTarget{
	{
		Core:        CoreClaudeCode,
		DisplayName: "Claude Code",
		RelPath:     "claude-code/CLAUDE.md",
		FileName:    "CLAUDE.md",
		Description: "Claude Code 专属全局指令文件（同步至 CLAUDE_CONFIG_DIR/CLAUDE.md）",
	},
	{
		Core:        CoreCodex,
		DisplayName: "OpenAI Codex",
		RelPath:     "codex/AGENTS.md",
		FileName:    "AGENTS.md",
		Description: "Codex CLI 专属全局指令文件（同步至 CODEX_HOME/AGENTS.md）",
	},
	{
		Core:        CoreOpencode,
		DisplayName: "OpenCode",
		RelPath:     "opencode/AGENTS.md",
		FileName:    "AGENTS.md",
		Description: "OpenCode 专属全局指令文件（同步至 OPENCODE_CONFIG_DIR/AGENTS.md）",
	},
	{
		Core:        CoreNative,
		DisplayName: "内置原生核心",
		RelPath:     "native/SYSTEM.md",
		FileName:    "SYSTEM.md",
		Description: "qwq 内置原生 Agent 专属系统提示词追加文件",
	},
}

// WorkspaceFileEntry describes one file inside an agent workspace area.
type WorkspaceFileEntry struct {
	Area      string `json:"area"`
	Path      string `json:"path"`
	Name      string `json:"name"`
	Group     string `json:"group,omitempty"` // skill slug or core name
	Size      int64  `json:"size"`
	IsText    bool   `json:"is_text"`
	UpdatedAt string `json:"updated_at"`
}

// WorkspaceListResult is returned by GET /api/v1/agent/workspace/files.
type WorkspaceListResult struct {
	Area          string               `json:"area"`
	DirectoryHint string               `json:"directory_hint"`
	Items         []WorkspaceFileEntry `json:"items"`
	PromptTargets []CorePromptTarget   `json:"prompt_targets,omitempty"`
}

// WorkspaceFileContent is returned by GET /api/v1/agent/workspace/file.
type WorkspaceFileContent struct {
	Area      string `json:"area"`
	Path      string `json:"path"`
	Content   string `json:"content"`
	Size      int64  `json:"size"`
	UpdatedAt string `json:"updated_at"`
}

// WorkspaceWriteInput is the body of PUT /api/v1/agent/workspace/file.
type WorkspaceWriteInput struct {
	Area          string `json:"area"`
	Path          string `json:"path"`
	Content       string `json:"content"`
	ContentBase64 string `json:"content_base64,omitempty"`
}

// MCPServerEntry is one user-configured MCP server in mcp/servers.json.
type MCPServerEntry struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Transport   string            `json:"transport"` // stdio | http
	Command     string            `json:"command,omitempty"`
	Args        []string          `json:"args,omitempty"`
	URL         string            `json:"url,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	Enabled     bool              `json:"enabled"`
	Source      string            `json:"source,omitempty"`
}

type mcpServersFile struct {
	Servers []MCPServerEntry `json:"servers"`
}

// WorkspaceManager owns <DataDir>/agent-workspace/{mcp,skills,prompts}.
type WorkspaceManager struct {
	rootDir string
	cliAuth *CLIAuthManager
}

// NewWorkspaceManager creates a workspace manager under <dataDir>/agent-workspace.
func NewWorkspaceManager(dataDir string, cliAuth *CLIAuthManager) *WorkspaceManager {
	root := ""
	if strings.TrimSpace(dataDir) != "" {
		root = filepath.Join(dataDir, "agent-workspace")
	}
	return &WorkspaceManager{rootDir: root, cliAuth: cliAuth}
}

// RootDir returns the workspace root path (empty when unconfigured).
func (w *WorkspaceManager) RootDir() string {
	if w == nil {
		return ""
	}
	return w.rootDir
}

func validateWorkspaceArea(area string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(area))
	switch a {
	case WorkspaceAreaMCP, WorkspaceAreaSkills, WorkspaceAreaPrompts:
		return a, nil
	default:
		return "", problem.Validation(problem.Violation{
			Pointer: "/area", Code: "INVALID", Message: "area must be mcp, skills or prompts.",
		})
	}
}

func cleanWorkspaceRelPath(raw string) (string, error) {
	p := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	p = strings.TrimLeft(p, "/")
	if p == "" {
		return "", problem.Validation(problem.Violation{
			Pointer: "/path", Code: "REQUIRED", Message: "A relative file path is required.",
		})
	}
	if len(p) > 240 {
		return "", problem.Validation(problem.Violation{
			Pointer: "/path", Code: "too_long", Message: "File path is at most 240 characters.",
		})
	}
	for _, r := range p {
		if unicode.IsControl(r) || r == 0 {
			return "", problem.Validation(problem.Violation{
				Pointer: "/path", Code: "INVALID", Message: "File path contains invalid control characters.",
			})
		}
	}
	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", problem.Validation(problem.Violation{
			Pointer: "/path", Code: "INVALID", Message: "File path must stay within the workspace area.",
		})
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", problem.Validation(problem.Violation{
				Pointer: "/path", Code: "INVALID", Message: "File path contains disallowed segment.",
			})
		}
	}
	return cleaned, nil
}

func (w *WorkspaceManager) areaDir(area string) (string, error) {
	if w == nil || w.rootDir == "" {
		return "", problem.New(problem.Unavailable, "Agent workspace directory is not configured on this host.")
	}
	a, err := validateWorkspaceArea(area)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(w.rootDir, a)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", problem.New(problem.Internal, "Failed to prepare workspace directory.")
	}
	return dir, nil
}

func (w *WorkspaceManager) resolvePath(area, relPath string) (string, string, error) {
	base, err := w.areaDir(area)
	if err != nil {
		return "", "", err
	}
	cleaned, err := cleanWorkspaceRelPath(relPath)
	if err != nil {
		return "", "", err
	}
	full := filepath.Join(base, filepath.FromSlash(cleaned))
	rel, err := filepath.Rel(base, full)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", "", problem.Validation(problem.Violation{
			Pointer: "/path", Code: "INVALID", Message: "File path escapes workspace boundary.",
		})
	}
	return full, cleaned, nil
}

// ListFiles lists files inside one strictly isolated workspace area.
func (w *WorkspaceManager) ListFiles(area string) (WorkspaceListResult, error) {
	a, err := validateWorkspaceArea(area)
	if err != nil {
		return WorkspaceListResult{}, err
	}
	base, err := w.areaDir(a)
	if err != nil {
		return WorkspaceListResult{}, err
	}
	// Ensure default mcp/servers.json exists so users see the canonical MCP catalog immediately.
	if a == WorkspaceAreaMCP {
		srvFile := filepath.Join(base, "servers.json")
		if _, statErr := os.Stat(srvFile); os.IsNotExist(statErr) {
			_ = writeFileAtomic(srvFile, []byte("{\n  \"servers\": []\n}\n"), 0o600)
		}
	}

	items := make([]WorkspaceFileEntry, 0, 16)
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if len(items) >= maxWorkspaceFilesListed {
			return fs.SkipAll
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if strings.HasPrefix(filepath.Base(relSlash), ".tmp-") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		group := ""
		if idx := strings.IndexByte(relSlash, '/'); idx > 0 {
			group = relSlash[:idx]
		}
		items = append(items, WorkspaceFileEntry{
			Area:      a,
			Path:      relSlash,
			Name:      path.Base(relSlash),
			Group:     group,
			Size:      info.Size(),
			IsText:    isLikelyTextFilename(relSlash),
			UpdatedAt: info.ModTime().UTC().Format(time.RFC3339),
		})
		return nil
	})
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })

	res := WorkspaceListResult{
		Area:          a,
		DirectoryHint: filepath.ToSlash(base),
		Items:         items,
	}
	if a == WorkspaceAreaPrompts {
		res.PromptTargets = append([]CorePromptTarget(nil), CorePromptTargets...)
	}
	return res, nil
}

// ReadFile returns the text contents of one workspace file.
func (w *WorkspaceManager) ReadFile(area, relPath string) (WorkspaceFileContent, error) {
	a, err := validateWorkspaceArea(area)
	if err != nil {
		return WorkspaceFileContent{}, err
	}
	full, cleaned, err := w.resolvePath(a, relPath)
	if err != nil {
		return WorkspaceFileContent{}, err
	}
	info, err := os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty editable buffer for canonical per-core prompt targets so UI opens cleanly.
			if a == WorkspaceAreaPrompts && isCanonicalPromptPath(cleaned) {
				return WorkspaceFileContent{Area: a, Path: cleaned, Content: "", Size: 0}, nil
			}
			return WorkspaceFileContent{}, problem.New(problem.NotFound, "Workspace file %q not found.", cleaned)
		}
		return WorkspaceFileContent{}, problem.Wrap(err)
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return WorkspaceFileContent{}, problem.New(problem.ValidationFailed, "Path is not a regular file.")
	}
	if info.Size() > maxWorkspaceReadBytes {
		return WorkspaceFileContent{}, problem.New(problem.PayloadTooLarge, "File is larger than 512 KiB and cannot be edited inline.")
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return WorkspaceFileContent{}, problem.Wrap(err)
	}
	return WorkspaceFileContent{
		Area:      a,
		Path:      cleaned,
		Content:   string(raw),
		Size:      info.Size(),
		UpdatedAt: info.ModTime().UTC().Format(time.RFC3339),
	}, nil
}

// WriteFile writes or uploads a file into one workspace area (text or base64).
func (w *WorkspaceManager) WriteFile(in WorkspaceWriteInput) (WorkspaceFileEntry, error) {
	a, err := validateWorkspaceArea(in.Area)
	if err != nil {
		return WorkspaceFileEntry{}, err
	}
	full, cleaned, err := w.resolvePath(a, in.Path)
	if err != nil {
		return WorkspaceFileEntry{}, err
	}
	var payload []byte
	if in.ContentBase64 != "" {
		dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(in.ContentBase64))
		if derr != nil {
			return WorkspaceFileEntry{}, problem.Validation(problem.Violation{
				Pointer: "/content_base64", Code: "INVALID", Message: "Invalid base64 file content.",
			})
		}
		payload = dec
	} else {
		payload = []byte(in.Content)
	}
	if len(payload) > maxWorkspaceFileBytes {
		return WorkspaceFileEntry{}, problem.New(problem.PayloadTooLarge, "Uploaded file exceeds 2 MiB limit.")
	}
	if a == WorkspaceAreaMCP && cleaned == "servers.json" {
		if !json.Valid(payload) {
			return WorkspaceFileEntry{}, problem.Validation(problem.Violation{
				Pointer: "/content", Code: "INVALID", Message: "mcp/servers.json must be valid JSON.",
			})
		}
	}
	if err := writeFileAtomic(full, payload, 0o600); err != nil {
		return WorkspaceFileEntry{}, problem.New(problem.Internal, "Failed to write workspace file: %v", err)
	}
	if a == WorkspaceAreaPrompts {
		w.syncPromptToCLIHome(cleaned, payload)
	}
	info, _ := os.Stat(full)
	group := ""
	if idx := strings.IndexByte(cleaned, '/'); idx > 0 {
		group = cleaned[:idx]
	}
	modTime := time.Now().UTC().Format(time.RFC3339)
	if info != nil {
		modTime = info.ModTime().UTC().Format(time.RFC3339)
	}
	return WorkspaceFileEntry{
		Area:      a,
		Path:      cleaned,
		Name:      path.Base(cleaned),
		Group:     group,
		Size:      int64(len(payload)),
		IsText:    isLikelyTextFilename(cleaned),
		UpdatedAt: modTime,
	}, nil
}

// DeletePath removes a file (or a skill directory under skills/<slug>).
func (w *WorkspaceManager) DeletePath(area, relPath string) error {
	a, err := validateWorkspaceArea(area)
	if err != nil {
		return err
	}
	full, cleaned, err := w.resolvePath(a, relPath)
	if err != nil {
		return err
	}
	info, err := os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return problem.New(problem.NotFound, "Workspace path %q not found.", cleaned)
		}
		return problem.Wrap(err)
	}
	if info.IsDir() {
		if a != WorkspaceAreaSkills {
			return problem.New(problem.ValidationFailed, "Only skill folders can be removed recursively.")
		}
		if err := os.RemoveAll(full); err != nil {
			return problem.Wrap(err)
		}
		return nil
	}
	if err := os.Remove(full); err != nil {
		return problem.Wrap(err)
	}
	if a == WorkspaceAreaPrompts {
		w.syncPromptToCLIHome(cleaned, nil)
	}
	return nil
}

// ReadPromptForCore reads the dedicated custom instruction file for core.
func (w *WorkspaceManager) ReadPromptForCore(core CoreName) string {
	if w == nil || w.rootDir == "" {
		return ""
	}
	for _, t := range CorePromptTargets {
		if t.Core == core {
			full := filepath.Join(w.rootDir, WorkspaceAreaPrompts, filepath.FromSlash(t.RelPath))
			raw, err := os.ReadFile(full)
			if err != nil {
				return ""
			}
			s := strings.TrimSpace(string(raw))
			if len(s) > maxInjectedPromptBytes {
				s = s[:maxInjectedPromptBytes]
			}
			return s
		}
	}
	return ""
}

// LoadCustomSkillsPrompt reads all user-installed SKILL.md files under skills/
// and builds a compact, bounded prompt block for the native core.
func (w *WorkspaceManager) LoadCustomSkillsPrompt() string {
	if w == nil || w.rootDir == "" {
		return ""
	}
	dir := filepath.Join(w.rootDir, WorkspaceAreaSkills)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	for _, ent := range entries {
		if b.Len() >= maxInjectedPromptBytes {
			break
		}
		var skillFile string
		if ent.IsDir() {
			cand := filepath.Join(dir, ent.Name(), "SKILL.md")
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				skillFile = cand
			}
		} else if strings.HasSuffix(strings.ToLower(ent.Name()), ".md") {
			skillFile = filepath.Join(dir, ent.Name())
		}
		if skillFile == "" {
			continue
		}
		raw, err := os.ReadFile(skillFile)
		if err != nil {
			continue
		}
		txt := strings.TrimSpace(string(raw))
		if txt == "" {
			continue
		}
		if len(txt) > 3072 {
			txt = txt[:3072] + "\n..."
		}
		if b.Len() == 0 {
			b.WriteString("\n\n## User Installed Skills\n")
		}
		b.WriteString("\n### ")
		b.WriteString(ent.Name())
		b.WriteString("\n")
		b.WriteString(txt)
		b.WriteString("\n")
	}
	out := b.String()
	if len(out) > maxInjectedPromptBytes {
		out = out[:maxInjectedPromptBytes]
	}
	return out
}

// ListMCPServers reads configured MCP servers from mcp/servers.json.
func (w *WorkspaceManager) ListMCPServers() ([]MCPServerEntry, error) {
	if w == nil || w.rootDir == "" {
		return []MCPServerEntry{}, nil
	}
	full, _, err := w.resolvePath(WorkspaceAreaMCP, "servers.json")
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			return []MCPServerEntry{}, nil
		}
		return nil, err
	}
	var parsed mcpServersFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return []MCPServerEntry{}, nil
	}
	if parsed.Servers == nil {
		return []MCPServerEntry{}, nil
	}
	return parsed.Servers, nil
}

// UpsertMCPServer adds or updates one MCP server inside mcp/servers.json.
func (w *WorkspaceManager) UpsertMCPServer(entry MCPServerEntry) ([]MCPServerEntry, error) {
	list, err := w.ListMCPServers()
	if err != nil {
		return nil, err
	}
	entry.ID = strings.TrimSpace(entry.ID)
	if entry.ID == "" {
		return nil, problem.Validation(problem.Violation{Pointer: "/id", Code: "REQUIRED", Message: "MCP server id is required."})
	}
	if entry.Name == "" {
		entry.Name = entry.ID
	}
	if entry.Transport == "" {
		if entry.URL != "" {
			entry.Transport = "http"
		} else {
			entry.Transport = "stdio"
		}
	}
	replaced := false
	for i := range list {
		if list[i].ID == entry.ID {
			list[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		list = append(list, entry)
	}
	raw, err := json.MarshalIndent(mcpServersFile{Servers: list}, "", "  ")
	if err != nil {
		return nil, problem.Wrap(err)
	}
	raw = append(raw, '\n')
	if _, err := w.WriteFile(WorkspaceWriteInput{
		Area:    WorkspaceAreaMCP,
		Path:    "servers.json",
		Content: string(raw),
	}); err != nil {
		return nil, err
	}
	return list, nil
}

// syncPromptToCLIHome mirrors a core's dedicated prompt file into its persistent
// CLI config directory so Claude Code / Codex / OpenCode pick it up automatically.
func (w *WorkspaceManager) syncPromptToCLIHome(relPath string, data []byte) {
	if w == nil || w.cliAuth == nil || w.cliAuth.RootDir() == "" {
		return
	}
	var core CoreName
	var dstRel string
	switch relPath {
	case "claude-code/CLAUDE.md":
		core = CoreClaudeCode
		dstRel = filepath.Join("config", "claude", "CLAUDE.md")
	case "codex/AGENTS.md":
		core = CoreCodex
		dstRel = filepath.Join("config", "codex", "AGENTS.md")
	case "opencode/AGENTS.md":
		core = CoreOpencode
		dstRel = filepath.Join("config", "opencode", "AGENTS.md")
	default:
		return
	}
	homeDir, err := w.cliAuth.CoreHomeDir(core)
	if err != nil {
		return
	}
	dst := filepath.Join(homeDir, dstRel)
	if len(data) == 0 {
		_ = os.Remove(dst)
		return
	}
	_ = writeFileAtomic(dst, data, 0o600)
}

func isCanonicalPromptPath(cleaned string) bool {
	for _, t := range CorePromptTargets {
		if t.RelPath == cleaned {
			return true
		}
	}
	return false
}

func isLikelyTextFilename(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	switch ext {
	case ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".sh", ".py", ".js", ".ts", ".mjs", ".cjs", ".ini", ".conf", ".env", ".xml", ".csv", "":
		return true
	default:
		return false
	}
}

func writeFileAtomic(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// SkillInstalled reports whether a skill slug exists in skills/<slug>.
func (w *WorkspaceManager) SkillInstalled(slug string) bool {
	if w == nil || w.rootDir == "" || slug == "" {
		return false
	}
	p := filepath.Join(w.rootDir, WorkspaceAreaSkills, slug, "SKILL.md")
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// MCPInstalledSet returns a map of installed MCP server IDs.
func (w *WorkspaceManager) MCPInstalledSet() map[string]bool {
	out := map[string]bool{}
	list, err := w.ListMCPServers()
	if err != nil {
		return out
	}
	for _, s := range list {
		out[s.ID] = true
	}
	return out
}

// FormatSlug sanitizes a repository directory name into a safe workspace slug.
func FormatSlug(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' || r == '.' || r == '/' {
			b.WriteByte('-')
		}
	}
	res := strings.Trim(b.String(), "-_")
	if res == "" {
		return fmt.Sprintf("item-%d", time.Now().Unix())
	}
	if len(res) > 64 {
		res = res[:64]
	}
	return res
}
