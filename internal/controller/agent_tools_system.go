// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Built-in general-purpose server agent tools + interactive exchange folder
// tools + plugin diagnostics tools.
//
// Security model:
//   - Server shell & filesystem tools (`host.shell.exec`, `host.fs.*`) and
//     plugin diagnostics (`host.plugins.logs`, `host.plugins.config.read`)
//     strictly require an admin session owner.
//   - Interactive Exchange Folder tools (`host.exchange.*`) are confined
//     strictly under `<DataDir>/agent-workspace/exchange/` and authorize via
//     `host.agent_sessions:read` / `host.agent_sessions:write`.
//   - Mutating server tools (`host.shell.exec`, `host.fs.write`, `host.fs.edit`)
//     and `host.exchange.delete` honor the session's permission mode:
//       * read_only / plan_mode: ALWAYS refused.
//       * safe: requires interactive human approval via ApprovalRouter
//         (`agentsession.IsInlineApproved(ctx)`).
//       * full: non-destructive calls run directly; dangerous commands or
//         sensitive paths STILL require human approval.
//   - Panel secret storage files (`master.key`, `qwq.db*`, `secrets.db*`) are
//     protected from raw filesystem reads to guard against prompt injection.

const (
	maxFSReadBytes      = 64 << 10
	defaultFSReadLines  = 200
	maxFSReadLines      = 500
	maxFSListEntries    = 200
	maxFSSearchMatches  = 100
	maxFSSearchFiles    = 5000
	maxFSWriteBytes     = 2 << 20
	defaultShellTimeout = 30
	maxShellTimeout     = 120
	maxShellOutputBytes = 64 << 10
)

// BuiltinAgentSystemTools returns the built-in general agent, plugin inspection,
// and interactive exchange folder tool specifications offered alongside the host
// and plugin catalog actions.
func BuiltinAgentSystemTools() []agentsession.ToolSpec {
	return []agentsession.ToolSpec{
		// --- General server read tools (admin-only) ---
		{
			Action:      "host.fs.list",
			Summary:     "列出服务器指定目录下的文件与子目录",
			Description: "只读查看宿主机文件系统目录内容（名称、类型、大小、修改时间），支持配置路径与是否显示隐藏文件。",
			Effect:      operations.EffectRead,
			Risk:        operations.RiskLow,
			Approval:    "none",
			Permission:  "host.system:read",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"绝对目录路径，默认 /root"},"show_hidden":{"type":"boolean"},"max_entries":{"type":"integer","minimum":1,"maximum":200}},"additionalProperties":false}`),
		},
		{
			Action:      "host.fs.read",
			Summary:     "读取服务器文本文件内容（支持按行分页）",
			Description: "只读查看宿主机配置文件、日志或脚本内容，支持 offset_line / limit_lines 分页读取；面板主密钥与数据库文件受保护不可直读。",
			Effect:      operations.EffectRead,
			Risk:        operations.RiskLow,
			Approval:    "none",
			Permission:  "host.system:read",
			Parameters:  json.RawMessage(`{"type":"object","required":["path"],"properties":{"path":{"type":"string","description":"要读取的文件路径"},"offset_line":{"type":"integer","minimum":1,"description":"起始行号（1-based）"},"limit_lines":{"type":"integer","minimum":1,"maximum":500,"description":"最多读取行数，默认 200"}},"additionalProperties":false}`),
		},
		{
			Action:      "host.fs.search",
			Summary:     "在服务器目录中按关键字或正则搜索文件内容与文件名",
			Description: "只读遍历指定目录搜索文本匹配行或按通配符查找文件，自动跳过 /proc /sys /dev 及大二进制文件。",
			Effect:      operations.EffectRead,
			Risk:        operations.RiskLow,
			Approval:    "none",
			Permission:  "host.system:read",
			Parameters:  json.RawMessage(`{"type":"object","required":["path"],"properties":{"path":{"type":"string","description":"搜索根目录"},"pattern":{"type":"string","description":"搜索关键字或正则表达式"},"glob":{"type":"string","description":"文件名通配符（如 *.conf、*.json）"},"regex":{"type":"boolean","description":"是否将 pattern 视为正则"},"max_results":{"type":"integer","minimum":1,"maximum":100}},"additionalProperties":false}`),
		},
		{
			Action:      "host.plugins.logs",
			Summary:     "查看指定已安装插件的近期运行日志",
			Description: "只读读取已安装插件的运行日志（支持按 stdout/stderr 过滤），便于排查插件启动或运行错误。",
			Effect:      operations.EffectRead,
			Risk:        operations.RiskLow,
			Approval:    "none",
			Permission:  "host.plugins:logs",
			Parameters:  json.RawMessage(`{"type":"object","required":["plugin_id"],"properties":{"plugin_id":{"type":"string"},"stream":{"type":"string","enum":["","stdout","stderr"]},"limit":{"type":"integer","minimum":1,"maximum":200}},"additionalProperties":false}`),
		},
		{
			Action:      "host.plugins.config.read",
			Summary:     "读取指定插件的当前已脱敏生效配置",
			Description: "只读获取指定插件在宿主中生效的配置 JSON（敏感字段已脱敏）与配置版本号。",
			Effect:      operations.EffectRead,
			Risk:        operations.RiskLow,
			Approval:    "none",
			Permission:  "host.plugins:read",
			Parameters:  json.RawMessage(`{"type":"object","required":["plugin_id"],"properties":{"plugin_id":{"type":"string"}},"additionalProperties":false}`),
		},

		// --- General server execution & file editing tools (admin-only, permission-mode governed) ---
		{
			Action:      "host.shell.exec",
			Summary:     "在宿主机执行 Shell 命令并返回标准输出与退出码",
			Description: "执行运维排查或管理命令（例如 systemctl、ss、nginx -t、docker ps、脚本运行等）。在「先问我」模式下每次执行均会弹出审批卡片，在「全自动」模式下非破坏性命令直接执行、高危破坏性命令仍需人工审批。",
			Effect:      operations.EffectWrite,
			Risk:        operations.RiskMedium,
			Approval:    "confirm",
			Permission:  "host.system:write",
			Parameters:  json.RawMessage(`{"type":"object","required":["command"],"properties":{"command":{"type":"string","description":"要执行的 Shell 命令"},"cwd":{"type":"string","description":"可选工作目录"},"timeout_seconds":{"type":"integer","minimum":1,"maximum":120,"description":"超时秒数，默认 30，最大 120"}},"additionalProperties":false}`),
		},
		{
			Action:      "host.fs.write",
			Summary:     "在服务器创建或覆盖写入文本文件",
			Description: "原子写入服务器上的配置文件、脚本或报告文件。受当前会话权限模式管控（只读模式拒绝、先问我模式弹审批卡片、全自动模式非敏感路径自动执行）。",
			Effect:      operations.EffectWrite,
			Risk:        operations.RiskMedium,
			Approval:    "confirm",
			Permission:  "host.system:write",
			Parameters:  json.RawMessage(`{"type":"object","required":["path","content"],"properties":{"path":{"type":"string","description":"目标文件路径"},"content":{"type":"string","description":"完整文件内容"},"create_dirs":{"type":"boolean","description":"父目录不存在时是否自动创建"},"mode":{"type":"string","description":"可选八进制文件权限，如 0644 或 0755"}},"additionalProperties":false}`),
		},
		{
			Action:      "host.fs.edit",
			Summary:     "对服务器已有文本文件执行精确片段替换",
			Description: "在目标文件中查找 old_text 并替换为 new_text，适合精准修改配置或代码片段。受会话权限模式管控。",
			Effect:      operations.EffectWrite,
			Risk:        operations.RiskMedium,
			Approval:    "confirm",
			Permission:  "host.system:write",
			Parameters:  json.RawMessage(`{"type":"object","required":["path","old_text","new_text"],"properties":{"path":{"type":"string","description":"目标文件路径"},"old_text":{"type":"string","description":"待替换的原文本（必须精确匹配）"},"new_text":{"type":"string","description":"替换后的新文本"},"replace_all":{"type":"boolean","description":"是否替换所有匹配项，默认仅允许唯一匹配"}},"additionalProperties":false}`),
		},

		// --- Interactive Agent File Exchange Folder tools (admin + operator) ---
		{
			Action:      "host.exchange.list",
			Summary:     "列出 Agent 交互文件夹中的子文件夹与文件",
			Description: "只读浏览交互文件夹（根目录或指定子目录）中用户上传的原始文件以及 Agent 输出的成果文件。",
			Effect:      operations.EffectRead,
			Risk:        operations.RiskLow,
			Approval:    "none",
			Permission:  "host.agent_sessions:read",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"交互文件夹内的相对子目录路径，留空表示根目录"}},"additionalProperties":false}`),
		},
		{
			Action:      "host.exchange.read",
			Summary:     "读取交互文件夹中的文本文件内容",
			Description: "只读读取用户上传到交互文件夹的文件内容（支持按行分页），结合服务器环境进行分析或处理。",
			Effect:      operations.EffectRead,
			Risk:        operations.RiskLow,
			Approval:    "none",
			Permission:  "host.agent_sessions:read",
			Parameters:  json.RawMessage(`{"type":"object","required":["path"],"properties":{"path":{"type":"string","description":"交互文件夹内的相对文件路径"},"offset_line":{"type":"integer","minimum":1},"limit_lines":{"type":"integer","minimum":1,"maximum":500}},"additionalProperties":false}`),
		},
		{
			Action:      "host.exchange.mkdir",
			Summary:     "在交互文件夹中新建子文件夹",
			Description: "在 Agent 交互文件夹中创建按任务分类的子文件夹（如 审查报告-20261125），避免文件混淆。",
			Effect:      operations.EffectWrite,
			Risk:        operations.RiskLow,
			Approval:    "auto",
			Permission:  "host.agent_sessions:write",
			Parameters:  json.RawMessage(`{"type":"object","required":["path"],"properties":{"path":{"type":"string","description":"要新建的相对子文件夹路径"}},"additionalProperties":false}`),
		},
		{
			Action:      "host.exchange.write",
			Summary:     "将文本/报告/配置文件写入交互文件夹供用户查看和下载",
			Description: "在 Agent 交互文件夹（或指定子文件夹）中保存生成的审查报告、配置、脚本或处理结果，用户可直接在 Agent 页面预览和下载。",
			Effect:      operations.EffectWrite,
			Risk:        operations.RiskLow,
			Approval:    "auto",
			Permission:  "host.agent_sessions:write",
			Parameters:  json.RawMessage(`{"type":"object","required":["path","content"],"properties":{"path":{"type":"string","description":"交互文件夹内的相对文件路径，如 审查报告/report.md"},"content":{"type":"string","description":"要写入的文本内容"}},"additionalProperties":false}`),
		},
		{
			Action:      "host.exchange.delete",
			Summary:     "删除交互文件夹中的指定文件或子文件夹",
			Description: "删除 Agent 交互文件夹中的文件或子目录。",
			Effect:      operations.EffectWrite,
			Risk:        operations.RiskMedium,
			Approval:    "confirm",
			Permission:  "host.agent_sessions:write",
			Parameters:  json.RawMessage(`{"type":"object","required":["path"],"properties":{"path":{"type":"string","description":"要删除的相对文件或子目录路径"}},"additionalProperties":false}`),
		},
	}
}

func builtinAgentSystemToolByAction(action string) (agentsession.ToolSpec, bool) {
	for _, spec := range BuiltinAgentSystemTools() {
		if spec.Action == action {
			return spec, true
		}
	}
	return agentsession.ToolSpec{}, false
}

func (r *AgentRunner) exchangeManager() *agentsession.ExchangeManager {
	if r.Controller != nil {
		if svc := r.Controller.AgentSessions(); svc != nil && svc.Exchange() != nil {
			return svc.Exchange()
		}
		if dir := r.Controller.Config().DataDir; dir != "" {
			return agentsession.NewExchangeManager(dir)
		}
	}
	return nil
}

func (r *AgentRunner) runBuiltinSystemTool(ctx context.Context, call agentsession.ToolCall, spec agentsession.ToolSpec) agentsession.ToolResult {
	mode := call.PermissionMode
	if ctxMode, ok := operations.PermissionModeFromContext(ctx); ok {
		mode = ctxMode
	}
	if mode == "" {
		mode = operations.PermissionSafe
	}

	// Hard ceiling: read_only mode never runs write tools.
	if spec.Effect != operations.EffectRead && mode == operations.PermissionReadOnly {
		return agentToolFailure(problem.New(problem.PermissionDenied,
			"The session permission mode is read_only; mutating tools are not allowed."))
	}

	// RBAC check.
	if spec.Permission != "" {
		az := r.authorizer()
		if az == nil {
			return agentToolFailure(problem.New(problem.Unavailable, "No authorizer is configured for agent tools."))
		}
		perm, err := authz.ParsePermission(spec.Permission)
		if err != nil {
			return agentToolFailure(problem.From(err))
		}
		res := authz.Resource{Name: string(perm.Resource()), NodeID: r.nodeID(), Action: spec.Action}
		if err := az.AuthorizeSessionActor(ctx, call.Actor.Kind, call.Actor.ID, string(perm), res); err != nil {
			return agentToolFailure(problem.From(err))
		}
	}

	// All server-wide shell/fs/plugin-diagnostic tools strictly require admin.
	isExchangeTool := strings.HasPrefix(spec.Action, "host.exchange.")
	if !isExchangeTool && !r.isOwnerAdmin(ctx, call.Actor) {
		return agentToolFailure(problem.New(problem.PermissionDenied,
			"Administrator role is required to use %s.", spec.Action))
	}

	var (
		payload any
		err     error
	)
	switch spec.Action {
	case "host.fs.list":
		payload, err = r.execFSList(call.Args)
	case "host.fs.read":
		payload, err = r.execFSRead(call.Args)
	case "host.fs.search":
		payload, err = r.execFSSearch(ctx, call.Args)
	case "host.plugins.logs":
		payload, err = r.execPluginsLogs(ctx, call.Args)
	case "host.plugins.config.read":
		payload, err = r.execPluginsConfigRead(call.Args)
	case "host.shell.exec":
		payload, err = r.execShell(ctx, call, mode)
	case "host.fs.write":
		payload, err = r.execFSWrite(ctx, call, mode)
	case "host.fs.edit":
		payload, err = r.execFSEdit(ctx, call, mode)
	case "host.exchange.list":
		payload, err = r.execExchangeList(call.Args)
	case "host.exchange.read":
		payload, err = r.execExchangeRead(call.Args)
	case "host.exchange.mkdir":
		payload, err = r.execExchangeMkdir(call.Args)
	case "host.exchange.write":
		payload, err = r.execExchangeWrite(call.Args)
	case "host.exchange.delete":
		payload, err = r.execExchangeDelete(ctx, call, mode)
	default:
		return agentToolFailure(problem.New(problem.NotFound, "Unknown system tool %q.", spec.Action))
	}
	if err != nil {
		return agentToolFailure(problem.From(err))
	}
	return agentsession.ToolResult{
		Status: agentsession.ToolSucceeded,
		Result: agentJSON(payload),
	}
}

func (r *AgentRunner) requireMutatingGate(ctx context.Context, mode operations.PermissionMode, dangerous bool, action string) error {
	if mode == operations.PermissionReadOnly {
		return problem.New(problem.PermissionDenied, "Action %s is blocked in read_only mode.", action)
	}
	if agentsession.IsInlineApproved(ctx) {
		return nil
	}
	if mode == operations.PermissionFull && !dangerous {
		return nil
	}
	return problem.New(problem.PermissionDenied, "Action %s requires human approval in %s mode.", action, mode)
}

func (r *AgentRunner) isProtectedPanelSecretPath(target string) bool {
	if r.matchProtectedSecretPath(target) {
		return true
	}
	cleaned := filepath.Clean(target)
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		if r.matchProtectedSecretPath(resolved) {
			return true
		}
	} else if parentResolved, perr := filepath.EvalSymlinks(filepath.Dir(cleaned)); perr == nil {
		if r.matchProtectedSecretPath(filepath.Join(parentResolved, filepath.Base(cleaned))) {
			return true
		}
	}
	return false
}

func (r *AgentRunner) matchProtectedSecretPath(target string) bool {
	cleaned := filepath.Clean(target)
	base := strings.ToLower(filepath.Base(cleaned))
	if base == "master.key" || base == "qwq.db" || base == "qwq.db-wal" || base == "qwq.db-shm" ||
		base == "secrets.db" || base == "secrets.key" {
		return true
	}
	if r.Controller != nil {
		if dd := strings.TrimSpace(r.Controller.Config().DataDir); dd != "" {
			cleanDD := filepath.Clean(dd)
			candidates := []string{cleanDD}
			if resolvedDD, err := filepath.EvalSymlinks(cleanDD); err == nil && resolvedDD != cleanDD {
				candidates = append(candidates, resolvedDD)
			}
			for _, rootDD := range candidates {
				// Allow access to agent-workspace/exchange inside DataDir, but block internal secret/auth files.
				exchangeDir := filepath.Join(rootDD, "agent-workspace", "exchange")
				if rel, err := filepath.Rel(exchangeDir, cleaned); err == nil && !strings.HasPrefix(rel, "..") {
					return false
				}
				for _, sub := range []string{"master.key", "qwq.db", "agent-homes", "tls"} {
					p := filepath.Join(rootDD, sub)
					if cleaned == p || strings.HasPrefix(cleaned, p+string(filepath.Separator)) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (r *AgentRunner) auditAgentSystemAction(ctx context.Context, call agentsession.ToolCall, action, subject, outcome string, details map[string]any) {
	if r.Controller == nil || r.Controller.DB() == nil {
		return
	}
	ai := actor.Actor{
		Kind:           actor.AIAgent,
		ID:             operations.SessionActorID(call.SessionID),
		OnBehalfOf:     call.Actor.ID,
		OnBehalfOfKind: call.Actor.Kind,
	}
	rawDetails, _ := json.Marshal(details)
	_ = r.Controller.DB().Update(context.WithoutCancel(ctx), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: ai, TraceID: agentTraceID(call.CallID)})
		return operations.Audit(context.WithoutCancel(ctx), tx, operations.AuditRecord{
			Actor:     ai,
			Action:    action,
			Subject:   subject,
			Outcome:   outcome,
			NodeID:    r.nodeID(),
			TraceID:   agentTraceID(call.CallID),
			RequestID: call.CallID,
			Details:   rawDetails,
		})
	})
}

func (r *AgentRunner) execFSList(rawArgs json.RawMessage) (any, error) {
	var args struct {
		Path       string `json:"path"`
		ShowHidden bool   `json:"show_hidden"`
		MaxEntries int    `json:"max_entries"`
	}
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
		}
	}
	target := strings.TrimSpace(args.Path)
	if target == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			target = home
		} else {
			target = "/"
		}
	}
	cleaned := filepath.Clean(target)
	if r.isProtectedPanelSecretPath(cleaned) {
		return nil, problem.New(problem.PermissionDenied, "Panel internal secret directory %q is protected.", cleaned)
	}
	limit := args.MaxEntries
	if limit <= 0 || limit > maxFSListEntries {
		limit = maxFSListEntries
	}
	dirEntries, err := os.ReadDir(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, problem.New(problem.NotFound, "Directory %q not found.", cleaned)
		}
		return nil, problem.New(problem.Unavailable, "Cannot list directory %q: %v", cleaned, err)
	}
	items := make([]map[string]any, 0, min(len(dirEntries), limit))
	truncated := false
	for _, de := range dirEntries {
		name := de.Name()
		if !args.ShowHidden && strings.HasPrefix(name, ".") {
			continue
		}
		if len(items) >= limit {
			truncated = true
			break
		}
		entryType := "file"
		if de.IsDir() {
			entryType = "dir"
		} else if de.Type()&os.ModeSymlink != 0 {
			entryType = "symlink"
		}
		item := map[string]any{
			"name": name,
			"type": entryType,
		}
		if fi, ierr := de.Info(); ierr == nil {
			item["size"] = fi.Size()
			item["mode"] = fi.Mode().String()
			item["updated_at"] = fi.ModTime().UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		ti, _ := items[i]["type"].(string)
		tj, _ := items[j]["type"].(string)
		if (ti == "dir") != (tj == "dir") {
			return ti == "dir"
		}
		ni, _ := items[i]["name"].(string)
		nj, _ := items[j]["name"].(string)
		return strings.ToLower(ni) < strings.ToLower(nj)
	})
	return map[string]any{
		"path":      filepath.ToSlash(cleaned),
		"entries":   items,
		"total":     len(items),
		"truncated": truncated,
	}, nil
}

func (r *AgentRunner) execFSRead(rawArgs json.RawMessage) (any, error) {
	var args struct {
		Path       string `json:"path"`
		OffsetLine int    `json:"offset_line"`
		LimitLines int    `json:"limit_lines"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	target := strings.TrimSpace(args.Path)
	if target == "" {
		return nil, problem.Validation(problem.Violation{Pointer: "/path", Code: "REQUIRED", Message: "path is required."})
	}
	cleaned := filepath.Clean(target)
	if r.isProtectedPanelSecretPath(cleaned) {
		return nil, problem.New(problem.PermissionDenied, "Panel internal key/database file %q cannot be read directly; use panel APIs instead.", cleaned)
	}
	return readBoundedTextFile(cleaned, args.OffsetLine, args.LimitLines)
}

func readBoundedTextFile(fullPath string, offsetLine, limitLines int) (map[string]any, error) {
	fi, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, problem.New(problem.NotFound, "File %q not found.", fullPath)
		}
		return nil, problem.New(problem.Unavailable, "Cannot open %q: %v", fullPath, err)
	}
	if fi.IsDir() {
		return nil, problem.New(problem.ValidationFailed, "Path %q is a directory; use host.fs.list instead.", fullPath)
	}
	if offsetLine <= 0 {
		offsetLine = 1
	}
	if limitLines <= 0 {
		limitLines = defaultFSReadLines
	}
	if limitLines > maxFSReadLines {
		limitLines = maxFSReadLines
	}
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, problem.New(problem.Unavailable, "Cannot read %q: %v", fullPath, err)
	}
	defer f.Close()

	// Sniff first 4 KiB for binary NUL bytes.
	head := make([]byte, 4096)
	hn, _ := f.Read(head)
	for _, b := range head[:hn] {
		if b == 0 {
			return map[string]any{
				"path":      filepath.ToSlash(fullPath),
				"size":      fi.Size(),
				"is_binary": true,
				"message":   "Binary file detected; text preview skipped.",
			}, nil
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, problem.Wrap(err)
	}

	br := bufio.NewReaderSize(f, 32<<10)
	var out strings.Builder
	lineNo := 0
	emitted := 0
	truncated := false
	for {
		line, rerr := br.ReadString('\n')
		if line != "" {
			lineNo++
			if lineNo >= offsetLine {
				if emitted >= limitLines || out.Len()+len(line) > maxFSReadBytes {
					truncated = true
					break
				}
				fmt.Fprintf(&out, "%d: %s", lineNo, line)
				if !strings.HasSuffix(line, "\n") {
					out.WriteByte('\n')
				}
				emitted++
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, problem.Wrap(rerr)
		}
	}
	return map[string]any{
		"path":        filepath.ToSlash(fullPath),
		"size":        fi.Size(),
		"offset_line": offsetLine,
		"lines_read":  emitted,
		"truncated":   truncated,
		"content":     out.String(),
	}, nil
}

func (r *AgentRunner) execFSSearch(ctx context.Context, rawArgs json.RawMessage) (any, error) {
	var args struct {
		Path       string `json:"path"`
		Pattern    string `json:"pattern"`
		Glob       string `json:"glob"`
		Regex      bool   `json:"regex"`
		MaxResults int    `json:"max_results"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	root := filepath.Clean(strings.TrimSpace(args.Path))
	if root == "" || root == "." {
		return nil, problem.Validation(problem.Violation{Pointer: "/path", Code: "REQUIRED", Message: "path is required."})
	}
	if args.Pattern == "" && args.Glob == "" {
		return nil, problem.Validation(problem.Violation{Pointer: "/pattern", Code: "REQUIRED", Message: "Provide pattern or glob."})
	}
	limit := args.MaxResults
	if limit <= 0 || limit > maxFSSearchMatches {
		limit = maxFSSearchMatches
	}
	var re *regexp.Regexp
	if args.Pattern != "" && args.Regex {
		var err error
		re, err = regexp.Compile(args.Pattern)
		if err != nil {
			return nil, problem.Validation(problem.Violation{Pointer: "/pattern", Code: "INVALID", Message: "Invalid regular expression: " + err.Error()})
		}
	}
	searchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	matches := make([]map[string]any, 0, min(limit, 32))
	filesScanned := 0
	truncated := false
	lowerPat := strings.ToLower(args.Pattern)

	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if searchCtx.Err() != nil {
			truncated = true
			return fs.SkipAll
		}
		if d.IsDir() {
			cleanP := filepath.Clean(p)
			if cleanP == "/proc" || cleanP == "/sys" || cleanP == "/dev" || cleanP == "/run" {
				return filepath.SkipDir
			}
			if p != root && (d.Name() == ".git" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			if r.isProtectedPanelSecretPath(cleanP) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || r.isProtectedPanelSecretPath(p) {
			return nil
		}
		if args.Glob != "" {
			ok, gerr := filepath.Match(args.Glob, d.Name())
			if gerr != nil || !ok {
				return nil
			}
		}
		filesScanned++
		if filesScanned > maxFSSearchFiles {
			truncated = true
			return fs.SkipAll
		}
		if args.Pattern == "" {
			matches = append(matches, map[string]any{"path": filepath.ToSlash(p)})
			if len(matches) >= limit {
				truncated = true
				return fs.SkipAll
			}
			return nil
		}
		fi, ierr := d.Info()
		if ierr != nil || fi.Size() > 2<<20 {
			return nil
		}
		f, oerr := os.Open(p)
		if oerr != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(io.LimitReader(f, 512<<10))
		sc.Buffer(make([]byte, 0, 16<<10), 128<<10)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			if strings.ContainsRune(line, 0) {
				return nil // skip binary
			}
			hit := false
			if re != nil {
				hit = re.MatchString(line)
			} else {
				hit = strings.Contains(strings.ToLower(line), lowerPat)
			}
			if hit {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 240 {
					snippet = snippet[:240] + "…"
				}
				matches = append(matches, map[string]any{
					"path": filepath.ToSlash(p),
					"line": lineNo,
					"text": snippet,
				})
				if len(matches) >= limit {
					truncated = true
					return fs.SkipAll
				}
			}
		}
		return nil
	})
	return map[string]any{
		"path":          filepath.ToSlash(root),
		"matches":       matches,
		"total":         len(matches),
		"files_scanned": filesScanned,
		"truncated":     truncated,
	}, nil
}

func (r *AgentRunner) execPluginsLogs(ctx context.Context, rawArgs json.RawMessage) (any, error) {
	var args struct {
		PluginID string `json:"plugin_id"`
		Stream   string `json:"stream"`
		Limit    int    `json:"limit"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	pid := strings.TrimSpace(args.PluginID)
	if pid == "" {
		return nil, problem.Validation(problem.Violation{Pointer: "/plugin_id", Code: "REQUIRED", Message: "plugin_id is required."})
	}
	if r.Controller == nil || r.Controller.Updater() == nil {
		return nil, problem.New(problem.Unavailable, "Plugin updater is unavailable on this host.")
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 200 {
		limit = 200
	}
	res, err := r.Controller.Updater().Logs(ctx, pid, "", strings.TrimSpace(args.Stream), limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"plugin_id":   pid,
		"items":       res.Lines,
		"total":       len(res.Lines),
		"truncated":   res.Truncated,
		"next_cursor": res.NextCursor,
	}, nil
}

func (r *AgentRunner) execPluginsConfigRead(rawArgs json.RawMessage) (any, error) {
	var args struct {
		PluginID string `json:"plugin_id"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	pid := strings.TrimSpace(args.PluginID)
	if pid == "" {
		return nil, problem.Validation(problem.Violation{Pointer: "/plugin_id", Code: "REQUIRED", Message: "plugin_id is required."})
	}
	if r.Controller == nil || r.Controller.Updater() == nil {
		return nil, problem.New(problem.Unavailable, "Plugin updater is unavailable on this host.")
	}
	cfg, ok := r.Controller.Updater().ActiveConfig(pid)
	if !ok {
		return map[string]any{
			"plugin_id": pid,
			"revision":  0,
			"config":    json.RawMessage(`{}`),
		}, nil
	}
	return map[string]any{
		"plugin_id": pid,
		"revision":  cfg.Revision,
		"config":    secrets.RedactArguments(cfg.Config),
	}, nil
}

func (r *AgentRunner) execShell(ctx context.Context, call agentsession.ToolCall, mode operations.PermissionMode) (any, error) {
	var args struct {
		Command        string `json:"command"`
		Cwd            string `json:"cwd"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(call.Args, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	cmdStr := strings.TrimSpace(args.Command)
	if cmdStr == "" {
		return nil, problem.Validation(problem.Violation{Pointer: "/command", Code: "REQUIRED", Message: "command is required."})
	}
	dangerous := agentsession.IsDangerousShellCommand(cmdStr)
	if err := r.requireMutatingGate(ctx, mode, dangerous, "host.shell.exec"); err != nil {
		return nil, err
	}
	timeoutSec := args.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = defaultShellTimeout
	}
	if timeoutSec > maxShellTimeout {
		timeoutSec = maxShellTimeout
	}
	cwd := strings.TrimSpace(args.Cwd)
	if cwd == "" {
		if ex := r.exchangeManager(); ex != nil && ex.RootDir() != "" {
			_ = os.MkdirAll(ex.RootDir(), 0o700)
			cwd = ex.RootDir()
		}
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(runCtx, "cmd", "/C", cmdStr)
	} else {
		shellBin := "/bin/bash"
		if _, err := os.Stat(shellBin); err != nil {
			shellBin = "/bin/sh"
		}
		cmd = exec.CommandContext(runCtx, shellBin, "-lc", cmdStr)
	}
	if cwd != "" {
		cmd.Dir = cwd
	}
	stdoutBuf := &cappedBuffer{max: maxShellOutputBytes}
	stderrBuf := &cappedBuffer{max: maxShellOutputBytes}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	start := time.Now()
	runErr := cmd.Run()
	durMS := time.Since(start).Milliseconds()

	exitCode := 0
	timedOut := false
	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			timedOut = true
			exitCode = -1
		} else if ee, ok := runErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			r.auditAgentSystemAction(ctx, call, "agent.shell.exec", "host/shell", operations.AuditFailure, map[string]any{
				"command": cmdStr, "cwd": cwd, "error": runErr.Error(),
			})
			return nil, problem.New(problem.Unavailable, "Failed to start shell command: %v", runErr)
		}
	}

	outcome := operations.AuditSuccess
	if exitCode != 0 {
		outcome = operations.AuditFailure
	}
	r.auditAgentSystemAction(ctx, call, "agent.shell.exec", "host/shell", outcome, map[string]any{
		"command": cmdStr, "cwd": cwd, "exit_code": exitCode, "duration_ms": durMS, "timed_out": timedOut,
	})
	return map[string]any{
		"command":     cmdStr,
		"cwd":         cwd,
		"exit_code":   exitCode,
		"timed_out":   timedOut,
		"duration_ms": durMS,
		"stdout":      stdoutBuf.String(),
		"stderr":      stderrBuf.String(),
		"truncated":   stdoutBuf.truncated || stderrBuf.truncated,
	}, nil
}

func (r *AgentRunner) execFSWrite(ctx context.Context, call agentsession.ToolCall, mode operations.PermissionMode) (any, error) {
	var args struct {
		Path       string `json:"path"`
		Content    string `json:"content"`
		CreateDirs bool   `json:"create_dirs"`
		Mode       string `json:"mode"`
	}
	if err := json.Unmarshal(call.Args, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	target := strings.TrimSpace(args.Path)
	if target == "" {
		return nil, problem.Validation(problem.Violation{Pointer: "/path", Code: "REQUIRED", Message: "path is required."})
	}
	cleaned := filepath.Clean(target)
	if r.isProtectedPanelSecretPath(cleaned) {
		return nil, problem.New(problem.PermissionDenied, "Panel internal secret/database file %q cannot be modified directly.", cleaned)
	}
	if len(args.Content) > maxFSWriteBytes {
		return nil, problem.New(problem.PayloadTooLarge, "File content exceeds %d MiB limit.", maxFSWriteBytes/(1<<20))
	}
	dangerous := agentsession.IsDangerousFilePath(cleaned)
	if err := r.requireMutatingGate(ctx, mode, dangerous, "host.fs.write"); err != nil {
		return nil, err
	}
	perm := os.FileMode(0o644)
	if fi, serr := os.Stat(cleaned); serr == nil {
		perm = fi.Mode().Perm()
	}
	if m := strings.TrimSpace(args.Mode); m != "" {
		if parsed, perr := strconv.ParseUint(m, 8, 32); perr == nil && parsed <= 0o777 {
			perm = os.FileMode(parsed)
		}
	}
	dir := filepath.Dir(cleaned)
	if args.CreateDirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, problem.New(problem.Internal, "Failed to create directory %q: %v", dir, err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".qwq-write-*")
	if err != nil {
		return nil, problem.New(problem.Unavailable, "Cannot write to %q: %v", cleaned, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return nil, problem.Wrap(err)
	}
	n, err := tmp.WriteString(args.Content)
	if err != nil {
		cleanup()
		return nil, problem.Wrap(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return nil, problem.Wrap(err)
	}
	if err := os.Rename(tmpName, cleaned); err != nil {
		_ = os.Remove(tmpName)
		return nil, problem.Wrap(err)
	}
	r.auditAgentSystemAction(ctx, call, "agent.fs.write", "host/fs", operations.AuditSuccess, map[string]any{
		"path": filepath.ToSlash(cleaned), "bytes": n,
	})
	return map[string]any{
		"path":          filepath.ToSlash(cleaned),
		"bytes_written": n,
	}, nil
}

func (r *AgentRunner) execFSEdit(ctx context.Context, call agentsession.ToolCall, mode operations.PermissionMode) (any, error) {
	var args struct {
		Path       string `json:"path"`
		OldText    string `json:"old_text"`
		NewText    string `json:"new_text"`
		ReplaceAll bool   `json:"replace_all"`
	}
	if err := json.Unmarshal(call.Args, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	target := strings.TrimSpace(args.Path)
	if target == "" {
		return nil, problem.Validation(problem.Violation{Pointer: "/path", Code: "REQUIRED", Message: "path is required."})
	}
	if args.OldText == "" {
		return nil, problem.Validation(problem.Violation{Pointer: "/old_text", Code: "REQUIRED", Message: "old_text is required."})
	}
	cleaned := filepath.Clean(target)
	if r.isProtectedPanelSecretPath(cleaned) {
		return nil, problem.New(problem.PermissionDenied, "Panel internal secret/database file %q cannot be edited directly.", cleaned)
	}
	dangerous := agentsession.IsDangerousFilePath(cleaned)
	if err := r.requireMutatingGate(ctx, mode, dangerous, "host.fs.edit"); err != nil {
		return nil, err
	}
	fi, err := os.Stat(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, problem.New(problem.NotFound, "File %q not found.", cleaned)
		}
		return nil, problem.Wrap(err)
	}
	if fi.Size() > maxFSWriteBytes {
		return nil, problem.New(problem.PayloadTooLarge, "File %q exceeds %d MiB edit limit.", cleaned, maxFSWriteBytes/(1<<20))
	}
	raw, err := os.ReadFile(cleaned)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	content := string(raw)
	count := strings.Count(content, args.OldText)
	if count == 0 {
		return nil, problem.New(problem.PreconditionFailed, "old_text was not found in %q.", cleaned)
	}
	if count > 1 && !args.ReplaceAll {
		return nil, problem.New(problem.PreconditionFailed,
			"old_text matched %d times in %q; provide more surrounding context or set replace_all=true.", count, cleaned)
	}
	var updated string
	if args.ReplaceAll {
		updated = strings.ReplaceAll(content, args.OldText, args.NewText)
	} else {
		updated = strings.Replace(content, args.OldText, args.NewText, 1)
		count = 1
	}
	tmp, err := os.CreateTemp(filepath.Dir(cleaned), ".qwq-edit-*")
	if err != nil {
		return nil, problem.Wrap(err)
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return nil, problem.Wrap(err)
	}
	if _, err := tmp.WriteString(updated); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return nil, problem.Wrap(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return nil, problem.Wrap(err)
	}
	if err := os.Rename(tmpName, cleaned); err != nil {
		_ = os.Remove(tmpName)
		return nil, problem.Wrap(err)
	}
	r.auditAgentSystemAction(ctx, call, "agent.fs.edit", "host/fs", operations.AuditSuccess, map[string]any{
		"path": filepath.ToSlash(cleaned), "replacements": count,
	})
	return map[string]any{
		"path":         filepath.ToSlash(cleaned),
		"replacements": count,
		"bytes":        len(updated),
	}, nil
}

func (r *AgentRunner) execExchangeList(rawArgs json.RawMessage) (any, error) {
	ex := r.exchangeManager()
	if ex == nil {
		return nil, problem.New(problem.Unavailable, "Interactive exchange folder is not configured.")
	}
	var args struct {
		Path string `json:"path"`
	}
	if len(rawArgs) > 0 {
		_ = json.Unmarshal(rawArgs, &args)
	}
	return ex.List(args.Path)
}

func (r *AgentRunner) execExchangeRead(rawArgs json.RawMessage) (any, error) {
	ex := r.exchangeManager()
	if ex == nil {
		return nil, problem.New(problem.Unavailable, "Interactive exchange folder is not configured.")
	}
	var args struct {
		Path       string `json:"path"`
		OffsetLine int    `json:"offset_line"`
		LimitLines int    `json:"limit_lines"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	full, info, cleaned, err := ex.ResolveDownload(args.Path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, problem.New(problem.ValidationFailed, "Path %q is a directory; use host.exchange.list.", cleaned)
	}
	res, err := readBoundedTextFile(full, args.OffsetLine, args.LimitLines)
	if err != nil {
		return nil, err
	}
	res["exchange_path"] = cleaned
	return res, nil
}

func (r *AgentRunner) execExchangeMkdir(rawArgs json.RawMessage) (any, error) {
	ex := r.exchangeManager()
	if ex == nil {
		return nil, problem.New(problem.Unavailable, "Interactive exchange folder is not configured.")
	}
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	return ex.Mkdir(args.Path)
}

func (r *AgentRunner) execExchangeWrite(rawArgs json.RawMessage) (any, error) {
	ex := r.exchangeManager()
	if ex == nil {
		return nil, problem.New(problem.Unavailable, "Interactive exchange folder is not configured.")
	}
	var args struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	return ex.WriteText(args.Path, args.Content)
}

func (r *AgentRunner) execExchangeDelete(ctx context.Context, call agentsession.ToolCall, mode operations.PermissionMode) (any, error) {
	ex := r.exchangeManager()
	if ex == nil {
		return nil, problem.New(problem.Unavailable, "Interactive exchange folder is not configured.")
	}
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(call.Args, &args); err != nil {
		return nil, problem.Validation(problem.Violation{Pointer: "/args", Code: "INVALID", Message: "Invalid JSON arguments."})
	}
	if err := r.requireMutatingGate(ctx, mode, false, "host.exchange.delete"); err != nil {
		return nil, err
	}
	if err := ex.Delete(args.Path); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": true, "path": strings.TrimSpace(args.Path)}, nil
}

type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	origLen := len(p)
	if c.buf.Len() >= c.max {
		c.truncated = true
		return origLen, nil
	}
	rem := c.max - c.buf.Len()
	if len(p) > rem {
		p = p[:rem]
		c.truncated = true
	}
	_, _ = c.buf.Write(p)
	return origLen, nil
}

func (c *cappedBuffer) String() string {
	b := c.buf.Bytes()
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b)
}
