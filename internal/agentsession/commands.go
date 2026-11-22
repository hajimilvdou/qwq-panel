// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Direct Slash Commands (modeled on @deepseek-ai/dsh-commands, Codex CLI, and
// OpenCode). Commands run directly against the host session runtime WITHOUT
// injecting the command or its output into the LLM conversation history,
// keeping context clean and deterministic.

// SlashCommandSpec describes one command exposed in the full-width `/` palette.
type SlashCommandSpec struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"` // builtin | core
	Description string   `json:"description"`
	ArgHint     string   `json:"arg_hint,omitempty"`
	AllowBusy   bool     `json:"allow_busy,omitempty"`
	Cores       []string `json:"cores,omitempty"` // empty means every core
}

// CommandExecRequest carries POST /api/v1/agent-sessions/{id}/commands.
type CommandExecRequest struct {
	SessionID string `json:"session_id"`
	Raw       string `json:"raw"`
	Name      string `json:"name"`
	Args      string `json:"args,omitempty"`
}

// CommandHost provides the controlled session hooks built-in commands need.
type CommandHost interface {
	SessionSnapshot(ctx context.Context, sessionID string) (SessionCommandState, error)
	CompactSession(ctx context.Context, sessionID string) (CompactionResult, error)
	SetPlanMode(ctx context.Context, sessionID string, enabled bool) error
	SetPermissionMode(ctx context.Context, sessionID string, mode operations.PermissionMode) error
	SetModel(ctx context.Context, sessionID string, model, effort string) error
	ForkSession(ctx context.Context, sessionID string, beforeSeq int64) (newSessionID string, err error)
	RevertSession(ctx context.Context, sessionID string, targetSeq int64) error
	ListSkills(ctx context.Context) []SkillSpec
	ActivateSkill(ctx context.Context, sessionID, skillID string) (SkillSpec, error)
	ListMCPTools(ctx context.Context, sessionID string) []string
}

// SessionCommandState is the minimal read view of a session for /status.
type SessionCommandState struct {
	SessionID      string                    `json:"session_id"`
	Core           CoreName                  `json:"core"`
	Status         Status                    `json:"status"`
	PermissionMode operations.PermissionMode `json:"permission_mode"`
	PlanMode       bool                      `json:"plan_mode"`
	Model          string                    `json:"model,omitempty"`
	ActiveSkills   []string                  `json:"active_skills,omitempty"`
	Telemetry      TelemetrySnapshot         `json:"telemetry"`
}

// CommandRegistry registers built-in and core-provided slash commands.
type CommandRegistry struct {
	host   CommandHost
	skills *SkillRegistry
}

// NewCommandRegistry constructs the unified slash command router.
func NewCommandRegistry(host CommandHost, skills *SkillRegistry) *CommandRegistry {
	return &CommandRegistry{host: host, skills: skills}
}

// BuiltinCommands returns the 10 panel-wide slash commands available across
// Native, Codex, OpenCode, DSH, and Generic ACP sessions.
func (r *CommandRegistry) BuiltinCommands() []SlashCommandSpec {
	return []SlashCommandSpec{
		{Name: "status", Category: "builtin", Description: "显示当前会话核心、授权级别、上下文用量与速率指标", AllowBusy: true},
		{Name: "compact", Category: "builtin", Description: "压缩早期对话历史为检查点摘要，释放上下文窗口"},
		{Name: "plan", Category: "builtin", Description: "切换计划模式（锁定只读并输出任务清单，批准后再执行）", ArgHint: "[on|off]"},
		{Name: "mode", Category: "builtin", Description: "切换会话权限级别（只读 / 重要操作先问我 / 按授权放行）", ArgHint: "<read_only|safe|full>"},
		{Name: "model", Category: "builtin", Description: "切换当前会话推理模型与思考深度", ArgHint: "<model> [low|medium|high]"},
		{Name: "fork", Category: "builtin", Description: "从当前位置分支出一条独立子会话（保留原会话不动）", AllowBusy: true},
		{Name: "revert", Category: "builtin", Description: "将逻辑工作游标回退到上一个检查点（不删除审计日志）", ArgHint: "[seq]"},
		{Name: "skills", Category: "builtin", Description: "查看或激活内置与自定义 VPS 运维技能包", ArgHint: "[skill_id]", AllowBusy: true},
		{Name: "mcp", Category: "builtin", Description: "显示当前已挂载的宿主 MCP 工具与权限过滤状态", AllowBusy: true},
		{Name: "new", Category: "builtin", Description: "在当前工作区开启空白运维会话", AllowBusy: true},
	}
}

// ParseSlashCommand splits "/compact" or "/mode read_only" into name & args.
func ParseSlashCommand(raw string) (name, args string, ok bool) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "/") {
		return "", "", false
	}
	body := strings.TrimSpace(strings.TrimPrefix(trimmed, "/"))
	if body == "" {
		return "", "", false
	}
	n, a, _ := strings.Cut(body, " ")
	return strings.ToLower(strings.TrimSpace(n)), strings.TrimSpace(a), true
}

// Execute runs a direct slash command against the host without creating a user
// or assistant message in the model transcript.
func (r *CommandRegistry) Execute(ctx context.Context, req CommandExecRequest) (CommandResult, error) {
	name := strings.ToLower(strings.TrimSpace(req.Name))
	args := strings.TrimSpace(req.Args)
	if name == "" && req.Raw != "" {
		n, a, ok := ParseSlashCommand(req.Raw)
		if !ok {
			return CommandResult{}, problem.Validation(problem.Violation{
				Pointer: "/raw", Code: "INVALID", Message: "Slash command must start with '/'.",
			})
		}
		name, args = n, a
	}
	if r.host == nil {
		return CommandResult{}, problem.New(problem.Unavailable, "Command host is unavailable.")
	}

	st, err := r.host.SessionSnapshot(ctx, req.SessionID)
	if err != nil {
		return CommandResult{}, err
	}

	switch name {
	case "status":
		raw, _ := json.Marshal(st)
		return CommandResult{
			Command: "/status",
			OK:      true,
			Summary: fmt.Sprintf("核心 %s · 模式 %s · 计划模式 %v · 上下文 %d%%", st.Core, st.PermissionMode, st.PlanMode, st.Telemetry.Context.Pct),
			Data:    raw,
		}, nil

	case "compact":
		if st.Status.Busy() {
			return CommandResult{}, problem.New(problem.StateConflict, "Cannot compact while a turn is running.")
		}
		res, err := r.host.CompactSession(ctx, req.SessionID)
		if err != nil {
			return CommandResult{}, err
		}
		raw, _ := json.Marshal(res)
		return CommandResult{
			Command: "/compact",
			OK:      true,
			Summary: fmt.Sprintf("已压缩上下文：%d → %d tokens（折叠 %d 条早期消息）", res.BeforeTokens, res.AfterTokens, res.DroppedMessages),
			Data:    raw,
		}, nil

	case "plan":
		next := !st.PlanMode
		if strings.EqualFold(args, "on") || strings.EqualFold(args, "true") {
			next = true
		} else if strings.EqualFold(args, "off") || strings.EqualFold(args, "false") {
			next = false
		}
		if err := r.host.SetPlanMode(ctx, req.SessionID, next); err != nil {
			return CommandResult{}, err
		}
		raw, _ := json.Marshal(map[string]any{"plan_mode": next})
		msg := "已开启计划模式（锁定只读工具，仅输出方案与任务清单）"
		if !next {
			msg = "已退出计划模式，恢复当前会话授权级别"
		}
		return CommandResult{Command: "/plan", OK: true, Summary: msg, Data: raw}, nil

	case "mode":
		m := operations.PermissionMode(args)
		if m == "" || !m.Valid() {
			return CommandResult{}, problem.Validation(problem.Violation{
				Pointer: "/args", Code: "INVALID", Message: "Mode must be read_only, safe, full or custom.",
			})
		}
		if err := r.host.SetPermissionMode(ctx, req.SessionID, m); err != nil {
			return CommandResult{}, err
		}
		raw, _ := json.Marshal(map[string]any{"permission_mode": m})
		return CommandResult{Command: "/mode", OK: true, Summary: fmt.Sprintf("已切换权限模式为 %s", m), Data: raw}, nil

	case "model":
		fields := strings.Fields(args)
		if len(fields) == 0 {
			return CommandResult{}, problem.Validation(problem.Violation{
				Pointer: "/args", Code: "REQUIRED", Message: "Specify a model identifier.",
			})
		}
		effort := ""
		if len(fields) > 1 {
			effort = strings.ToLower(fields[1])
		}
		if err := r.host.SetModel(ctx, req.SessionID, fields[0], effort); err != nil {
			return CommandResult{}, err
		}
		raw, _ := json.Marshal(map[string]any{"model": fields[0], "reasoning_effort": effort})
		return CommandResult{Command: "/model", OK: true, Summary: fmt.Sprintf("已切换推理模型为 %s", fields[0]), Data: raw}, nil

	case "fork":
		newID, err := r.host.ForkSession(ctx, req.SessionID, 0)
		if err != nil {
			return CommandResult{}, err
		}
		raw, _ := json.Marshal(map[string]any{"new_session_id": newID, "parent_session_id": req.SessionID})
		return CommandResult{Command: "/fork", OK: true, Summary: fmt.Sprintf("已分支出新会话 %s", newID), Data: raw}, nil

	case "revert":
		if st.Status.Busy() {
			return CommandResult{}, problem.New(problem.StateConflict, "Cannot revert while a turn is running.")
		}
		if err := r.host.RevertSession(ctx, req.SessionID, 0); err != nil {
			return CommandResult{}, err
		}
		return CommandResult{Command: "/revert", OK: true, Summary: "已回退逻辑检查点（审计记录保持完整）"}, nil

	case "skills":
		if args != "" {
			sk, err := r.host.ActivateSkill(ctx, req.SessionID, args)
			if err != nil {
				return CommandResult{}, err
			}
			raw, _ := json.Marshal(sk)
			return CommandResult{Command: "/skills", OK: true, Summary: fmt.Sprintf("已激活技能「%s」", sk.Name), Data: raw}, nil
		}
		list := r.host.ListSkills(ctx)
		raw, _ := json.Marshal(list)
		return CommandResult{Command: "/skills", OK: true, Summary: fmt.Sprintf("当前共有 %d 个可用运维技能", len(list)), Data: raw}, nil

	case "mcp":
		tools := r.host.ListMCPTools(ctx, req.SessionID)
		raw, _ := json.Marshal(map[string]any{"tools": tools, "count": len(tools)})
		return CommandResult{Command: "/mcp", OK: true, Summary: fmt.Sprintf("宿主 MCP 工具桥已挂载 %d 项授权动作", len(tools)), Data: raw}, nil

	case "new":
		return CommandResult{Command: "/new", OK: true, Summary: "前端可立即创建新空白会话"}, nil

	default:
		return CommandResult{
			Command: "/" + name,
			OK:      false,
			Summary: fmt.Sprintf("未知快捷指令 /%s", name),
		}, problem.New(problem.NotFound, "Unknown slash command /%s.", name)
	}
}
