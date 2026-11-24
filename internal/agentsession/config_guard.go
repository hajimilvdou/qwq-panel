// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

var externalSessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// MaxSessionConfigBytes bounds any session config payload.
const MaxSessionConfigBytes = 32 << 10

// AllowedExternalSessionConfigKeys enumerates the non-sensitive per-session
// preference keys permitted for external CLI / ACP session configs.
// Host execution boundary fields (binary, args, command, work_dir, server_url,
// env, mcp_config) and credentials are strictly forbidden in session JSON.
var AllowedExternalSessionConfigKeys = map[string]bool{
	"model":                 true,
	"reasoning_effort":      true,
	"max_context_tokens":    true,
	"temperature":           true,
	"max_tokens":            true,
	"system_prompt":         true,
	"plan_mode":             true,
	"transport":             true,
	"auth_mode":             true,
	"provider_id":           true,
	"active_skills":         true,
	"max_turns":             true,
	"resume_session_id":     true,
	"external_thread_id":    true,
	"agent":                 true,
	"profile":               true,
	"compaction_checkpoint": true,
}

// ValidateExternalSessionConfig rejects any per-session config key outside the
// strict allowlist so untrusted session payloads can never override host
// execution paths, CLI arguments, working directories, server URLs, or secrets.
func ValidateExternalSessionConfig(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage("{}"), nil
	}
	if len(raw) > MaxSessionConfigBytes {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID", Message: "session config exceeds 32 KiB limit.",
		})
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID", Message: "session config must be a JSON object.",
		})
	}
	for k := range obj {
		if !AllowedExternalSessionConfigKeys[k] {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/" + k, Code: "INVALID",
				Message: "forbidden session config key: host execution paths, arguments, work_dir, server_url, and secrets cannot be set per-session.",
			})
		}
	}
	if rawModel, ok := obj["model"]; ok {
		var m string
		if err := json.Unmarshal(rawModel, &m); err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/model", Code: "INVALID", Message: "invalid model name in session config.",
			})
		}
		trimmedModel := strings.TrimSpace(m)
		if trimmedModel != "" {
			if strings.HasPrefix(trimmedModel, "-") {
				return nil, problem.Validation(problem.Violation{
					Pointer: "/config/model", Code: "INVALID", Message: "invalid model name in session config.",
				})
			}
			if _, merr := ValidateProviderModel(trimmedModel); merr != nil {
				return nil, problem.Validation(problem.Violation{
					Pointer: "/config/model", Code: "INVALID", Message: "invalid model name in session config.",
				})
			}
		}
	}
	if rawEffort, ok := obj["reasoning_effort"]; ok {
		var eff string
		if err := json.Unmarshal(rawEffort, &eff); err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/reasoning_effort", Code: "INVALID", Message: "invalid reasoning_effort in session config.",
			})
		}
		trimmed := strings.TrimSpace(eff)
		if strings.HasPrefix(trimmed, "-") {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/reasoning_effort", Code: "INVALID", Message: "reasoning_effort must not start with '-'.",
			})
		}
		if _, err := ValidateReasoningEffort(trimmed, "/config/reasoning_effort"); err != nil {
			return nil, err
		}
	}
	if rawMaxTurns, ok := obj["max_turns"]; ok {
		var mt int
		if err := json.Unmarshal(rawMaxTurns, &mt); err != nil || mt < 0 || mt > 64 {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/max_turns", Code: "OUT_OF_RANGE", Message: "max_turns must be an integer between 0 and 64.",
			})
		}
	}
	if rawTransport, ok := obj["transport"]; ok {
		var tr string
		if err := json.Unmarshal(rawTransport, &tr); err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/transport", Code: "INVALID", Message: "invalid transport in session config.",
			})
		}
		switch tr {
		case "", "auto", "cli", "acp", "app-server", "exec-json", "serve-http", "run-json", "headless", "http":
		default:
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/transport", Code: "INVALID", Message: "unsupported transport in session config.",
			})
		}
	}
	if rawAuthMode, ok := obj["auth_mode"]; ok {
		var am string
		if err := json.Unmarshal(rawAuthMode, &am); err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/auth_mode", Code: "INVALID", Message: "invalid auth_mode in session config.",
			})
		}
		switch am {
		case "", "oauth", "provider":
		default:
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/auth_mode", Code: "INVALID", Message: "unsupported auth_mode in session config.",
			})
		}
	}
	for _, idField := range []string{"provider_id", "resume_session_id", "external_thread_id"} {
		if rawID, ok := obj[idField]; ok {
			var v string
			if err := json.Unmarshal(rawID, &v); err != nil {
				return nil, problem.Validation(problem.Violation{
					Pointer: "/config/" + idField, Code: "INVALID", Message: "invalid identifier in session config.",
				})
			}
			if v != "" && (!externalSessionIDPattern.MatchString(v) || strings.Contains(v, "..")) {
				return nil, problem.Validation(problem.Violation{
					Pointer: "/config/" + idField, Code: "INVALID", Message: "invalid identifier in session config.",
				})
			}
		}
	}
	if rawCP, ok := obj["compaction_checkpoint"]; ok {
		trimmedCP := strings.TrimSpace(string(rawCP))
		if trimmedCP != "null" {
			var cp map[string]any
			if err := json.Unmarshal(rawCP, &cp); err != nil || cp == nil {
				return nil, problem.Validation(problem.Violation{
					Pointer: "/config/compaction_checkpoint", Code: "INVALID", Message: "compaction_checkpoint must be a JSON object.",
				})
			}
		}
	}
	if rawAgent, ok := obj["agent"]; ok {
		var ag string
		if err := json.Unmarshal(rawAgent, &ag); err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/agent", Code: "INVALID", Message: "invalid agent in session config.",
			})
		}
		switch ag {
		case "", "build", "plan", "general":
		default:
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/agent", Code: "INVALID", Message: "unsupported agent in session config.",
			})
		}
	}
	if rawProfile, ok := obj["profile"]; ok {
		var pf string
		if err := json.Unmarshal(rawProfile, &pf); err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/profile", Code: "INVALID", Message: "invalid profile in session config.",
			})
		}
		switch pf {
		case "", "code", "standard", "headless":
		default:
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/profile", Code: "INVALID", Message: "unsupported profile in session config.",
			})
		}
	}
	return raw, nil
}

// AppendPosixPromptArg terminates CLI option parsing with "--" before appending
// the user prompt so prompts beginning with "-" cannot inject CLI flags.
func AppendPosixPromptArg(baseArgs []string, userPrompt string) []string {
	out := make([]string, 0, len(baseArgs)+2)
	out = append(out, baseArgs...)
	out = append(out, "--", userPrompt)
	return out
}

// ValidateAgentSessionSecurityBoundary enforces strict role separation on AI
// agent sessions (SEC-01 / P0-SEC-01):
//  1. Viewers may never create, update, or send turns in agent sessions;
//  2. Non-native external CLI cores (which spawn host subprocesses) are strictly
//     restricted to system administrators (admin);
//  3. permission_mode == "full" (auto-skipping plugin approvals) is strictly
//     restricted to system administrators (admin).
func ValidateAgentSessionSecurityBoundary(callerRole, coreID, permissionMode string) error {
	role := strings.ToLower(strings.TrimSpace(callerRole))
	if role == "viewer" || role == "" {
		return problem.New(problem.PermissionDenied, "只读观察员无权启动或操作 AI 运维会话。")
	}
	normCore := strings.ToLower(strings.TrimSpace(coreID))
	if normCore == "" {
		normCore = string(CoreNative)
	}
	if normCore != string(CoreNative) && role != "admin" {
		return problem.New(problem.PermissionDenied, "外部 CLI 引擎 (%s) 具备宿主机子进程访问能力，仅限系统管理员 (admin) 使用。", normCore)
	}
	if strings.EqualFold(strings.TrimSpace(permissionMode), "full") && role != "admin" {
		return problem.New(problem.PermissionDenied, "全自动免审批模式 (full) 仅限系统管理员 (admin) 开启。")
	}
	return nil
}

// ValidateAgentSessionActorBoundary enforces both role separation and human-only
// restrictions: service accounts may never launch host external CLI subprocesses
// or enable full auto-approval mode.
func ValidateAgentSessionActorBoundary(owner actor.Actor, callerRole, coreID, permissionMode string) error {
	if err := ValidateAgentSessionSecurityBoundary(callerRole, coreID, permissionMode); err != nil {
		return err
	}
	normCore := strings.ToLower(strings.TrimSpace(coreID))
	if normCore == "" {
		normCore = string(CoreNative)
	}
	isExternalCore := normCore != string(CoreNative)
	isFullMode := strings.EqualFold(strings.TrimSpace(permissionMode), "full")
	if (isExternalCore || isFullMode) && owner.Kind != actor.Human && owner.Kind != actor.System {
		return problem.New(problem.PermissionDenied, "外部 CLI 引擎与全自动免审批模式 (full) 仅限人类管理员会话使用，服务账号无权开启。")
	}
	return nil
}

// BuildSafeClaudeDisallowedTools blocks Claude Code's built-in shell, edit,
// network, subagent, and raw host file-reading tools whenever the session is
// not in administrator full mode so prompt injection cannot read /var/lib/qwq
// secrets or pivot via subagents/web fetches outside the controlled qwq MCP bridge.
func BuildSafeClaudeDisallowedTools(permissionMode string) string {
	if strings.EqualFold(strings.TrimSpace(permissionMode), "full") {
		return ""
	}
	return "Bash,Write,Edit,MultiEdit,NotebookEdit,Read,Grep,Glob,WebFetch,WebSearch,LS,NotebookRead,Task,Agent"
}

// MergeExternalResumeConfig atomically merges an external CLI session/thread
// identifier into agent_sessions.config_json after validating the identifier
// against the strict allowlist pattern.
func MergeExternalResumeConfig(existingConfigJSON []byte, key, externalID string) ([]byte, bool, error) {
	externalID = strings.TrimSpace(externalID)
	if externalID == "" || key == "" {
		return existingConfigJSON, false, nil
	}
	if key != "resume_session_id" && key != "external_thread_id" {
		return existingConfigJSON, false, problem.Validation(problem.Violation{
			Pointer: "/config/" + key, Code: "INVALID", Message: "unsupported external resume key.",
		})
	}
	if !externalSessionIDPattern.MatchString(externalID) || strings.Contains(externalID, "..") {
		return existingConfigJSON, false, problem.Validation(problem.Violation{
			Pointer: "/config/" + key, Code: "INVALID", Message: "invalid external session identifier.",
		})
	}
	cfgMap := make(map[string]any)
	if len(existingConfigJSON) > 0 {
		_ = json.Unmarshal(existingConfigJSON, &cfgMap)
	}
	if prev, _ := cfgMap[key].(string); prev == externalID {
		return existingConfigJSON, false, nil
	}
	cfgMap[key] = externalID
	updated, err := json.Marshal(cfgMap)
	if err != nil {
		return existingConfigJSON, false, err
	}
	if len(updated) > MaxSessionConfigBytes {
		return existingConfigJSON, false, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID", Message: "session config exceeds 32 KiB limit.",
		})
	}
	return updated, true, nil
}
