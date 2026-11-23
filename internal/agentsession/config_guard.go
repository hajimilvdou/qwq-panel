// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// MaxSessionConfigBytes bounds any session config payload.
const MaxSessionConfigBytes = 32 << 10

// AllowedExternalSessionConfigKeys enumerates the non-sensitive per-session
// preference keys permitted for external CLI / ACP session configs.
// Host execution boundary fields (binary, args, command, work_dir, server_url,
// env, mcp_config) and credentials are strictly forbidden in session JSON.
var AllowedExternalSessionConfigKeys = map[string]bool{
	"model":              true,
	"reasoning_effort":   true,
	"max_context_tokens": true,
	"temperature":        true,
	"max_tokens":         true,
	"system_prompt":      true,
	"plan_mode":          true,
	"transport":          true,
	"auth_mode":          true,
	"provider_id":        true,
	"active_skills":      true,
	"max_turns":          true,
	"resume_session_id":  true,
	"external_thread_id": true,
	"agent":              true,
	"profile":            true,
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
		if err := json.Unmarshal(rawModel, &m); err != nil || strings.HasPrefix(strings.TrimSpace(m), "-") || len(m) > 128 {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/model", Code: "INVALID", Message: "invalid model name in session config.",
			})
		}
	}
	if rawEffort, ok := obj["reasoning_effort"]; ok {
		var eff string
		if err := json.Unmarshal(rawEffort, &eff); err != nil || len(eff) > 64 {
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
		for _, r := range trimmed {
			if unicode.IsControl(r) || unicode.IsSpace(r) {
				return nil, problem.Validation(problem.Violation{
					Pointer: "/config/reasoning_effort", Code: "INVALID", Message: "reasoning_effort contains invalid characters.",
				})
			}
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
			if err := json.Unmarshal(rawID, &v); err != nil || strings.HasPrefix(strings.TrimSpace(v), "-") || len(v) > 128 {
				return nil, problem.Validation(problem.Violation{
					Pointer: "/config/" + idField, Code: "INVALID", Message: "invalid identifier in session config.",
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
