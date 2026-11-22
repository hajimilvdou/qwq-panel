// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"strconv"
	"strings"
)

// DefaultFallbackEffort is used when a model is not in the built-in catalog
// and the user did not specify a custom reasoning_effort.
const DefaultFallbackEffort = "high"

// ModelEffortProfile describes the official reasoning/thinking effort levels
// supported by a mainstream AI model family.
type ModelEffortProfile struct {
	Family        string   `json:"family"`
	Patterns      []string `json:"patterns"`
	Levels        []string `json:"levels"`
	DefaultEffort string   `json:"default_effort"`
	Notes         string   `json:"notes"`
}

// builtinModelEffortProfiles lists mainstream AI models and their official
// reasoning effort tiers, ordered from most-specific to broadest pattern.
var builtinModelEffortProfiles = []ModelEffortProfile{
	// OpenAI GPT-5.2+ / Codex frontier family (supports xhigh & none/minimal)
	{
		Family:        "OpenAI GPT-5.2+ / Codex",
		Patterns:      []string{"gpt-5.4", "gpt-5.3", "gpt-5.2", "gpt-5-codex", "gpt-5-pro", "codex-max", "codex-mini", "codex"},
		Levels:        []string{"none", "minimal", "low", "medium", "high", "xhigh"},
		DefaultEffort: "high",
		Notes:         "OpenAI GPT-5.2+/Codex 官方支持 none / minimal / low / medium / high / xhigh",
	},
	// OpenAI GPT-5 / 5.1 mini & nano (balanced default medium, supports minimal..high)
	{
		Family:        "OpenAI GPT-5 mini / nano",
		Patterns:      []string{"gpt-5-mini", "gpt-5-nano", "gpt-5.1-mini", "gpt-5.1-nano"},
		Levels:        []string{"minimal", "low", "medium", "high"},
		DefaultEffort: "medium",
		Notes:         "GPT-5 轻量版支持 minimal / low / medium / high，推荐默认 medium",
	},
	// OpenAI GPT-5 / 5.1 standard
	{
		Family:        "OpenAI GPT-5 / 5.1",
		Patterns:      []string{"gpt-5.1", "gpt-5"},
		Levels:        []string{"none", "minimal", "low", "medium", "high"},
		DefaultEffort: "high",
		Notes:         "GPT-5 系列支持 none / minimal / low / medium / high",
	},
	// OpenAI o-series reasoning models
	{
		Family:        "OpenAI o1 / o3 / o4-mini",
		Patterns:      []string{"o4-mini", "o3-pro", "o3-mini", "o3", "o1-pro", "o1-mini", "o1"},
		Levels:        []string{"low", "medium", "high"},
		DefaultEffort: "high",
		Notes:         "OpenAI o 系列官方挡位为 low / medium / high",
	},
	// Anthropic Claude 4.6+ / 4.7+ / 5 Opus (supports xhigh & max)
	{
		Family:        "Anthropic Claude Opus 4.6+",
		Patterns:      []string{"claude-opus-4-7", "claude-opus-4.7", "claude-opus-4-6", "claude-opus-4.6", "claude-4-6-opus", "claude-opus-5", "claude-5-opus"},
		Levels:        []string{"low", "medium", "high", "xhigh", "max"},
		DefaultEffort: "high",
		Notes:         "Claude Opus 4.6+ 支持 low / medium / high / xhigh / max（或自定义 token 预算）",
	},
	// Anthropic Claude Haiku 4.5 / 4.6
	{
		Family:        "Anthropic Claude Haiku 4.5+",
		Patterns:      []string{"claude-haiku-4", "claude-4-5-haiku", "claude-4-6-haiku"},
		Levels:        []string{"low", "medium", "high"},
		DefaultEffort: "medium",
		Notes:         "Claude Haiku 4.5+ 推荐默认 medium，支持 low / medium / high",
	},
	// Anthropic Claude 3.7 / 4 / 4.5 / 4.6 Sonnet & Opus
	{
		Family:        "Anthropic Claude Sonnet / Opus 4.x",
		Patterns:      []string{"claude-sonnet-4", "claude-4-6-sonnet", "claude-4-5-sonnet", "claude-opus-4", "claude-3-7-sonnet", "claude-3.7-sonnet", "claude-"},
		Levels:        []string{"low", "medium", "high", "max"},
		DefaultEffort: "high",
		Notes:         "Claude 3.7/4.x 系列支持 low / medium / high / max（也可直接填数字作为 thinking budget）",
	},
	// Google Gemini 3 / 3.1 / 4
	{
		Family:        "Google Gemini 3 / 4",
		Patterns:      []string{"gemini-4", "gemini-3.1", "gemini-3-pro", "gemini-3-flash", "gemini-3"},
		Levels:        []string{"minimal", "low", "medium", "high", "xhigh"},
		DefaultEffort: "high",
		Notes:         "Gemini 3/4 系列支持 minimal / low / medium / high / xhigh",
	},
	// Google Gemini 2.5 Flash
	{
		Family:        "Google Gemini 2.5 Flash",
		Patterns:      []string{"gemini-2.5-flash", "gemini-2-5-flash"},
		Levels:        []string{"none", "low", "medium", "high"},
		DefaultEffort: "medium",
		Notes:         "Gemini 2.5 Flash 支持 none / low / medium / high，推荐默认 medium",
	},
	// Google Gemini 2.5 Pro
	{
		Family:        "Google Gemini 2.5 Pro",
		Patterns:      []string{"gemini-2.5-pro", "gemini-2-5-pro", "gemini-2.5"},
		Levels:        []string{"low", "medium", "high"},
		DefaultEffort: "high",
		Notes:         "Gemini 2.5 Pro 支持 low / medium / high",
	},
	// DeepSeek R1 / Reasoner / V3.2 / V4
	{
		Family:        "DeepSeek Reasoner / R1 / V3.2+",
		Patterns:      []string{"deepseek-reasoner", "deepseek-r1", "deepseek-v4", "deepseek-v3.2", "deepseek-chat"},
		Levels:        []string{"none", "low", "medium", "high", "max"},
		DefaultEffort: "high",
		Notes:         "DeepSeek 推理系列支持 none / low / medium / high / max",
	},
	// xAI Grok 3 / 4
	{
		Family:        "xAI Grok 3 / 4",
		Patterns:      []string{"grok-4", "grok-3-mini", "grok-3"},
		Levels:        []string{"low", "medium", "high"},
		DefaultEffort: "high",
		Notes:         "xAI Grok 推理模型支持 low / medium / high",
	},
	// Alibaba Qwen3 / Qwen3.5 / QwQ
	{
		Family:        "Alibaba Qwen3 / QwQ",
		Patterns:      []string{"qwen3", "qwen-3", "qwq"},
		Levels:        []string{"none", "low", "medium", "high", "max"},
		DefaultEffort: "high",
		Notes:         "通义千问 Qwen3 / QwQ 支持 none / low / medium / high / max（或直接填预算数字）",
	},
	// Zhipu GLM-4.5 / 4.6 / 5
	{
		Family:        "Zhipu GLM-4.5 / 5",
		Patterns:      []string{"glm-5", "glm-4.7", "glm-4.6", "glm-4.5", "glm-z1"},
		Levels:        []string{"none", "minimal", "low", "medium", "high", "xhigh", "max"},
		DefaultEffort: "high",
		Notes:         "智谱 GLM-4.5/5 系列支持 none / minimal / low / medium / high / xhigh / max",
	},
	// Moonshot Kimi K2 / K3
	{
		Family:        "Moonshot Kimi K2 / K3",
		Patterns:      []string{"kimi-k3", "kimi-k2", "moonshot"},
		Levels:        []string{"low", "medium", "high", "max"},
		DefaultEffort: "high",
		Notes:         "月之暗面 Kimi K2/K3 推理系列支持 low / medium / high / max",
	},
	// MiniMax M1 / M2
	{
		Family:        "MiniMax M1 / M2",
		Patterns:      []string{"minimax-m2", "minimax-m1", "minimax"},
		Levels:        []string{"low", "medium", "high"},
		DefaultEffort: "high",
		Notes:         "MiniMax M1/M2 支持 low / medium / high",
	},
	// ByteDance Doubao Seed / Thinking
	{
		Family:        "Doubao Seed / Thinking",
		Patterns:      []string{"doubao-seed", "doubao-1.6", "doubao-1.5-thinking", "doubao"},
		Levels:        []string{"minimal", "low", "medium", "high"},
		DefaultEffort: "high",
		Notes:         "豆包 Seed / Thinking 系列支持 minimal / low / medium / high",
	},
	// Mistral Magistral
	{
		Family:        "Mistral Magistral",
		Patterns:      []string{"magistral"},
		Levels:        []string{"low", "medium", "high"},
		DefaultEffort: "high",
		Notes:         "Mistral Magistral 支持 low / medium / high",
	},
}

// BuiltinModelEffortProfiles returns a copy of the built-in mainstream AI
// model reasoning effort catalog.
func BuiltinModelEffortProfiles() []ModelEffortProfile {
	out := make([]ModelEffortProfile, len(builtinModelEffortProfiles))
	copy(out, builtinModelEffortProfiles)
	return out
}

// normalizeModelID strips common gateway/router prefixes (e.g. "openai/",
// "anthropic/", "openrouter/google/") and lowercases the model identifier.
func normalizeModelID(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if idx := strings.LastIndex(m, "/"); idx >= 0 && idx < len(m)-1 {
		m = m[idx+1:]
	}
	return m
}

// MatchModelEffortProfile looks up a model identifier against the built-in
// catalog of mainstream AI models.
func MatchModelEffortProfile(model string) (ModelEffortProfile, bool) {
	norm := normalizeModelID(model)
	if norm == "" {
		return ModelEffortProfile{}, false
	}
	for _, p := range builtinModelEffortProfiles {
		for _, pat := range p.Patterns {
			if strings.HasPrefix(norm, pat) || strings.Contains(norm, pat) {
				return p, true
			}
		}
	}
	return ModelEffortProfile{}, false
}

// ResolveReasoningEffort returns the effective reasoning effort code for a turn:
//  1. If the user explicitly configured a custom effort, return it verbatim.
//  2. Otherwise match the model against the built-in mainstream AI catalog.
//  3. If unmatched and unconfigured, default to "high".
func ResolveReasoningEffort(model, configured string) (effort string, matched bool, profile ModelEffortProfile) {
	profile, matched = MatchModelEffortProfile(model)
	custom := strings.TrimSpace(configured)
	if custom != "" {
		return custom, matched, profile
	}
	if matched && profile.DefaultEffort != "" {
		return profile.DefaultEffort, true, profile
	}
	return DefaultFallbackEffort, false, ModelEffortProfile{}
}

// IsReasoningEffortDisabled reports whether an effort string explicitly turns
// off extended reasoning (used by adapters/APIs that represent off by omitting
// thinking parameters).
func IsReasoningEffortDisabled(effort string) bool {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "", "off", "disabled", "false", "0":
		return true
	default:
		return false
	}
}

// ParseNumericThinkingBudget parses a positive integer token budget if the user
// entered a numeric custom effort (e.g. "8192" or "16384").
func ParseNumericThinkingBudget(effort string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(effort))
	if err != nil || n <= 0 {
		return 0, false
	}
	if n < 1024 {
		n = 1024
	}
	if n > 128000 {
		n = 128000
	}
	return n, true
}
