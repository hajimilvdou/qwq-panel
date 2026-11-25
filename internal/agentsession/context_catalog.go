// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DefaultFallbackContextTokens is used when a model is not in the built-in
// catalog, carries no explicit size suffix, and the user did not specify a
// custom max_context_tokens.
const DefaultFallbackContextTokens int64 = 128_000

// ModelContextProfile describes the official context window of a mainstream AI
// model family.
type ModelContextProfile struct {
	Family        string   `json:"family"`
	Patterns      []string `json:"patterns"`
	ContextTokens int64    `json:"context_tokens"`
	Label         string   `json:"label"`
	Notes         string   `json:"notes"`
}

var builtinModelContextProfiles = []ModelContextProfile{
	// OpenAI
	{
		Family:        "OpenAI GPT-5.3 / 5.4",
		Patterns:      []string{"gpt-5.4", "gpt-5.3"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "GPT-5.3 / GPT-5.4 系列原生 1M 上下文窗口",
	},
	{
		Family:        "OpenAI GPT-5 / 5.1 / 5.2 / Codex",
		Patterns:      []string{"gpt-5.2", "gpt-5.1", "gpt-5-codex", "gpt-5-pro", "gpt-5-mini", "gpt-5-nano", "gpt-5", "codex-max", "codex-mini", "codex"},
		ContextTokens: 400_000,
		Label:         "400K",
		Notes:         "GPT-5 / 5.1 / 5.2 与 Codex 系列官方 400K 上下文窗口",
	},
	{
		Family:        "OpenAI GPT-4.1",
		Patterns:      []string{"gpt-4.1-mini", "gpt-4.1-nano", "gpt-4.1"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "GPT-4.1 全系（含 mini / nano）官方 1M 上下文窗口",
	},
	{
		Family:        "OpenAI o1 / o3 / o4-mini",
		Patterns:      []string{"o4-mini", "o3-pro", "o3-mini", "o3", "o1-pro", "o1"},
		ContextTokens: 200_000,
		Label:         "200K",
		Notes:         "OpenAI o1 / o3 / o4-mini 系列官方 200K 上下文窗口",
	},
	{
		Family:        "OpenAI GPT-4o / o1-mini / GPT-4 Turbo",
		Patterns:      []string{"o1-mini", "gpt-4o", "chatgpt-4o", "gpt-4-turbo"},
		ContextTokens: 128_000,
		Label:         "128K",
		Notes:         "GPT-4o / o1-mini / GPT-4 Turbo 官方 128K 上下文窗口",
	},

	// Anthropic Claude
	{
		Family: "Anthropic Claude 4.6+ / 5",
		Patterns: []string{
			"claude-opus-4-7", "claude-opus-4.7",
			"claude-opus-4-6", "claude-opus-4.6", "claude-4-6-opus",
			"claude-sonnet-4-6", "claude-sonnet-4.6", "claude-4-6-sonnet",
			"claude-opus-5", "claude-sonnet-5", "claude-5",
		},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "Claude Opus/Sonnet 4.6+ 支持 1M 上下文（如通道仅开放标准档可手动改为 200K）",
	},
	{
		Family: "Anthropic Claude 3.5 / 3.7 / 4 / 4.5 / Haiku 4",
		Patterns: []string{
			"claude-sonnet-4-5", "claude-sonnet-4.5", "claude-4-5-sonnet",
			"claude-opus-4-5", "claude-opus-4.5", "claude-4-5-opus",
			"claude-opus-4-1", "claude-opus-4.1",
			"claude-sonnet-4", "claude-opus-4", "claude-haiku-4",
			"claude-4-sonnet", "claude-4-opus", "claude-4-haiku",
			"claude-3-7", "claude-3.7", "claude-3-5", "claude-3.5", "claude-3",
		},
		ContextTokens: 200_000,
		Label:         "200K",
		Notes:         "Claude 3.5 / 3.7 / 4 / 4.5 与 Haiku 4 标准 200K 上下文窗口",
	},

	// Google Gemini
	{
		Family:        "Google Gemini 1.5 Pro",
		Patterns:      []string{"gemini-1.5-pro", "gemini-1-5-pro"},
		ContextTokens: 2_000_000,
		Label:         "2M",
		Notes:         "Gemini 1.5 Pro 支持 2M 上下文窗口",
	},
	{
		Family:        "Google Gemini 2.0 / 2.5 / 3 / 3.1 / 4",
		Patterns:      []string{"gemini-4", "gemini-3.1", "gemini-3", "gemini-2.5", "gemini-2-5", "gemini-2.0", "gemini-2-0", "gemini-1.5-flash", "gemini-exp"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "Gemini 2.0 / 2.5 / 3 / 3.1 / 4 全系支持 1M 上下文窗口",
	},

	// DeepSeek
	{
		Family:        "DeepSeek V4",
		Patterns:      []string{"deepseek-v4"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "DeepSeek V4 长上下文窗口 1M",
	},
	{
		Family:        "DeepSeek V3 / V3.2 / R1",
		Patterns:      []string{"deepseek-v3.2", "deepseek-v3.1", "deepseek-v3", "deepseek-r1", "deepseek-reasoner", "deepseek-chat", "deepseek"},
		ContextTokens: 128_000,
		Label:         "128K",
		Notes:         "DeepSeek V3 / V3.2 / R1 官方 API 128K 上下文窗口",
	},

	// Alibaba Qwen
	{
		Family:        "Alibaba Qwen Long / Qwen2.5-1M",
		Patterns:      []string{"qwen-long", "qwen2.5-1m", "qwen-2.5-1m"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "通义千问 Qwen-Long / Qwen2.5-1M 支持 1M 上下文窗口",
	},
	{
		Family:        "Alibaba Qwen3 Coder / Max / Plus / 3.5",
		Patterns:      []string{"qwen3-coder", "qwen3-max", "qwen3-plus", "qwen3.5", "qwen-3.5"},
		ContextTokens: 262_144,
		Label:         "256K",
		Notes:         "通义千问 Qwen3-Coder / Max / Plus / 3.5 原生 256K (262,144) 上下文",
	},
	{
		Family:        "Alibaba Qwen3 / QwQ / Qwen2.5",
		Patterns:      []string{"qwen3", "qwen-3", "qwq", "qwen2.5", "qwen-plus", "qwen-turbo", "qwen-max"},
		ContextTokens: 131_072,
		Label:         "128K",
		Notes:         "通义千问 Qwen3 / QwQ / Qwen2.5 标准 128K (131,072) 上下文",
	},

	// xAI Grok
	{
		Family:        "xAI Grok 4.1 / 4.20 / 4 Fast",
		Patterns:      []string{"grok-4.20", "grok-4.2", "grok-4.1", "grok-4-fast", "grok-code-fast"},
		ContextTokens: 2_000_000,
		Label:         "2M",
		Notes:         "xAI Grok 4.1 / 4.20 / 4 Fast 官方 2M 上下文窗口",
	},
	{
		Family:        "xAI Grok 4",
		Patterns:      []string{"grok-4"},
		ContextTokens: 256_000,
		Label:         "256K",
		Notes:         "xAI Grok 4 标准 256K 上下文窗口",
	},
	{
		Family:        "xAI Grok 3 / Grok 2",
		Patterns:      []string{"grok-3", "grok-2"},
		ContextTokens: 131_072,
		Label:         "128K",
		Notes:         "xAI Grok 3 / Grok 2 官方 128K (131,072) 上下文窗口",
	},

	// Zhipu GLM
	{
		Family:        "Zhipu GLM-4-Long",
		Patterns:      []string{"glm-4-long"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "智谱 GLM-4-Long 支持 1M 上下文窗口",
	},
	{
		Family:        "Zhipu GLM-5 / GLM-4.7 / GLM-4.6",
		Patterns:      []string{"glm-5", "glm-4.7", "glm-4.6"},
		ContextTokens: 200_000,
		Label:         "200K",
		Notes:         "智谱 GLM-5 / GLM-4.7 / GLM-4.6 官方 200K 上下文窗口",
	},
	{
		Family:        "Zhipu GLM-4.5 / GLM-4 / GLM-Z1",
		Patterns:      []string{"glm-4.5", "glm-4", "glm-z1"},
		ContextTokens: 128_000,
		Label:         "128K",
		Notes:         "智谱 GLM-4.5 / GLM-4 / GLM-Z1 标准 128K 上下文窗口",
	},

	// Moonshot Kimi
	{
		Family:        "Moonshot Kimi K3",
		Patterns:      []string{"kimi-k3"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "月之暗面 Kimi K3 长上下文 1M",
	},
	{
		Family:        "Moonshot Kimi K2 / K2.5 / K2.6",
		Patterns:      []string{"kimi-k2.6", "kimi-k2.5", "kimi-k2"},
		ContextTokens: 262_144,
		Label:         "256K",
		Notes:         "月之暗面 Kimi K2 / K2.5 / K2.6 官方 256K (262,144) 上下文窗口",
	},
	{
		Family:        "Moonshot v1-128k",
		Patterns:      []string{"moonshot-v1-128k"},
		ContextTokens: 128_000,
		Label:         "128K",
		Notes:         "Moonshot v1 128K 上下文",
	},
	{
		Family:        "Moonshot v1-32k",
		Patterns:      []string{"moonshot-v1-32k"},
		ContextTokens: 32_768,
		Label:         "32K",
		Notes:         "Moonshot v1 32K 上下文",
	},
	{
		Family:        "Moonshot v1-8k",
		Patterns:      []string{"moonshot-v1-8k"},
		ContextTokens: 8_192,
		Label:         "8K",
		Notes:         "Moonshot v1 8K 上下文",
	},

	// MiniMax
	{
		Family:        "MiniMax M1 / M3",
		Patterns:      []string{"minimax-m3", "minimax-m1"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "MiniMax M1 / M3 原生 1M 上下文窗口",
	},
	{
		Family:        "MiniMax M2 / M2.5",
		Patterns:      []string{"minimax-m2.5", "minimax-m2"},
		ContextTokens: 204_800,
		Label:         "200K",
		Notes:         "MiniMax M2 / M2.5 官方 200K (204,800) 上下文窗口",
	},

	// ByteDance Doubao
	{
		Family:        "Doubao Seed / 1.5 / 1.6",
		Patterns:      []string{"doubao-seed", "doubao-1.6", "doubao-1.5", "doubao-pro"},
		ContextTokens: 256_000,
		Label:         "256K",
		Notes:         "字节豆包 Seed / 1.5 / 1.6 系列官方 256K 上下文窗口",
	},

	// Meta Llama
	{
		Family:        "Meta Llama 4 Scout",
		Patterns:      []string{"llama-4-scout", "llama4-scout"},
		ContextTokens: 10_000_000,
		Label:         "10M",
		Notes:         "Meta Llama 4 Scout 原生最高 10M 上下文窗口",
	},
	{
		Family:        "Meta Llama 4 Maverick",
		Patterns:      []string{"llama-4-maverick", "llama4-maverick", "llama-4", "llama4"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "Meta Llama 4 Maverick 支持 1M 上下文窗口",
	},
	{
		Family:        "Meta Llama 3.1 / 3.2 / 3.3",
		Patterns:      []string{"llama-3.3", "llama-3.2", "llama-3.1", "llama3.3", "llama3.2", "llama3.1"},
		ContextTokens: 128_000,
		Label:         "128K",
		Notes:         "Meta Llama 3.1 / 3.2 / 3.3 标准 128K 上下文窗口",
	},

	// Mistral
	{
		Family:        "Mistral Large 4",
		Patterns:      []string{"mistral-large-4"},
		ContextTokens: 1_000_000,
		Label:         "1M",
		Notes:         "Mistral Large 4 支持 1M 上下文窗口",
	},
	{
		Family:        "Mistral Codestral / Devstral",
		Patterns:      []string{"codestral", "devstral"},
		ContextTokens: 256_000,
		Label:         "256K",
		Notes:         "Mistral Codestral / Devstral 256K 上下文窗口",
	},
	{
		Family:        "Mistral Large / Medium / Magistral",
		Patterns:      []string{"mistral-large", "mistral-medium", "mistral-small", "magistral", "mistral-nemo", "pixtral"},
		ContextTokens: 128_000,
		Label:         "128K",
		Notes:         "Mistral 系列标准 128K 上下文窗口",
	},
}

// BuiltinModelContextProfiles returns a deep copy of the built-in mainstream
// model context window catalog.
func BuiltinModelContextProfiles() []ModelContextProfile {
	out := make([]ModelContextProfile, len(builtinModelContextProfiles))
	for i, p := range builtinModelContextProfiles {
		out[i] = ModelContextProfile{
			Family:        p.Family,
			Patterns:      append([]string(nil), p.Patterns...),
			ContextTokens: p.ContextTokens,
			Label:         p.Label,
			Notes:         p.Notes,
		}
	}
	return out
}

// explicitContextSuffixRe matches explicit context-window markers embedded in
// model identifiers, e.g. "[1m]", "-1m", ":128k", "-256k", "_32k".
var explicitContextSuffixRe = regexp.MustCompile(`(?i)(?:\[(\d+)([km])\]|(?:^|[-_:.])(\d+)([km])(?:$|[-_:.]))`)

// parseExplicitModelContext extracts an explicit token limit embedded in a
// model name (for example "claude-sonnet-4-5[1m]" -> 1_000_000,
// "my-model-64k" -> 64_000).
func parseExplicitModelContext(norm string) (int64, bool) {
	matches := explicitContextSuffixRe.FindAllStringSubmatch(norm, -1)
	for _, m := range matches {
		numStr, unit := m[1], m[2]
		if numStr == "" {
			numStr, unit = m[3], m[4]
		}
		n, err := strconv.ParseInt(numStr, 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		var tokens int64
		switch strings.ToLower(unit) {
		case "k":
			if n < 4 || n > 4096 {
				continue
			}
			tokens = n * 1000
		case "m":
			if n < 1 || n > 10 {
				continue
			}
			tokens = n * 1_000_000
		default:
			continue
		}
		if tokens >= minProviderContextTokens && tokens <= maxProviderContextTokens {
			return tokens, true
		}
	}
	return 0, false
}

// MatchModelContextProfile looks up a model identifier against the built-in
// catalog of mainstream AI models' context windows. Explicit size annotations
// like "[1m]" or "-256k" take precedence when present.
func MatchModelContextProfile(model string) (ModelContextProfile, bool) {
	norm := normalizeModelID(model)
	if norm == "" {
		return ModelContextProfile{}, false
	}
	// Bracketed explicit override like "claude-sonnet-4-5[1m]" always wins.
	if strings.Contains(norm, "[") {
		if explicit, ok := parseExplicitModelContext(norm); ok {
			return ModelContextProfile{
				Family:        "模型标注上下文",
				ContextTokens: explicit,
				Label:         FormatContextTokensLabel(explicit),
				Notes:         "根据模型名中的显式上下文标记自动识别",
			}, true
		}
	}
	for _, p := range builtinModelContextProfiles {
		for _, pat := range p.Patterns {
			if matchesModelPattern(norm, pat) {
				return p, true
			}
		}
	}
	// Fallback: inspect explicit size suffix (e.g. "custom-llm-64k", "local-256k").
	if explicit, ok := parseExplicitModelContext(norm); ok {
		return ModelContextProfile{
			Family:        "模型后缀识别",
			ContextTokens: explicit,
			Label:         FormatContextTokensLabel(explicit),
			Notes:         "根据模型名称后缀自动识别上下文窗口",
		}, true
	}
	return ModelContextProfile{}, false
}

// ResolveContextWindow returns the effective context window in tokens:
//  1. If the user explicitly configured a positive value, return it verbatim.
//  2. Otherwise match the model against the built-in mainstream AI catalog.
//  3. If unmatched, fall back to DefaultFallbackContextTokens (128K).
func ResolveContextWindow(model string, configured int64) (tokens int64, matched bool, profile ModelContextProfile) {
	profile, matched = MatchModelContextProfile(model)
	if configured > 0 {
		return configured, matched, profile
	}
	if matched && profile.ContextTokens > 0 {
		return profile.ContextTokens, true, profile
	}
	return DefaultFallbackContextTokens, false, ModelContextProfile{}
}

// FormatContextTokensLabel renders a compact human label such as "128K", "200K", "1M".
func FormatContextTokensLabel(tokens int64) string {
	if tokens <= 0 {
		return "自动"
	}
	if tokens >= 1_000_000 {
		if tokens%1_000_000 == 0 {
			return fmt.Sprintf("%dM", tokens/1_000_000)
		}
		return fmt.Sprintf("%.1fM", float64(tokens)/1_000_000)
	}
	if tokens >= 1000 {
		switch tokens {
		case 8_192:
			return "8K"
		case 16_384:
			return "16K"
		case 32_768:
			return "32K"
		case 65_536:
			return "64K"
		case 131_072:
			return "128K"
		case 204_800:
			return "200K"
		case 262_144:
			return "256K"
		case 524_288:
			return "512K"
		}
		return fmt.Sprintf("%dK", tokens/1000)
	}
	return strconv.FormatInt(tokens, 10)
}
