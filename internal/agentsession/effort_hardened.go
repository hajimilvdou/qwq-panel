// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ============================================================================
// 修复 R2-BUG-10：AI 思考强度目录精准匹配、OpenAI 非推理模型兼容与 Anthropic 多轮工具签名保持
// ============================================================================

// HardenedBuiltinModelEffortProfiles 替换原 builtinModelEffortProfiles，消除非推理模型误伤且返回深拷贝。
func HardenedBuiltinModelEffortProfiles() []ModelEffortProfile {
	src := []ModelEffortProfile{
		{
			Family:        "OpenAI GPT-5.2+ / Codex",
			Patterns:      []string{"gpt-5.4", "gpt-5.3", "gpt-5.2", "gpt-5-codex", "gpt-5-pro", "codex-max", "codex-mini", "codex"},
			Levels:        []string{"none", "minimal", "low", "medium", "high", "xhigh"},
			DefaultEffort: "high",
			Notes:         "OpenAI GPT-5.2+/Codex 官方支持 none / minimal / low / medium / high / xhigh",
		},
		{
			Family:        "OpenAI GPT-5 mini / nano",
			Patterns:      []string{"gpt-5-mini", "gpt-5-nano", "gpt-5.1-mini", "gpt-5.1-nano"},
			Levels:        []string{"minimal", "low", "medium", "high"},
			DefaultEffort: "medium",
			Notes:         "GPT-5 轻量版支持 minimal / low / medium / high，推荐默认 medium",
		},
		{
			Family:        "OpenAI GPT-5 / 5.1",
			Patterns:      []string{"gpt-5.1", "gpt-5"},
			Levels:        []string{"none", "minimal", "low", "medium", "high"},
			DefaultEffort: "high",
			Notes:         "GPT-5 系列支持 none / minimal / low / medium / high",
		},
		{
			Family:        "OpenAI o1 / o3 / o4-mini",
			Patterns:      []string{"o4-mini", "o3-pro", "o3-mini", "o3", "o1-pro", "o1-mini", "o1"},
			Levels:        []string{"low", "medium", "high"},
			DefaultEffort: "high",
			Notes:         "OpenAI o 系列官方挡位为 low / medium / high",
		},
		{
			Family:        "Anthropic Claude Opus 4.6+",
			Patterns:      []string{"claude-opus-4-7", "claude-opus-4.7", "claude-opus-4-6", "claude-opus-4.6", "claude-4-6-opus", "claude-opus-5", "claude-5-opus"},
			Levels:        []string{"low", "medium", "high", "xhigh", "max"},
			DefaultEffort: "high",
			Notes:         "Claude Opus 4.6+ 支持 low / medium / high / xhigh / max（或自定义 token 预算）",
		},
		{
			Family:        "Anthropic Claude Haiku 4.5+",
			Patterns:      []string{"claude-haiku-4", "claude-4-5-haiku", "claude-4-6-haiku"},
			Levels:        []string{"low", "medium", "high"},
			DefaultEffort: "medium",
			Notes:         "Claude Haiku 4.5+ 推荐默认 medium，支持 low / medium / high",
		},
		{
			// 注意：严禁使用裸 "claude-" 兜底，避免命中不支持 Extended Thinking 的 claude-3-5-sonnet / claude-3-haiku！
			Family: "Anthropic Claude 3.7 / 4.x Sonnet & Opus",
			Patterns: []string{
				"claude-sonnet-4", "claude-4-6-sonnet", "claude-4-5-sonnet", "claude-4-sonnet",
				"claude-opus-4", "claude-4-opus", "claude-3-7-sonnet", "claude-3.7-sonnet",
			},
			Levels:        []string{"low", "medium", "high", "max"},
			DefaultEffort: "high",
			Notes:         "Claude 3.7/4.x 系列支持 low / medium / high / max（也可直接填数字作为 thinking budget）",
		},
		{
			Family:        "Google Gemini 3 / 4",
			Patterns:      []string{"gemini-4", "gemini-3.1", "gemini-3-pro", "gemini-3-flash", "gemini-3"},
			Levels:        []string{"minimal", "low", "medium", "high", "xhigh"},
			DefaultEffort: "high",
			Notes:         "Gemini 3/4 系列支持 minimal / low / medium / high / xhigh",
		},
		{
			Family:        "Google Gemini 2.5 Flash",
			Patterns:      []string{"gemini-2.5-flash", "gemini-2-5-flash"},
			Levels:        []string{"none", "low", "medium", "high"},
			DefaultEffort: "medium",
			Notes:         "Gemini 2.5 Flash 支持 none / low / medium / high，推荐默认 medium",
		},
		{
			Family:        "Google Gemini 2.5 Pro",
			Patterns:      []string{"gemini-2.5-pro", "gemini-2-5-pro", "gemini-2.5"},
			Levels:        []string{"low", "medium", "high"},
			DefaultEffort: "high",
			Notes:         "Gemini 2.5 Pro 支持 low / medium / high",
		},
		{
			// 仅对明确推理端点默认注入 high；deepseek-chat (V3 非推理端点) 不默认强塞 reasoning_effort
			Family:        "DeepSeek Reasoner / R1 / V3.2+",
			Patterns:      []string{"deepseek-reasoner", "deepseek-r1", "deepseek-v4", "deepseek-v3.2"},
			Levels:        []string{"none", "low", "medium", "high", "max"},
			DefaultEffort: "high",
			Notes:         "DeepSeek 推理系列支持 none / low / medium / high / max",
		},
		{
			Family:        "xAI Grok 3 / 4",
			Patterns:      []string{"grok-4", "grok-3-mini", "grok-3"},
			Levels:        []string{"low", "medium", "high"},
			DefaultEffort: "high",
			Notes:         "xAI Grok 推理模型支持 low / medium / high",
		},
		{
			Family:        "Alibaba Qwen3 / QwQ",
			Patterns:      []string{"qwen3", "qwen-3", "qwq"},
			Levels:        []string{"none", "low", "medium", "high", "max"},
			DefaultEffort: "high",
			Notes:         "通义千问 Qwen3 / QwQ 支持 none / low / medium / high / max",
		},
		{
			Family:        "Zhipu GLM-4.5 / 5",
			Patterns:      []string{"glm-5", "glm-4.7", "glm-4.6", "glm-4.5", "glm-z1"},
			Levels:        []string{"none", "minimal", "low", "medium", "high", "xhigh", "max"},
			DefaultEffort: "high",
			Notes:         "智谱 GLM-4.5/5 系列支持 none / minimal / low / medium / high / xhigh / max",
		},
		{
			Family:        "Moonshot Kimi K2 / K3",
			Patterns:      []string{"kimi-k3", "kimi-k2"},
			Levels:        []string{"low", "medium", "high", "max"},
			DefaultEffort: "high",
			Notes:         "月之暗面 Kimi K2/K3 推理系列支持 low / medium / high / max",
		},
		{
			Family:        "MiniMax M1 / M2",
			Patterns:      []string{"minimax-m2", "minimax-m1"},
			Levels:        []string{"low", "medium", "high"},
			DefaultEffort: "high",
			Notes:         "MiniMax M1/M2 支持 low / medium / high",
		},
		{
			Family:        "Doubao Seed / Thinking",
			Patterns:      []string{"doubao-seed", "doubao-1.6", "doubao-1.5-thinking"},
			Levels:        []string{"minimal", "low", "medium", "high"},
			DefaultEffort: "high",
			Notes:         "豆包 Seed / Thinking 系列支持 minimal / low / medium / high",
		},
		{
			Family:        "Mistral Magistral",
			Patterns:      []string{"magistral"},
			Levels:        []string{"low", "medium", "high"},
			DefaultEffort: "high",
			Notes:         "Mistral Magistral 支持 low / medium / high",
		},
	}
	out := make([]ModelEffortProfile, len(src))
	for i := range src {
		out[i] = ModelEffortProfile{
			Family:        src[i].Family,
			Patterns:      append([]string(nil), src[i].Patterns...),
			Levels:        append([]string(nil), src[i].Levels...),
			DefaultEffort: src[i].DefaultEffort,
			Notes:         src[i].Notes,
		}
	}
	return out
}

// ResolveOpenAIChatEffort 专为 OpenAI `/v1/chat/completions` 及兼容网关计算安全的 reasoning_effort 与 temperature：
//   - 若用户未填写 configured 且模型未命中推理目录（如 gpt-4o、gpt-4.1、deepseek-chat、Ollama），返回 ""，绝不盲塞 "high"；
//   - 若仅 GPT-5 系列显式支持 "none" 字面量则保留 "none"，其余网关遇到 "none" 自动映射为省略字段（""）；
//   - 若填写或命中了 "off"/"disabled"/"false"/"0"，返回 ""；
//   - 若用户填写了纯数字 token 预算（如 "8192"），自动按区间映射为 low / medium / high，防止网关因枚举校验报 400；
//   - 只要最终发送了非空且非 "none" 的 reasoning_effort，自动屏蔽 temperature（OpenAI o1/o3/gpt-5 硬约束）。
func ResolveOpenAIChatEffort(model, configured string, temp *float64) (wireEffort string, wireTemp *float64) {
	eff, matched, _ := ResolveReasoningEffort(model, configured)
	custom := strings.TrimSpace(configured)
	if custom == "" && !matched {
		// 未知或普通非推理模型：不注入 reasoning_effort，保留原 temperature
		return "", temp
	}
	lower := strings.ToLower(strings.TrimSpace(eff))
	if lower == "none" {
		normModel := normalizeModelID(model)
		if strings.HasPrefix(normModel, "gpt-5") {
			return "none", temp
		}
		return "", temp
	}
	if IsReasoningEffortDisabled(lower) {
		return "", temp
	}
	if budget, ok := ParseNumericThinkingBudget(lower); ok {
		switch {
		case budget <= 4096:
			wireEffort = "low"
		case budget <= 16384:
			wireEffort = "medium"
		default:
			wireEffort = "high"
		}
		return wireEffort, nil
	}
	return eff, nil
}

// FormatCodexEffortConfigOverride 生成合法的 TOML 字符串键值对供 `codex exec -c` 使用。
func FormatCodexEffortConfigOverride(effort string) string {
	return fmt.Sprintf("model_reasoning_effort=%s", strconv.Quote(strings.TrimSpace(effort)))
}

// AnthropicThinkingBlock 保存 Anthropic `/v1/messages` 返回的原始 thinking / redacted_thinking 块及其加密签名。
type AnthropicThinkingBlock struct {
	Type      string `json:"type"`                // "thinking" | "redacted_thinking"
	Thinking  string `json:"thinking,omitempty"`  // type == "thinking"
	Signature string `json:"signature,omitempty"` // Anthropic 必填签名
	Data      string `json:"data,omitempty"`      // type == "redacted_thinking"
}

// AnthropicResponseContentBlock 完整覆盖 Anthropic Messages API 响应块字段（含 Signature 与 Data）。
type AnthropicResponseContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Thinking  string          `json:"thinking"`
	Signature string          `json:"signature"`
	Data      string          `json:"data"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

// AnthropicThinkingKeeper 在单次多步工具循环内按首条 tool_use ID 保持 assistant thinking 块，
// 无需侵入修改公共 ModelMessage 结构体即可 100% 满足 Anthropic 多轮工具调用签名要求。
type AnthropicThinkingKeeper struct {
	byFirstToolCallID map[string][]AnthropicThinkingBlock
}

func NewAnthropicThinkingKeeper() *AnthropicThinkingKeeper {
	return &AnthropicThinkingKeeper{
		byFirstToolCallID: make(map[string][]AnthropicThinkingBlock),
	}
}

// RecordAssistantTurn 在解析完 Anthropic 响应后记录该轮的 thinking / redacted_thinking 块。
func (k *AnthropicThinkingKeeper) RecordAssistantTurn(blocks []AnthropicResponseContentBlock) {
	if k == nil || len(blocks) == 0 {
		return
	}
	var preserved []AnthropicThinkingBlock
	firstToolID := ""
	for _, blk := range blocks {
		switch blk.Type {
		case "thinking":
			if blk.Signature != "" || blk.Thinking != "" {
				preserved = append(preserved, AnthropicThinkingBlock{
					Type:      "thinking",
					Thinking:  blk.Thinking,
					Signature: blk.Signature,
				})
			}
		case "redacted_thinking":
			if blk.Data != "" {
				preserved = append(preserved, AnthropicThinkingBlock{
					Type: "redacted_thinking",
					Data: blk.Data,
				})
			}
		case "tool_use":
			if firstToolID == "" && blk.ID != "" {
				firstToolID = blk.ID
			}
		}
	}
	if firstToolID != "" && len(preserved) > 0 {
		k.byFirstToolCallID[firstToolID] = preserved
	}
}

// BuildAssistantMessageBlocks 为包含 ToolCalls 的历史 assistant 消息组装符合 Anthropic 规范的 content 数组。
// 返回 hasThinking 供上层判断是否所有历史 tool_use 轮均具备完整 thinking 签名；
// 若遇到恢复自旧会话且无缓存签名的历史消息，上层可自动降级本轮省略 thinking 参数以避免 400。
func (k *AnthropicThinkingKeeper) BuildAssistantMessageBlocks(m ModelMessage) (blocks []map[string]any, hasThinking bool) {
	if len(m.ToolCalls) > 0 && k != nil {
		if saved, ok := k.byFirstToolCallID[m.ToolCalls[0].CallID]; ok && len(saved) > 0 {
			hasThinking = true
			for _, tb := range saved {
				if tb.Type == "redacted_thinking" {
					blocks = append(blocks, map[string]any{
						"type": "redacted_thinking",
						"data": tb.Data,
					})
				} else {
					blocks = append(blocks, map[string]any{
						"type":      "thinking",
						"thinking":  tb.Thinking,
						"signature": tb.Signature,
					})
				}
			}
		}
	}
	if m.Content != "" {
		blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
	}
	for _, tc := range m.ToolCalls {
		var inp any = map[string]any{}
		if len(tc.Arguments) > 0 {
			_ = json.Unmarshal(tc.Arguments, &inp)
		}
		blocks = append(blocks, map[string]any{
			"type":  "tool_use",
			"id":    tc.CallID,
			"name":  tc.Name,
			"input": inp,
		})
	}
	return blocks, hasThinking
}
