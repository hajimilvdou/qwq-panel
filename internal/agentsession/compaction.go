// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const maxCheckpointSummaryBytes = 6144

// CompactionCheckpoint is persisted inside agent_sessions.config_json so
// compacted context remains effective across subsequent turns and host restarts
// without mutating or deleting immutable transcript/audit rows.
type CompactionCheckpoint struct {
	UpToSeq         int64  `json:"up_to_seq"`
	Summary         string `json:"summary"`
	BeforeTokens    int64  `json:"before_tokens"`
	AfterTokens     int64  `json:"after_tokens"`
	DroppedMessages int    `json:"dropped_messages"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

// BuildCompactionCheckpoint builds a durable CompactionCheckpoint from persisted
// session messages (preserving their real SQLite Seq values and keeping the
// newest KeepRecentMessages turns verbatim without splitting tool call pairs).
func BuildCompactionCheckpoint(ctx context.Context, hist []Message, opts CompactionOptions, summarizer Provider) (CompactionCheckpoint, CompactionResult, error) {
	opts = opts.normalized()
	// Exclude a trailing `/compact` trigger message from compaction math.
	work := make([]Message, 0, len(hist))
	for _, m := range hist {
		if m.Role == RoleSystem {
			continue
		}
		if name, _, ok := ParseSlashCommand(m.Content); ok && name == "compact" {
			continue
		}
		work = append(work, m)
	}
	modelAll := make([]ModelMessage, 0, len(work))
	for _, m := range work {
		modelAll = append(modelAll, ModelMessage{Role: m.Role, Content: m.Content})
	}
	beforeTok := EstimateContextBreakdown("", nil, modelAll, opts.MaxContextTokens).MessageTokens
	if len(work) <= opts.KeepRecentMessages {
		return CompactionCheckpoint{}, CompactionResult{
			BeforeTokens:    beforeTok,
			AfterTokens:     beforeTok,
			DroppedMessages: 0,
			SummaryPreview:  "历史消息较短，无需折叠压缩。",
		}, nil
	}

	cut := len(work) - opts.KeepRecentMessages
	for cut > 0 && work[cut].Role == RoleTool {
		cut--
	}
	if cut <= 0 {
		return CompactionCheckpoint{}, CompactionResult{
			BeforeTokens:   beforeTok,
			AfterTokens:    beforeTok,
			SummaryPreview: "当前尾部均为连续工具调用，保持原样。",
		}, nil
	}

	older := modelAll[:cut]
	tail := modelAll[cut:]
	summaryText := buildExtractiveSummary(older)
	if summarizer != nil {
		if resp, err := summarizer.Complete(ctx, ProviderRequest{
			Messages: []ModelMessage{
				{Role: LoopRoleSystem, Content: "Summarize the earlier VPS operations session into concise bullet points preserving host facts, revisions, ports, and decisions."},
				{Role: LoopRoleUser, Content: summaryText},
			},
		}); err == nil && strings.TrimSpace(resp.Content) != "" {
			summaryText = strings.TrimSpace(resp.Content)
		}
	}
	if len(summaryText) > maxCheckpointSummaryBytes {
		summaryText = clipText(summaryText, maxCheckpointSummaryBytes)
	}

	afterTok := EstimateContextBreakdown("", nil, tail, opts.MaxContextTokens).MessageTokens + EstimateTokens(summaryText)
	preview := summaryText
	if len(preview) > 180 {
		preview = preview[:180] + "…"
	}
	cp := CompactionCheckpoint{
		UpToSeq:         work[cut-1].Seq,
		Summary:         summaryText,
		BeforeTokens:    beforeTok,
		AfterTokens:     afterTok,
		DroppedMessages: len(older),
		UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	res := CompactionResult{
		CheckpointID:    fmt.Sprintf("seq_%d", cp.UpToSeq),
		BeforeTokens:    beforeTok,
		AfterTokens:     afterTok,
		DroppedMessages: len(older),
		SummaryPreview:  preview,
	}
	return cp, res, nil
}

// ApplyCompactionCheckpoint collapses persisted messages with Seq <= cp.UpToSeq
// into a single synthetic checkpoint message while keeping all newer messages
// verbatim (and filtering out direct slash command trigger rows).
func ApplyCompactionCheckpoint(msgs []Message, cp *CompactionCheckpoint, names toolNames) []ModelMessage {
	if cp == nil || cp.UpToSeq <= 0 || strings.TrimSpace(cp.Summary) == "" {
		return historyMessages(msgs, names)
	}
	newer := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		if m.Seq <= cp.UpToSeq {
			continue
		}
		if name, _, ok := ParseSlashCommand(m.Content); ok && (name == "compact" || name == "status" || name == "skills" || name == "mcp" || name == "help") {
			continue
		}
		newer = append(newer, m)
	}
	out := make([]ModelMessage, 0, len(newer)+1)
	out = append(out, ModelMessage{
		Role:    LoopRoleSystem,
		Content: "[Compacted Session Context Checkpoint]\n" + cp.Summary,
	})
	out = append(out, historyMessages(newer, names)...)
	return out
}

// Native Context Compaction Engine + Session Fork / Revert contracts
// (backporting OpenCode compaction/fork/revert, Codex thread/compact &
// thread/fork, and DSH context budget governance directly into qwq NativeCore).

// CompactionOptions controls when and how history compaction runs.
type CompactionOptions struct {
	// MaxContextTokens is the model context window budget (default 128000).
	MaxContextTokens int64
	// AutoTriggerPct triggers step-boundary compaction when used >= pct (default 80).
	AutoTriggerPct int
	// KeepRecentMessages is the minimum tail preserved verbatim (default 6).
	KeepRecentMessages int
}

func (o CompactionOptions) normalized() CompactionOptions {
	if o.MaxContextTokens <= 0 {
		o.MaxContextTokens = 128_000
	}
	if o.AutoTriggerPct <= 0 || o.AutoTriggerPct > 95 {
		o.AutoTriggerPct = 80
	}
	if o.KeepRecentMessages <= 0 {
		o.KeepRecentMessages = 6
	}
	return o
}

// CompactRequest carries input for Core-level or Native-level compaction.
type CompactRequest struct {
	SessionID string
	Messages  []ModelMessage
	Options   CompactionOptions
}

// EstimateTokens gives a fast, deterministic, zero-dependency token estimate
// that handles both ASCII code/JSON (~4 chars/token) and CJK text (~1.5 runes/token).
func EstimateTokens(text string) int64 {
	if text == "" {
		return 0
	}
	var asciiChars, nonASCII int64
	for _, r := range text {
		if r < 128 {
			asciiChars++
		} else {
			nonASCII++
		}
	}
	est := (asciiChars+3)/4 + (nonASCII*2+1)/3
	if est == 0 && utf8.RuneCountInString(text) > 0 {
		return 1
	}
	return est
}

// EstimateContextBreakdown computes DSH-grade System / Tool / Message context
// occupancy so NativeCore reports identical telemetry to DSH.
func EstimateContextBreakdown(systemText string, tools []ToolDef, messages []ModelMessage, maxTokens int64) ContextBreakdown {
	if maxTokens <= 0 {
		maxTokens = 128_000
	}
	sysTok := EstimateTokens(systemText)
	var toolTok int64
	for _, td := range tools {
		toolTok += EstimateTokens(td.Name) + EstimateTokens(td.Description) + EstimateTokens(string(td.Parameters)) + 16
	}
	var msgTok int64
	for _, m := range messages {
		if m.Role == LoopRoleSystem {
			continue
		}
		msgTok += EstimateTokens(m.Content) + 8
		for _, tc := range m.ToolCalls {
			msgTok += EstimateTokens(tc.Name) + EstimateTokens(string(tc.Arguments)) + 12
		}
	}
	used := sysTok + toolTok + msgTok
	pct := int((used * 100) / maxTokens)
	if pct > 100 {
		pct = 100
	}
	return ContextBreakdown{
		UsedTokens:    used,
		MaxTokens:     maxTokens,
		Pct:           pct,
		SystemTokens:  sysTok,
		ToolTokens:    toolTok,
		MessageTokens: msgTok,
	}
}

// CompactTranscript summarizes older turns into a single structured checkpoint
// message while strictly preserving:
//  1. Leading system prompt(s)
//  2. The newest KeepRecentMessages turns
//  3. Valid assistant(tool_calls) <-> tool(tool_call_id) pairing (never splits a pair!)
//
// An optional summarizer Provider may generate an LLM summary; when nil (or if
// the model is unavailable), a deterministic local extractive summary is built
// so compaction is always reliable offline and in tests.
func CompactTranscript(ctx context.Context, msgs []ModelMessage, opts CompactionOptions, summarizer Provider) ([]ModelMessage, CompactionResult, error) {
	opts = opts.normalized()
	clean := SanitizeHistory(msgs)

	var sysMsgs, body []ModelMessage
	for _, m := range clean {
		if m.Role == LoopRoleSystem {
			sysMsgs = append(sysMsgs, m)
		} else {
			body = append(body, m)
		}
	}

	beforeTok := EstimateContextBreakdown("", nil, clean, opts.MaxContextTokens).MessageTokens
	if len(body) <= opts.KeepRecentMessages {
		return clean, CompactionResult{
			BeforeTokens:    beforeTok,
			AfterTokens:     beforeTok,
			DroppedMessages: 0,
			SummaryPreview:  "历史消息较短，无需折叠压缩。",
		}, nil
	}

	// Pick cut index that never separates an assistant tool_call from its tool results.
	cut := len(body) - opts.KeepRecentMessages
	for cut > 0 && body[cut].Role == LoopRoleTool {
		cut--
	}
	if cut <= 0 {
		return clean, CompactionResult{
			BeforeTokens: beforeTok, AfterTokens: beforeTok,
			SummaryPreview: "当前尾部均为连续工具调用，保持原样。",
		}, nil
	}

	older := body[:cut]
	tail := body[cut:]

	summaryText := buildExtractiveSummary(older)
	if summarizer != nil {
		if resp, err := summarizer.Complete(ctx, ProviderRequest{
			Messages: []ModelMessage{
				{Role: LoopRoleSystem, Content: "Summarize the earlier VPS operations session into concise bullet points preserving host facts, revisions, ports, and decisions."},
				{Role: LoopRoleUser, Content: summaryText},
			},
		}); err == nil && strings.TrimSpace(resp.Content) != "" {
			summaryText = strings.TrimSpace(resp.Content)
		}
	}

	checkpointMsg := ModelMessage{
		Role:    LoopRoleSystem,
		Content: "[Compacted Session Context Checkpoint]\n" + summaryText,
	}

	out := make([]ModelMessage, 0, len(sysMsgs)+1+len(tail))
	out = append(out, sysMsgs...)
	out = append(out, checkpointMsg)
	out = append(out, tail...)
	out = SanitizeHistory(out)

	afterTok := EstimateContextBreakdown("", nil, out, opts.MaxContextTokens).MessageTokens + EstimateTokens(checkpointMsg.Content)
	preview := summaryText
	if len(preview) > 180 {
		preview = preview[:180] + "…"
	}
	return out, CompactionResult{
		BeforeTokens:    beforeTok,
		AfterTokens:     afterTok,
		DroppedMessages: len(older),
		SummaryPreview:  preview,
	}, nil
}

func buildExtractiveSummary(older []ModelMessage) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Earlier transcript (%d entries compacted):\n", len(older))
	for _, m := range older {
		snippet := strings.TrimSpace(m.Content)
		if len(snippet) > 140 {
			snippet = snippet[:140] + "…"
		}
		if snippet == "" && len(m.ToolCalls) > 0 {
			names := make([]string, 0, len(m.ToolCalls))
			for _, tc := range m.ToolCalls {
				names = append(names, tc.Name)
			}
			snippet = "called tools: " + strings.Join(names, ", ")
		}
		if snippet != "" {
			fmt.Fprintf(&b, "- [%s] %s\n", m.Role, snippet)
		}
	}
	return strings.TrimSpace(b.String())
}
