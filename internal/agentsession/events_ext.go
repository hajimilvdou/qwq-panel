// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"encoding/json"
	"time"
)

// Backward-compatible SSE event types extending the 8 core events in types.go.
// Older clients that only handle the original 8 types safely ignore these frames
// while preserving monotonic seq continuity.
const (
	// EventReasoningDelta streams incremental model thinking/reasoning tokens
	// (OpenAI reasoning_content, Codex item/reasoning/delta, OpenCode reasoning
	// part, DSH ACP agent_thought_chunk).
	EventReasoningDelta = "reasoning.delta"
	// EventPlanUpdated publishes the full ordered task checklist driving the
	// floating Task Execution Sheet in the AI workspace.
	EventPlanUpdated = "plan.updated"
	// EventTelemetryUpdated publishes DSH-grade session & step telemetry
	// (model/tool latency, TTFT, TPS, token cache hit rate, context breakdown).
	EventTelemetryUpdated = "telemetry.updated"
	// EventCommandResult reports the outcome of a direct slash command that ran
	// against the runtime without polluting the model's conversation history.
	EventCommandResult = "command.result"
	// EventSessionCompacted announces that older transcript turns were summarized
	// into a compaction checkpoint to reclaim context window budget.
	EventSessionCompacted = "session.compacted"
	// EventSessionReverted announces that the session logical cursor rewound to
	// an earlier seq while retaining immutable audit rows.
	EventSessionReverted = "session.reverted"
)

// PlanItemStatus is the lifecycle state of one step in the task checklist.
type PlanItemStatus string

const (
	PlanPending    PlanItemStatus = "pending"
	PlanInProgress PlanItemStatus = "in_progress"
	PlanCompleted  PlanItemStatus = "completed"
	PlanSkipped    PlanItemStatus = "skipped"
)

// PlanItem is one structured step shown in the floating Task Execution Sheet.
type PlanItem struct {
	ID     string         `json:"id"`
	Title  string         `json:"title"`
	Status PlanItemStatus `json:"status"`
	Note   string         `json:"note,omitempty"`
}

// TokenUsage captures provider-neutral token accounting with prompt cache detail.
type TokenUsage struct {
	Input         int64 `json:"input"`
	CachedRead    int64 `json:"cached_read"`
	CachedWrite   int64 `json:"cached_write,omitempty"`
	UncachedInput int64 `json:"uncached_input"`
	Output        int64 `json:"output"`
	Reasoning     int64 `json:"reasoning,omitempty"`
	Total         int64 `json:"total"`
	CacheHitPct   int   `json:"cache_hit_pct"`
}

// ContextBreakdown estimates how the active context window is occupied across
// system instructions, tool schemas, and conversation messages.
type ContextBreakdown struct {
	UsedTokens    int64 `json:"used_tokens"`
	MaxTokens     int64 `json:"max_tokens"`
	Pct           int   `json:"pct"`
	SystemTokens  int64 `json:"system_tokens"`
	ToolTokens    int64 `json:"tool_tokens"`
	MessageTokens int64 `json:"message_tokens"`
}

// TelemetrySnapshot carries the full DSH-grade runtime metrics displayed in the
// bottom telemetry bar popovers (Session Stats / Token Usage / Context Budget).
type TelemetrySnapshot struct {
	Turns     int              `json:"turns"`
	Steps     int              `json:"steps"`
	ModelMS   int64            `json:"model_ms"`
	ToolMS    int64            `json:"tool_ms"`
	TTFTMS    int64            `json:"ttft_ms"`
	TPS       float64          `json:"tps"`
	Tokens    TokenUsage       `json:"tokens"`
	Context   ContextBreakdown `json:"context"`
	UpdatedAt time.Time        `json:"updated_at,omitempty"`
}

// ComputeDerived recalculates Total, UncachedInput, CacheHitPct, and Context.Pct
// so every adapter (Native, Codex, OpenCode, DSH) produces consistent numbers.
func (t *TelemetrySnapshot) ComputeDerived() {
	if t.Tokens.UncachedInput == 0 && t.Tokens.Input >= t.Tokens.CachedRead {
		t.Tokens.UncachedInput = t.Tokens.Input - t.Tokens.CachedRead
	}
	if t.Tokens.Total == 0 {
		t.Tokens.Total = t.Tokens.Input + t.Tokens.Output + t.Tokens.Reasoning
	}
	if denom := t.Tokens.CachedRead + t.Tokens.UncachedInput; denom > 0 {
		t.Tokens.CacheHitPct = int((t.Tokens.CachedRead * 100) / denom)
	}
	if t.Context.MaxTokens > 0 {
		if t.Context.UsedTokens == 0 {
			t.Context.UsedTokens = t.Context.SystemTokens + t.Context.ToolTokens + t.Context.MessageTokens
		}
		pct := int((t.Context.UsedTokens * 100) / t.Context.MaxTokens)
		if pct > 100 {
			pct = 100
		}
		t.Context.Pct = pct
	}
}

// CommandResult is emitted by EventCommandResult for direct slash commands.
type CommandResult struct {
	Command string          `json:"command"`
	OK      bool            `json:"ok"`
	Summary string          `json:"summary"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// CompactionResult describes a completed context compaction checkpoint.
type CompactionResult struct {
	CheckpointID    string `json:"checkpoint_id,omitempty"`
	BeforeTokens    int64  `json:"before_tokens"`
	AfterTokens     int64  `json:"after_tokens"`
	DroppedMessages int    `json:"dropped_messages"`
	SummaryPreview  string `json:"summary_preview"`
}

// ExtendedEventEnvelope wraps an existing Event plus structured extension
// payloads. During merge into types.go, these fields are added directly onto
// Event with `omitempty` so the wire format remains flat JSON.
type ExtendedEventEnvelope struct {
	Event
	ReasoningDelta string             `json:"reasoning_delta,omitempty"`
	Plan           []PlanItem         `json:"plan,omitempty"`
	Telemetry      *TelemetrySnapshot `json:"telemetry,omitempty"`
	Command        *CommandResult     `json:"command,omitempty"`
	Compaction     *CompactionResult  `json:"compaction,omitempty"`
}

// emitExtended marshals structured extension payloads into Event.Result when
// running against an unmodified Event struct, ensuring zero-loss transport even
// before types.go adds first-class fields.
func emitExtended(emit Emit, typ string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return emit(Event{
		Type:   typ,
		Result: raw,
		At:     time.Now().UTC(),
	})
}
