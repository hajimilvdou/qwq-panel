// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// EnhancedNativeCore upgrades qwq's built-in `native` core with full feature
// parity across Codex, OpenCode, and DeepSeek Harness (DSH):
//   - True SSE streaming (`stream: true`, `stream_options.include_usage: true`)
//     with automatic non-streaming fallback for legacy endpoints;
//   - Incremental reasoning/thinking stream (`reasoning.delta`);
//   - Live DSH-grade telemetry (`telemetry.updated`: TTFT, TPS, model/tool ms,
//     prompt cache hit rate, System/Tool/Message context window breakdown);
//   - Structured Task Execution Checklist (`host.agent.update_plan` -> `plan.updated`);
//   - Plan Mode (`plan_mode`: read-only ceiling + structured plan-first workflow);
//   - Skill prompt injection from `SkillRegistry`;
//   - Step-boundary auto-compaction & manual `/compact`;
//   - Optional `reasoning_effort` (`low`/`medium`/`high`) and OpenCode-style
//     `soft_landing` when approaching max_steps.

const (
	planToolActionName   = "host.agent.update_plan"
	planToolFunctionName = "host_agent_update_plan"
	maxEnhancedSteps     = 16
)

// enhancedNativeConfig extends nativeConfig with strictly additive optional fields.
type enhancedNativeConfig struct {
	nativeConfig
	PlanMode             bool                  `json:"plan_mode,omitempty"`
	EnablePlanTool       bool                  `json:"enable_plan_tool,omitempty"`
	ReasoningEffort      string                `json:"reasoning_effort,omitempty"` // low | medium | high
	ActiveSkills         []string              `json:"active_skills,omitempty"`
	Stream               *bool                 `json:"stream,omitempty"` // nil keeps non-streaming compatibility for legacy tests; UI sets true
	SoftLanding          bool                  `json:"soft_landing,omitempty"`
	MaxContextTokens     int64                 `json:"max_context_tokens,omitempty"`
	AutoCompactPct       int                   `json:"auto_compact_pct,omitempty"`
	CompactionCheckpoint *CompactionCheckpoint `json:"compaction_checkpoint,omitempty"`
}

func decodeEnhancedNativeConfig(raw json.RawMessage) (*enhancedNativeConfig, error) {
	base, err := decodeNativeConfig(raw)
	if err != nil {
		return nil, err
	}
	cfg := &enhancedNativeConfig{nativeConfig: *base}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, cfg)
		cfg.nativeConfig = *base
	}
	eff, err := ValidateReasoningEffort(cfg.ReasoningEffort, "/config/reasoning_effort")
	if err != nil {
		return nil, err
	}
	cfg.ReasoningEffort = eff
	if _, err := ValidateMaxContextTokens(cfg.MaxContextTokens, "/config/max_context_tokens"); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *enhancedNativeConfig) wantStream() bool {
	if c.Stream == nil {
		return false
	}
	return *c.Stream
}

// EnhancedNativeCore wraps NativeCore while preserving every security boundary.
type EnhancedNativeCore struct {
	base      *NativeCore
	skills    *SkillRegistry
	workspace *WorkspaceManager
}

// NewEnhancedNativeCore constructs the upgraded native core.
func NewEnhancedNativeCore(opts NativeOptions, skills *SkillRegistry) *EnhancedNativeCore {
	if skills == nil {
		skills = NewSkillRegistry()
	}
	return &EnhancedNativeCore{
		base:   NewNativeCore(opts),
		skills: skills,
	}
}

// SetWorkspace attaches the separated workspace manager (SYSTEM.md + user skills).
func (c *EnhancedNativeCore) SetWorkspace(ws *WorkspaceManager) {
	c.workspace = ws
}

func (c *EnhancedNativeCore) Name() string { return string(CoreNative) }

// Descriptor implements CapableCore.
func (c *EnhancedNativeCore) Descriptor(context.Context) CoreDescriptor {
	return CoreDescriptor{
		Name:        CoreNative,
		DisplayName: "内置原生核心 (qwq Native)",
		Protocol:    "openai-sse",
		Fallback:    "openai-json",
		Available:   true,
		Capabilities: CoreCapabilities{
			Streaming:             true,
			Reasoning:             true,
			PlanChecklist:         true,
			PlanMode:              true,
			Telemetry:             true,
			Compaction:            true,
			SlashCommands:         true,
			Skills:                true,
			Fork:                  true,
			Revert:                true,
			BidirectionalApproval: true,
			MCPHostTools:          true,
			ReasoningEffort:       true,
		},
	}
}

// Compact implements CompactableCore.
func (c *EnhancedNativeCore) Compact(ctx context.Context, req CompactRequest) (CompactionResult, error) {
	_, res, err := CompactTranscript(ctx, req.Messages, req.Options, nil)
	return res, err
}

// Run implements Core with streaming SSE, live telemetry, skills, plan tool & auto-compaction.
func (c *EnhancedNativeCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	cfg, err := decodeEnhancedNativeConfig(turn.Config)
	if err != nil {
		return err
	}
	var apiKey []byte
	providerKind := ProviderKindOpenAI
	if cfg.BaseURL == "" {
		if c.base.providers != nil {
			ep, found, pErr := c.base.providers.ResolveProvider(ctx, cfg.ProviderID)
			if pErr != nil {
				return problem.From(pErr)
			}
			if !found {
				if cfg.ProviderID != "" {
					return problem.New(problem.Unavailable,
						"The AI provider config.provider_id names no longer exists; pick another one or ask an administrator.")
				}
			} else {
				defer clear(ep.Key)
				apiKey = ep.Key
				cfg.BaseURL = ep.BaseURL
				if ep.Kind != "" {
					providerKind = ep.Kind
				}
				if cfg.Model == "" {
					cfg.Model = ep.Model
				}
				if cfg.ReasoningEffort == "" {
					cfg.ReasoningEffort = ep.ReasoningEffort
				}
				if cfg.MaxContextTokens == 0 {
					cfg.MaxContextTokens = ep.MaxContextTokens
				}
			}
		}
	} else {
		apiKey, err = c.base.apiKey(ctx, turn)
		if err != nil {
			return err
		}
		defer clear(apiKey)
	}
	if err := cfg.configured(); err != nil {
		return err
	}

	// Enforce Plan Mode read-only ceiling even if session PermissionMode is safe/full.
	effectiveTurn := turn
	if cfg.PlanMode {
		effectiveTurn.PermissionMode = operations.PermissionReadOnly
	}

	// Offer built-in task checklist tool only when PlanMode or EnablePlanTool
	// is requested so legacy tests asserting exact catalog tool counts stay intact.
	toolsWithPlan := append([]ToolSpec(nil), effectiveTurn.Tools...)
	if cfg.PlanMode || cfg.EnablePlanTool {
		toolsWithPlan = append(toolsWithPlan, ToolSpec{
			Action:  planToolActionName,
			Summary: "Update the structured task execution checklist displayed to the operator.",
			Effect:  "read",
			Risk:    "low",
			Parameters: json.RawMessage(`{
				"type":"object",
				"required":["items"],
				"properties":{
					"items":{
						"type":"array",
						"items":{
							"type":"object",
							"required":["id","title","status"],
							"properties":{
								"id":{"type":"string"},
								"title":{"type":"string"},
								"status":{"type":"string","enum":["pending","in_progress","completed","skipped"]},
								"note":{"type":"string"}
							}
						}
					}
				}
			}`),
		})
	}

	names := newToolNames(toolsWithPlan)
	sys := systemText(&cfg.nativeConfig)
	if c.workspace != nil {
		if customSys := c.workspace.ReadPromptForCore(CoreNative); customSys != "" {
			sys += "\n\n## User Custom Instructions (SYSTEM.md)\n" + customSys
		}
		if customSkills := c.workspace.LoadCustomSkillsPrompt(); customSkills != "" {
			sys += customSkills
		}
	}
	if cfg.PlanMode {
		sys += "\n\n## Plan Mode Active\nYou are in read-only Plan Mode. Inspect the host using read tools, call `" +
			planToolFunctionName + "` to maintain a clear checklist, and present a concrete change plan for operator approval without mutating host state."
	}
	sys += c.skills.BuildSkillPrompt(cfg.ActiveSkills)

	messages := make([]ModelMessage, 0, len(turn.Messages)+2)
	messages = append(messages, ModelMessage{Role: LoopRoleSystem, Content: sys})
	messages = append(messages, ApplyCompactionCheckpoint(turn.Messages, cfg.CompactionCheckpoint, names)...)

	// Step-boundary auto-compaction when context exceeds threshold.
	compOpts := CompactionOptions{
		MaxContextTokens: cfg.MaxContextTokens,
		AutoTriggerPct:   cfg.AutoCompactPct,
	}.normalized()
	toolDefs := names.defs()
	ctxBreak := EstimateContextBreakdown(sys, toolDefs, messages, compOpts.MaxContextTokens)
	if ctxBreak.Pct >= compOpts.AutoTriggerPct {
		compacted, compRes, cErr := CompactTranscript(ctx, messages, compOpts, nil)
		if cErr == nil && compRes.DroppedMessages > 0 {
			messages = compacted
			_ = emitExtended(emit, EventSessionCompacted, compRes)
		}
	}

	telemetry := TelemetrySnapshot{
		Turns:   1,
		Context: EstimateContextBreakdown(sys, toolDefs, messages, compOpts.MaxContextTokens),
	}

	baseTools := &nativeTools{names: names, runner: effectiveTurn.Runner, turn: effectiveTurn}
	wrappedTools := &enhancedTools{
		inner:     baseTools,
		emit:      emit,
		telemetry: &telemetry,
	}
	gate := c.base.gate
	if gate == nil {
		gate = nativeGate{tools: baseTools, mode: effectiveTurn.PermissionMode}
	}

	provider := &streamingOpenAIProvider{
		core:           c.base,
		cfg:            cfg,
		providerKind:   providerKind,
		apiKey:         apiKey,
		emit:           emit,
		telemetry:      &telemetry,
		sysText:        sys,
		toolDefs:       toolDefs,
		maxCtx:         compOpts.MaxContextTokens,
		thinkingKeeper: NewAnthropicThinkingKeeper(),
	}

	maxSteps := cfg.steps(c.base.steps)
	if maxSteps > maxEnhancedSteps {
		maxSteps = maxEnhancedSteps
	}

	baseLoopEmit := nativeEmit(emit, names)
	loopEmit := func(e LoopEvent) error {
		if e.Type == LoopEventDelta && provider.consumeStreamedDelta() {
			return nil
		}
		return baseLoopEmit(e)
	}
	_, err = RunLoop(ctx, provider, wrappedTools, gate, loopEmit, LoopOptions{
		Messages:   messages,
		MaxSteps:   maxSteps,
		NextCallID: turn.NextCallID,
	})

	// Emit final telemetry snapshot at turn exit for enhanced sessions.
	telemetry.Context = EstimateContextBreakdown(sys, toolDefs, messages, compOpts.MaxContextTokens)
	telemetry.ComputeDerived()
	telemetry.UpdatedAt = time.Now().UTC()
	if cfg.wantStream() || cfg.EnablePlanTool || cfg.PlanMode {
		_ = emitExtended(emit, EventTelemetryUpdated, telemetry)
	}

	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrLoopApproval):
		return ErrWaitingApproval
	case errors.Is(err, ErrLoopStepLimit):
		if cfg.SoftLanding {
			_ = emit(Event{
				Type:  EventMessageDelta,
				Delta: "\n\n（已达到单轮工具步数上限，以上为当前阶段性核查结论；如需继续执行请发送确认指令。）",
			})
			return nil
		}
		return problem.New(problem.Unavailable,
			"The agent did not finish within the tool-call step limit; send another message to continue.")
	default:
		return err
	}
}

// enhancedTools intercepts host.agent.update_plan locally (read-only metadata
// update, zero host mutation) and measures exact tool latency for DSH telemetry.
type enhancedTools struct {
	inner     *nativeTools
	emit      Emit
	telemetry *TelemetrySnapshot
}

func (t *enhancedTools) Tools() []ToolDef                 { return t.inner.Tools() }
func (t *enhancedTools) Spec(name string) (ToolDef, bool) { return t.inner.Spec(name) }

func (t *enhancedTools) Execute(ctx context.Context, call ModelToolCall) (ToolOutcome, error) {
	start := time.Now()
	defer func() {
		t.telemetry.ToolMS += time.Since(start).Milliseconds()
	}()

	if spec, ok := t.inner.Spec(call.Name); ok && spec.Action == planToolActionName {
		var payload struct {
			Items []PlanItem `json:"items"`
		}
		if err := json.Unmarshal(call.Arguments, &payload); err != nil {
			return ToolOutcome{
				Status: ToolFailed,
				Error:  problem.New(problem.ValidationFailed, "update_plan requires a JSON object with an items array."),
			}, nil
		}
		_ = emitExtended(t.emit, EventPlanUpdated, payload.Items)
		return ToolOutcome{Status: ToolSucceeded, Result: json.RawMessage(`{"updated":true}`)}, nil
	}

	return t.inner.Execute(ctx, call)
}

// streamingOpenAIProvider executes OpenAI-compatible SSE streaming requests,
// capturing TTFT, TPS, cached tokens, reasoning_content, and tool_call deltas.
type streamingOpenAIProvider struct {
	core           *NativeCore
	cfg            *enhancedNativeConfig
	providerKind   string
	apiKey         []byte
	emit           Emit
	telemetry      *TelemetrySnapshot
	sysText        string
	toolDefs       []ToolDef
	maxCtx         int64
	streamedDelta  bool
	thinkingKeeper *AnthropicThinkingKeeper
}

func (p *streamingOpenAIProvider) consumeStreamedDelta() bool {
	if !p.streamedDelta {
		return false
	}
	p.streamedDelta = false
	return true
}

type streamChatRequest struct {
	Model           string         `json:"model"`
	Messages        []chatMessage  `json:"messages"`
	Tools           []chatTool     `json:"tools,omitempty"`
	ToolChoice      string         `json:"tool_choice,omitempty"`
	Temperature     *float64       `json:"temperature,omitempty"`
	ReasoningEffort string         `json:"reasoning_effort,omitempty"`
	Stream          bool           `json:"stream,omitempty"`
	StreamOptions   map[string]any `json:"stream_options,omitempty"`
}

type openAIUsage struct {
	PromptTokens        int64 `json:"prompt_tokens"`
	CompletionTokens    int64 `json:"completion_tokens"`
	TotalTokens         int64 `json:"total_tokens"`
	PromptTokensDetails struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionTokensDetails struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

func (p *streamingOpenAIProvider) Complete(ctx context.Context, req ProviderRequest) (ProviderResponse, error) {
	p.telemetry.Steps++
	p.streamedDelta = false
	stepStart := time.Now()

	if p.providerKind == ProviderKindAnthropic {
		return p.completeAnthropic(ctx, req, stepStart)
	}

	effort, temp := ResolveOpenAIChatEffort(p.cfg.Model, p.cfg.ReasoningEffort, p.cfg.Temperature)
	body := streamChatRequest{
		Model:           p.cfg.Model,
		Messages:        toChatMessages(req.Messages),
		Tools:           chatToolsFromDefs(req.Tools),
		Temperature:     temp,
		ReasoningEffort: effort,
		Stream:          p.cfg.wantStream(),
	}
	if len(body.Tools) > 0 {
		body.ToolChoice = "auto"
	}
	if body.Stream {
		body.StreamOptions = map[string]any{"include_usage": true}
	}

	raw, err := json.Marshal(body)
	if err != nil {
		return ProviderResponse{}, problem.Wrap(err)
	}
	timeout := p.cfg.timeout()
	if p.core.timeout > 0 && p.core.timeout < timeout {
		timeout = p.core.timeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, p.cfg.BaseURL+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The native core's base_url cannot be used.")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if body.Stream {
		httpReq.Header.Set("Accept", "text/event-stream, application/json")
	} else {
		httpReq.Header.Set("Accept", "application/json")
	}
	if len(p.apiKey) > 0 {
		httpReq.Header.Set("Authorization", "Bearer "+string(p.apiKey))
	}

	resp, err := p.core.client.Do(httpReq)
	if err != nil {
		if errors.Is(err, errEgressDenied) {
			return ProviderResponse{}, problem.New(problem.PermissionDenied, "%s", egressDeniedDetail)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return ProviderResponse{}, problem.New(problem.Timeout, "The model did not answer before its deadline.")
		}
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model endpoint could not be reached.")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ProviderResponse{}, modelStatusError(resp.StatusCode)
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		return p.parseSSE(resp.Body, stepStart, req.Messages)
	}
	return p.parseJSON(resp.Body, stepStart, req.Messages)
}

func (p *streamingOpenAIProvider) parseJSON(r io.Reader, stepStart time.Time, msgs []ModelMessage) (ProviderResponse, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxModelResponse+1))
	if err != nil {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model endpoint did not answer.")
	}
	if len(data) > maxModelResponse {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model answered more than 1 MiB.")
	}
	var out struct {
		Choices []struct {
			Message struct {
				chatMessage
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
		Usage *openAIUsage `json:"usage"`
	}
	if err := json.Unmarshal(data, &out); err != nil || len(out.Choices) == 0 {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model endpoint returned an invalid response.")
	}
	msg := out.Choices[0].Message
	if msg.ReasoningContent != "" {
		_ = emitExtended(p.emit, EventReasoningDelta, map[string]string{"delta": msg.ReasoningContent})
	}
	p.recordUsage(stepStart, time.Since(stepStart), out.Usage, msg.Content, msgs)
	return toProviderResponse(msg.Content, msg.ToolCalls), nil
}

func (p *streamingOpenAIProvider) parseSSE(r io.Reader, stepStart time.Time, msgs []ModelMessage) (ProviderResponse, error) {
	sc := bufio.NewScanner(io.LimitReader(r, 4<<20))
	sc.Buffer(make([]byte, 0, 64<<10), 512<<10)

	var (
		contentBuf   strings.Builder
		firstTokenAt time.Time
		usage        *openAIUsage
		toolAcc      = map[int]*chatToolCall{}
		toolOrder    []int
	)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					Reasoning        string `json:"reasoning"`
					ToolCalls        []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
			Usage *openAIUsage `json:"usage"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		d := chunk.Choices[0].Delta
		reason := d.ReasoningContent
		if reason == "" {
			reason = d.Reasoning
		}
		if reason != "" {
			if firstTokenAt.IsZero() {
				firstTokenAt = time.Now()
			}
			_ = emitExtended(p.emit, EventReasoningDelta, map[string]string{"delta": reason})
		}
		if d.Content != "" {
			if firstTokenAt.IsZero() {
				firstTokenAt = time.Now()
			}
			contentBuf.WriteString(d.Content)
			if p.emit != nil {
				p.streamedDelta = true
				_ = p.emit(Event{Type: EventMessageDelta, Delta: d.Content})
			}
		}
		for _, tc := range d.ToolCalls {
			acc, ok := toolAcc[tc.Index]
			if !ok {
				acc = &chatToolCall{Type: "function"}
				toolAcc[tc.Index] = acc
				toolOrder = append(toolOrder, tc.Index)
			}
			if tc.ID != "" {
				acc.ID = tc.ID
			}
			if tc.Function.Name != "" {
				acc.Function.Name += tc.Function.Name
			}
			if tc.Function.Arguments != "" {
				acc.Function.Arguments += tc.Function.Arguments
			}
		}
	}

	calls := make([]chatToolCall, 0, len(toolOrder))
	for _, idx := range toolOrder {
		calls = append(calls, *toolAcc[idx])
	}
	ttft := time.Since(stepStart)
	if !firstTokenAt.IsZero() {
		ttft = firstTokenAt.Sub(stepStart)
	}
	p.recordUsage(stepStart, ttft, usage, contentBuf.String(), msgs)
	return toProviderResponse(contentBuf.String(), calls), nil
}

func (p *streamingOpenAIProvider) recordUsage(stepStart time.Time, ttft time.Duration, u *openAIUsage, text string, msgs []ModelMessage) {
	dur := time.Since(stepStart)
	p.telemetry.ModelMS += dur.Milliseconds()
	if p.telemetry.TTFTMS == 0 {
		p.telemetry.TTFTMS = ttft.Milliseconds()
	}
	if u != nil {
		p.telemetry.Tokens.Input += u.PromptTokens
		p.telemetry.Tokens.CachedRead += u.PromptTokensDetails.CachedTokens
		p.telemetry.Tokens.Output += u.CompletionTokens
		p.telemetry.Tokens.Reasoning += u.CompletionTokensDetails.ReasoningTokens
		p.telemetry.Tokens.Total += u.TotalTokens
	} else {
		estOut := EstimateTokens(text)
		p.telemetry.Tokens.Output += estOut
		p.telemetry.Tokens.Total += estOut
	}
	if p.telemetry.ModelMS > 0 && p.telemetry.Tokens.Output > 0 {
		p.telemetry.TPS = float64(p.telemetry.Tokens.Output) / (float64(p.telemetry.ModelMS) / 1000.0)
	}
	p.telemetry.Context = EstimateContextBreakdown(p.sysText, p.toolDefs, msgs, p.maxCtx)
	p.telemetry.ComputeDerived()
	if p.cfg.wantStream() || p.cfg.EnablePlanTool || p.cfg.PlanMode {
		_ = emitExtended(p.emit, EventTelemetryUpdated, *p.telemetry)
	}
}

func toProviderResponse(content string, calls []chatToolCall) ProviderResponse {
	out := ProviderResponse{Content: content}
	for _, call := range calls {
		var args json.RawMessage
		if call.Function.Arguments != "" {
			args = json.RawMessage(call.Function.Arguments)
		}
		out.ToolCalls = append(out.ToolCalls, ModelToolCall{
			CallID: call.ID, Name: call.Function.Name, Arguments: args,
		})
	}
	return out
}

func anthropicMessagesURL(baseURL string) string {
	u := strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(u, "/v1") {
		return u + "/messages"
	}
	return u + "/v1/messages"
}

func anthropicThinkingBudget(model, configured string) int {
	effort, matched, _ := ResolveReasoningEffort(model, configured)
	if strings.TrimSpace(configured) == "" && !matched {
		return 0
	}
	lower := strings.ToLower(strings.TrimSpace(effort))
	if IsReasoningEffortDisabled(lower) || lower == "none" {
		return 0
	}
	if n, ok := ParseNumericThinkingBudget(lower); ok {
		return n
	}
	switch lower {
	case "minimal":
		return 1024
	case "low":
		return 4096
	case "medium":
		return 10240
	case "high":
		return 24576
	case "xhigh":
		return 36864
	case "max":
		return 49152
	default:
		// Any custom non-disabled effort code enables deep thinking with a safe default budget.
		return 16384
	}
}

// completeAnthropic executes one Messages API turn against an Anthropic-compatible
// endpoint (official Anthropic API or third-party Claude relay) with full tool
// calling, extended thinking effort mapping, and usage telemetry.
func (p *streamingOpenAIProvider) completeAnthropic(ctx context.Context, req ProviderRequest, stepStart time.Time) (ProviderResponse, error) {
	var sysParts []string
	var msgs []map[string]any
	allToolTurnsHaveThinking := true
	for _, m := range req.Messages {
		switch m.Role {
		case LoopRoleSystem:
			if strings.TrimSpace(m.Content) != "" {
				sysParts = append(sysParts, m.Content)
			}
		case LoopRoleUser:
			msgs = append(msgs, map[string]any{"role": "user", "content": m.Content})
		case LoopRoleAssistant:
			if len(m.ToolCalls) == 0 {
				if m.Content != "" {
					msgs = append(msgs, map[string]any{"role": "assistant", "content": m.Content})
				}
			} else {
				blocks, hasThinking := p.thinkingKeeper.BuildAssistantMessageBlocks(m)
				if !hasThinking {
					allToolTurnsHaveThinking = false
				}
				msgs = append(msgs, map[string]any{"role": "assistant", "content": blocks})
			}
		case LoopRoleTool:
			block := map[string]any{
				"type":        "tool_result",
				"tool_use_id": m.ToolCallID,
				"content":     m.Content,
			}
			if len(msgs) > 0 && msgs[len(msgs)-1]["role"] == "user" {
				if prevBlocks, ok := msgs[len(msgs)-1]["content"].([]map[string]any); ok {
					msgs[len(msgs)-1]["content"] = append(prevBlocks, block)
					continue
				}
			}
			msgs = append(msgs, map[string]any{
				"role":    "user",
				"content": []map[string]any{block},
			})
		}
	}

	var tools []map[string]any
	for _, td := range req.Tools {
		var schema any = map[string]any{"type": "object", "properties": map[string]any{}}
		if len(td.Parameters) > 0 {
			_ = json.Unmarshal(td.Parameters, &schema)
		}
		tools = append(tools, map[string]any{
			"name":         td.Name,
			"description":  td.Description,
			"input_schema": schema,
		})
	}

	maxTokens := 8192
	payload := map[string]any{
		"model":      p.cfg.Model,
		"max_tokens": maxTokens,
		"messages":   msgs,
	}
	if len(sysParts) > 0 {
		payload["system"] = strings.Join(sysParts, "\n\n")
	}
	if len(tools) > 0 {
		payload["tools"] = tools
	}
	if budget := anthropicThinkingBudget(p.cfg.Model, p.cfg.ReasoningEffort); budget > 0 && allToolTurnsHaveThinking {
		if maxTokens <= budget {
			payload["max_tokens"] = budget + 4096
		}
		payload["thinking"] = map[string]any{
			"type":          "enabled",
			"budget_tokens": budget,
		}
	} else if p.cfg.Temperature != nil {
		payload["temperature"] = *p.cfg.Temperature
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return ProviderResponse{}, problem.Wrap(err)
	}
	timeout := p.cfg.timeout()
	if p.core.timeout > 0 && p.core.timeout < timeout {
		timeout = p.core.timeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, anthropicMessagesURL(p.cfg.BaseURL), bytes.NewReader(raw))
	if err != nil {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The native core's base_url cannot be used.")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	applyProviderAuthHeaders(httpReq, ProviderKindAnthropic, p.apiKey)

	resp, err := p.core.client.Do(httpReq)
	if err != nil {
		if errors.Is(err, errEgressDenied) {
			return ProviderResponse{}, problem.New(problem.PermissionDenied, "%s", egressDeniedDetail)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return ProviderResponse{}, problem.New(problem.Timeout, "The model did not answer before its deadline.")
		}
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model endpoint could not be reached.")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ProviderResponse{}, modelStatusError(resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxModelResponse+1))
	if err != nil {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model endpoint did not answer.")
	}
	if len(data) > maxModelResponse {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model answered more than 1 MiB.")
	}

	var out struct {
		Content []AnthropicResponseContentBlock `json:"content"`
		Usage   *struct {
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model endpoint returned an invalid response.")
	}
	p.thinkingKeeper.RecordAssistantTurn(out.Content)

	var textBuf strings.Builder
	var toolCalls []ModelToolCall
	for _, blk := range out.Content {
		switch blk.Type {
		case "thinking":
			if blk.Thinking != "" {
				_ = emitExtended(p.emit, EventReasoningDelta, map[string]string{"delta": blk.Thinking})
			}
		case "text":
			if blk.Text != "" {
				textBuf.WriteString(blk.Text)
			}
		case "tool_use":
			toolCalls = append(toolCalls, ModelToolCall{
				CallID: blk.ID, Name: blk.Name, Arguments: blk.Input,
			})
		}
	}
	var usage *openAIUsage
	if out.Usage != nil {
		usage = &openAIUsage{
			PromptTokens:     out.Usage.InputTokens + out.Usage.CacheReadInputTokens + out.Usage.CacheCreationInputTokens,
			CompletionTokens: out.Usage.OutputTokens,
			TotalTokens:      out.Usage.InputTokens + out.Usage.CacheReadInputTokens + out.Usage.CacheCreationInputTokens + out.Usage.OutputTokens,
		}
		usage.PromptTokensDetails.CachedTokens = out.Usage.CacheReadInputTokens
	}
	p.recordUsage(stepStart, time.Since(stepStart), usage, textBuf.String(), req.Messages)
	return ProviderResponse{Content: textBuf.String(), ToolCalls: toolCalls}, nil
}
