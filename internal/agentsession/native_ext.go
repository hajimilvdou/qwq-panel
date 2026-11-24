// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
	Stream               *bool                 `json:"stream,omitempty"` // nil defaults to true; explicit false disables streaming
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
		return true
	}
	return *c.Stream
}

func (c *enhancedNativeConfig) wantTelemetry() bool {
	return (c.Stream != nil && *c.Stream) || c.EnablePlanTool || c.PlanMode
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
	if cfg.wantTelemetry() {
		_ = emitExtended(emit, EventTelemetryUpdated, telemetry)
	}

	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrLoopApproval):
		return ErrWaitingApproval
	case errors.Is(err, ErrLoopStepLimit):
		if cfg.SoftLanding {
			const note = "\n\n（已达到单轮工具步数上限，以上为当前阶段性核查结论；如需继续执行请发送确认指令。）"
			_ = emit(Event{Type: EventMessageDelta, Delta: note})
			_ = emit(Event{Type: EventMessageCompleted})
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

func (p *streamingOpenAIProvider) RemapToolCallIDs(orig, normalized []ModelToolCall) {
	if p.thinkingKeeper != nil {
		p.thinkingKeeper.RemapToolCallIDs(orig, normalized)
	}
}

func (p *streamingOpenAIProvider) effectiveTimeout() time.Duration {
	timeout := p.cfg.timeout()
	if p.cfg.TimeoutSeconds == 0 && p.core.timeout > 0 {
		timeout = p.core.timeout
	}
	return timeout
}

func (p *streamingOpenAIProvider) streamIdleTimeout(timeout time.Duration) time.Duration {
	idle := defaultChunkIdleWait
	if timeout > 0 && timeout < idle {
		idle = timeout
	}
	return idle
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

	primaryBase, fallbackBase := normalizeOpenAICompatBaseURL(p.cfg.BaseURL)
	resp, reqCtx, stopHeaderTimer, cancelCause, err := p.doOpenAIHTTP(ctx, primaryBase, body)
	if err != nil {
		return ProviderResponse{}, err
	}
	// If the endpoint had no version path and returned 404 (e.g. local Ollama
	// at http://127.0.0.1:11434 or a root-served proxy), retry once against the
	// alternate path (/v1 vs root) before failing.
	if resp.StatusCode == http.StatusNotFound && fallbackBase != "" {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
		_ = resp.Body.Close()
		stopHeaderTimer()
		cancelCause(nil)
		resp, reqCtx, stopHeaderTimer, cancelCause, err = p.doOpenAIHTTP(ctx, fallbackBase, body)
		if err != nil {
			return ProviderResponse{}, err
		}
		primaryBase = fallbackBase
	}
	// OpenCode/DSH compatibility: many OpenAI-compatible gateways (Ollama,
	// vLLM, LiteLLM, OneAPI, non-reasoner endpoints) return HTTP 400 or 422
	// when optional `stream_options` or `reasoning_effort` fields are sent.
	// Retry once cleanly without those optional extensions before failing.
	if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity) &&
		(body.StreamOptions != nil || body.ReasoningEffort != "") {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
		_ = resp.Body.Close()
		stopHeaderTimer()
		cancelCause(nil)
		body.StreamOptions = nil
		body.ReasoningEffort = ""
		resp, reqCtx, stopHeaderTimer, cancelCause, err = p.doOpenAIHTTP(ctx, primaryBase, body)
		if err != nil {
			return ProviderResponse{}, err
		}
	}
	defer stopHeaderTimer()
	defer cancelCause(nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return ProviderResponse{}, formatUpstreamHTTPError(resp.StatusCode, errBody, p.apiKey)
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		stopHeaderTimer()
		idle := p.streamIdleTimeout(p.effectiveTimeout())
		streamReader := newIdleTimeoutReader(reqCtx, cancelCause, resp.Body, idle, maxSSEWireBytes)
		return p.parseSSE(streamReader, stepStart, req.Messages)
	}
	return p.parseJSON(resp.Body, stepStart, req.Messages)
}

func (p *streamingOpenAIProvider) doOpenAIHTTP(ctx context.Context, baseURL string, body streamChatRequest) (*http.Response, context.Context, func(), context.CancelCauseFunc, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, nil, nil, nil, problem.Wrap(err)
	}
	timeout := p.effectiveTimeout()
	reqCtx, cancelCause := context.WithCancelCause(ctx)
	hdrTimer := time.AfterFunc(timeout, func() { cancelCause(context.DeadlineExceeded) })
	stopTimer := func() { hdrTimer.Stop() }

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		stopTimer()
		cancelCause(nil)
		return nil, nil, nil, nil, problem.New(problem.Unavailable, "The native core's base_url cannot be used.")
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
		cause := context.Cause(reqCtx)
		stopTimer()
		cancelCause(nil)
		if errors.Is(err, errEgressDenied) {
			return nil, nil, nil, nil, problem.New(problem.PermissionDenied, "%s", egressDeniedDetail)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(cause, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return nil, nil, nil, nil, problem.New(problem.Timeout, "The model did not answer before its deadline.")
		}
		return nil, nil, nil, nil, problem.New(problem.Unavailable, "The model endpoint could not be reached.")
	}
	return resp, reqCtx, stopTimer, cancelCause, nil
}

// thinkTagSplitter separates leading `<think>...</think>` blocks emitted inline
// inside `delta.content` by Ollama / DeepSeek-R1 / QwQ endpoints into
// reasoning vs visible answer deltas across arbitrary SSE chunk boundaries.
type thinkTagSplitter struct {
	state int // 0=detecting, 1=inside <think>, 2=passthrough
	buf   string
}

const (
	thinkOpenTag  = "<think>"
	thinkCloseTag = "</think>"
)

func (s *thinkTagSplitter) Feed(chunk string) (reasoning, text string) {
	if chunk == "" {
		return "", ""
	}
	if s.state == 2 {
		return "", chunk
	}
	s.buf += chunk
	if s.state == 0 {
		trimmed := strings.TrimLeft(s.buf, " \t\r\n")
		if trimmed == "" {
			return "", ""
		}
		if strings.HasPrefix(trimmed, thinkOpenTag) {
			s.state = 1
			s.buf = trimmed[len(thinkOpenTag):]
		} else if strings.HasPrefix(thinkOpenTag, trimmed) {
			// Wait for more bytes to decide whether stream starts with <think>.
			return "", ""
		} else {
			s.state = 2
			out := s.buf
			s.buf = ""
			return "", out
		}
	}
	if s.state == 1 {
		if idx := strings.Index(s.buf, thinkCloseTag); idx >= 0 {
			reason := s.buf[:idx]
			rest := strings.TrimLeft(s.buf[idx+len(thinkCloseTag):], "\r\n")
			s.buf = ""
			s.state = 2
			return reason, rest
		}
		// Keep a short tail in case `</think>` is split across SSE chunks,
		// stepping back to a valid UTF-8 rune boundary so multi-byte characters
		// (e.g. CJK) are never bisected across emitted deltas.
		keep := len(thinkCloseTag) - 1
		if len(s.buf) > keep {
			cut := len(s.buf) - keep
			for cut > 0 && !utf8.RuneStart(s.buf[cut]) {
				cut--
			}
			if cut == 0 {
				return "", ""
			}
			reason := s.buf[:cut]
			s.buf = s.buf[cut:]
			return reason, ""
		}
		return "", ""
	}
	return "", ""
}

func (s *thinkTagSplitter) Flush() (reasoning, text string) {
	if s.buf == "" {
		return "", ""
	}
	rem := s.buf
	s.buf = ""
	if s.state == 1 {
		return rem, ""
	}
	return "", rem
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
				Reasoning        string `json:"reasoning"`
			} `json:"message"`
		} `json:"choices"`
		Usage *openAIUsage `json:"usage"`
	}
	if err := json.Unmarshal(data, &out); err != nil || len(out.Choices) == 0 {
		if msg := extractSafeUpstreamErrorMsg(data, p.apiKey); msg != "" {
			return ProviderResponse{}, problem.New(problem.Unavailable, "上游模型返回错误：%s", msg)
		}
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model endpoint returned an invalid response.")
	}
	msg := out.Choices[0].Message
	reason := msg.ReasoningContent
	if reason == "" {
		reason = msg.Reasoning
	}
	content := msg.Content
	if reason == "" && strings.Contains(content, thinkOpenTag) {
		var sp thinkTagSplitter
		r1, t1 := sp.Feed(content)
		r2, t2 := sp.Flush()
		if r1+r2 != "" {
			reason = r1 + r2
			content = t1 + t2
		}
	}
	if reason != "" {
		_ = emitExtended(p.emit, EventReasoningDelta, map[string]string{"delta": reason})
	}
	p.recordUsage(stepStart, time.Since(stepStart), out.Usage, content, msgs)
	return toProviderResponse(content, reason, msg.ToolCalls), nil
}

func (p *streamingOpenAIProvider) parseSSE(r io.Reader, stepStart time.Time, msgs []ModelMessage) (ProviderResponse, error) {
	br := bufio.NewReaderSize(r, 64<<10)

	var (
		contentBuf   strings.Builder
		reasonBuf    strings.Builder
		firstTokenAt time.Time
		usage        *openAIUsage
		toolSlots    []*chatToolCall
		toolByIndex  = map[int]*chatToolCall{}
		toolByID     = map[string]*chatToolCall{}
		thinkSplit   thinkTagSplitter
		sawReasonKey bool
	)

	emitReasoning := func(s string) {
		if s == "" {
			return
		}
		if firstTokenAt.IsZero() {
			firstTokenAt = time.Now()
		}
		reasonBuf.WriteString(s)
		_ = emitExtended(p.emit, EventReasoningDelta, map[string]string{"delta": s})
	}
	emitContent := func(s string) {
		if s == "" {
			return
		}
		if firstTokenAt.IsZero() {
			firstTokenAt = time.Now()
		}
		contentBuf.WriteString(s)
		if p.emit != nil {
			p.streamedDelta = true
			_ = p.emit(Event{Type: EventMessageDelta, Delta: s})
		}
	}

	var readErr error
	for {
		rawLine, err := readSSELineUnlimited(br, 4<<20)
		if rawLine != "" {
			line := strings.TrimSpace(rawLine)
			if strings.HasPrefix(line, "data:") {
				payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if payload != "" && payload != "[DONE]" {
					var chunk struct {
						Error   any `json:"error"`
						Choices []struct {
							Delta struct {
								Content          string `json:"content"`
								ReasoningContent string `json:"reasoning_content"`
								Reasoning        string `json:"reasoning"`
								ToolCalls        []struct {
									Index    *int   `json:"index"`
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
					if json.Unmarshal([]byte(payload), &chunk) == nil {
						if chunk.Error != nil && len(chunk.Choices) == 0 {
							msg := extractSafeUpstreamErrorMsg([]byte(payload), p.apiKey)
							if msg != "" {
								return ProviderResponse{}, problem.New(problem.Unavailable, "上游模型流式返回错误：%s", msg)
							}
							return ProviderResponse{}, problem.New(problem.Unavailable, "The model stream returned an error.")
						}
						if chunk.Usage != nil {
							usage = chunk.Usage
						}
						if len(chunk.Choices) > 0 {
							d := chunk.Choices[0].Delta
							reason := d.ReasoningContent
							if reason == "" {
								reason = d.Reasoning
							}
							if reason != "" {
								sawReasonKey = true
								emitReasoning(reason)
							}
							if d.Content != "" {
								if sawReasonKey {
									emitContent(d.Content)
								} else {
									rPart, tPart := thinkSplit.Feed(d.Content)
									emitReasoning(rPart)
									emitContent(tPart)
								}
							}
							for _, tc := range d.ToolCalls {
								var acc *chatToolCall
								if tc.ID != "" {
									acc = toolByID[tc.ID]
								}
								if acc == nil && tc.Index != nil {
									if candidate := toolByIndex[*tc.Index]; candidate != nil {
										if tc.ID == "" || candidate.ID == "" || candidate.ID == tc.ID {
											acc = candidate
										}
									}
								}
								if acc == nil && tc.Index == nil && tc.ID == "" && len(toolSlots) > 0 {
									acc = toolSlots[len(toolSlots)-1]
								}
								if acc == nil {
									acc = &chatToolCall{Type: "function"}
									toolSlots = append(toolSlots, acc)
									if tc.Index != nil {
										toolByIndex[*tc.Index] = acc
									}
								}
								if tc.ID != "" {
									acc.ID = tc.ID
									toolByID[tc.ID] = acc
								}
								if tc.Function.Name != "" {
									acc.Function.Name += tc.Function.Name
								}
								if tc.Function.Arguments != "" {
									acc.Function.Arguments += tc.Function.Arguments
								}
							}
						}
					}
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
	}
	if readErr != nil {
		if errors.Is(readErr, errSSEIdleTimeout) {
			return ProviderResponse{}, problem.New(problem.Timeout, "%s", readErr.Error())
		}
		if errors.Is(readErr, errSSEWireLimitExceeded) {
			return ProviderResponse{}, problem.New(problem.Unavailable, "%s", readErr.Error())
		}
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model stream was interrupted before completion.")
	}
	if !sawReasonKey {
		rRem, tRem := thinkSplit.Flush()
		emitReasoning(rRem)
		emitContent(tRem)
	}

	calls := make([]chatToolCall, 0, len(toolSlots))
	for _, acc := range toolSlots {
		calls = append(calls, *acc)
	}
	if contentBuf.Len() == 0 && reasonBuf.Len() == 0 && len(calls) == 0 {
		return ProviderResponse{}, problem.New(problem.Unavailable, "上游模型流式响应未返回有效内容。")
	}
	ttft := time.Since(stepStart)
	if !firstTokenAt.IsZero() {
		ttft = firstTokenAt.Sub(stepStart)
	}
	p.recordUsage(stepStart, ttft, usage, contentBuf.String(), msgs)
	return toProviderResponse(contentBuf.String(), reasonBuf.String(), calls), nil
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
	if p.cfg.wantTelemetry() {
		_ = emitExtended(p.emit, EventTelemetryUpdated, *p.telemetry)
	}
}

func toProviderResponse(content, reasoning string, calls []chatToolCall) ProviderResponse {
	out := ProviderResponse{Content: content, ReasoningContent: reasoning}
	for _, call := range calls {
		rawArgs := strings.TrimSpace(call.Function.Arguments)
		var args json.RawMessage
		if rawArgs == "" {
			args = json.RawMessage("{}")
		} else {
			args = json.RawMessage(rawArgs)
		}
		out.ToolCalls = append(out.ToolCalls, ModelToolCall{
			CallID: call.ID, Name: call.Function.Name, Arguments: args,
		})
	}
	return out
}

func anthropicMessagesURL(baseURL string) string {
	return normalizeAnthropicCLIBaseURL(baseURL) + "/v1/messages"
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
// endpoint (official Anthropic API or third-party Claude relay) with true SSE
// streaming (plus automatic JSON fallback), tool calling, extended thinking
// signature preservation, and usage telemetry.
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
	if p.cfg.wantStream() {
		payload["stream"] = true
	}
	if len(sysParts) > 0 {
		payload["system"] = strings.Join(sysParts, "\n\n")
	}
	if len(tools) > 0 {
		payload["tools"] = tools
	}
	if budget := anthropicThinkingBudget(p.cfg.Model, p.cfg.ReasoningEffort); budget > 0 && allToolTurnsHaveThinking {
		reqMax := maxTokens
		if reqMax <= budget {
			reqMax = budget + 4096
		}
		cappedMax, cappedBudget := CapAnthropicMaxTokens(p.cfg.Model, reqMax, budget)
		payload["max_tokens"] = cappedMax
		if cappedBudget > 0 {
			payload["thinking"] = map[string]any{
				"type":          "enabled",
				"budget_tokens": cappedBudget,
			}
		} else if p.cfg.Temperature != nil {
			payload["temperature"] = *p.cfg.Temperature
		}
	} else if p.cfg.Temperature != nil {
		payload["temperature"] = *p.cfg.Temperature
	}

	resp, reqCtx, stopHeaderTimer, cancelCause, err := p.doAnthropicHTTP(ctx, payload)
	if err != nil {
		return ProviderResponse{}, err
	}
	// If an Anthropic-compatible gateway rejects auto-injected extended thinking
	// parameters with 400/422, retry once cleanly without `thinking`.
	if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity) &&
		payload["thinking"] != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
		_ = resp.Body.Close()
		stopHeaderTimer()
		cancelCause(nil)
		delete(payload, "thinking")
		payload["max_tokens"] = maxTokens
		if p.cfg.Temperature != nil {
			payload["temperature"] = *p.cfg.Temperature
		}
		resp, reqCtx, stopHeaderTimer, cancelCause, err = p.doAnthropicHTTP(ctx, payload)
		if err != nil {
			return ProviderResponse{}, err
		}
	}
	defer stopHeaderTimer()
	defer cancelCause(nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return ProviderResponse{}, formatUpstreamHTTPError(resp.StatusCode, errBody, p.apiKey)
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		stopHeaderTimer()
		idle := p.streamIdleTimeout(p.effectiveTimeout())
		streamReader := newIdleTimeoutReader(reqCtx, cancelCause, resp.Body, idle, maxSSEWireBytes)
		return p.parseAnthropicSSE(streamReader, stepStart, req.Messages)
	}
	return p.parseAnthropicJSON(resp.Body, stepStart, req.Messages)
}

func (p *streamingOpenAIProvider) doAnthropicHTTP(ctx context.Context, payload map[string]any) (*http.Response, context.Context, func(), context.CancelCauseFunc, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, nil, nil, problem.Wrap(err)
	}
	timeout := p.effectiveTimeout()
	reqCtx, cancelCause := context.WithCancelCause(ctx)
	hdrTimer := time.AfterFunc(timeout, func() { cancelCause(context.DeadlineExceeded) })
	stopTimer := func() { hdrTimer.Stop() }

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, anthropicMessagesURL(p.cfg.BaseURL), bytes.NewReader(raw))
	if err != nil {
		stopTimer()
		cancelCause(nil)
		return nil, nil, nil, nil, problem.New(problem.Unavailable, "The native core's base_url cannot be used.")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.cfg.wantStream() {
		httpReq.Header.Set("Accept", "text/event-stream, application/json")
	} else {
		httpReq.Header.Set("Accept", "application/json")
	}
	applyProviderAuthHeaders(httpReq, ProviderKindAnthropic, p.apiKey)

	resp, err := p.core.client.Do(httpReq)
	if err != nil {
		cause := context.Cause(reqCtx)
		stopTimer()
		cancelCause(nil)
		if errors.Is(err, errEgressDenied) {
			return nil, nil, nil, nil, problem.New(problem.PermissionDenied, "%s", egressDeniedDetail)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(cause, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return nil, nil, nil, nil, problem.New(problem.Timeout, "The model did not answer before its deadline.")
		}
		return nil, nil, nil, nil, problem.New(problem.Unavailable, "The model endpoint could not be reached.")
	}
	return resp, reqCtx, stopTimer, cancelCause, nil
}

func (p *streamingOpenAIProvider) parseAnthropicJSON(r io.Reader, stepStart time.Time, msgs []ModelMessage) (ProviderResponse, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxModelResponse+1))
	if err != nil {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model endpoint did not answer.")
	}
	if len(data) > maxModelResponse {
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model answered more than 1 MiB.")
	}

	var out struct {
		Type    string                          `json:"type"`
		Error   any                             `json:"error"`
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
	if out.Type == "error" || out.Error != nil {
		if msg := extractSafeUpstreamErrorMsg(data, p.apiKey); msg != "" {
			return ProviderResponse{}, problem.New(problem.Unavailable, "上游模型返回错误：%s", msg)
		}
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model endpoint returned an error.")
	}
	if len(out.Content) == 0 {
		return ProviderResponse{}, problem.New(problem.Unavailable, "上游模型响应未返回有效内容。")
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
			args := blk.Input
			if len(bytes.TrimSpace(args)) == 0 {
				args = json.RawMessage("{}")
			}
			toolCalls = append(toolCalls, ModelToolCall{
				CallID: blk.ID, Name: blk.Name, Arguments: args,
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
	p.recordUsage(stepStart, time.Since(stepStart), usage, textBuf.String(), msgs)
	return ProviderResponse{Content: textBuf.String(), ToolCalls: toolCalls}, nil
}

func (p *streamingOpenAIProvider) parseAnthropicSSE(r io.Reader, stepStart time.Time, msgs []ModelMessage) (ProviderResponse, error) {
	br := bufio.NewReaderSize(r, 64<<10)

	type blockAcc struct {
		typ       string
		id        string
		name      string
		text      strings.Builder
		thinking  strings.Builder
		signature strings.Builder
		inputJSON strings.Builder
		data      string
	}
	var (
		blocks       = map[int]*blockAcc{}
		blockOrder   []int
		textBuf      strings.Builder
		firstTokenAt time.Time
		usage        openAIUsage
		hasUsage     bool
	)

	var readErr error
	for {
		rawLine, err := readSSELineUnlimited(br, 4<<20)
		if rawLine != "" {
			line := strings.TrimSpace(rawLine)
			if strings.HasPrefix(line, "data:") {
				payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if payload != "" && payload != "[DONE]" {
					var ev struct {
						Type    string `json:"type"`
						Index   int    `json:"index"`
						Error   any    `json:"error"`
						Message *struct {
							Usage *struct {
								InputTokens              int64 `json:"input_tokens"`
								CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
								CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
							} `json:"usage"`
						} `json:"message"`
						ContentBlock *struct {
							Type string `json:"type"`
							ID   string `json:"id"`
							Name string `json:"name"`
							Data string `json:"data"`
						} `json:"content_block"`
						Delta *struct {
							Type        string `json:"type"`
							Text        string `json:"text"`
							Thinking    string `json:"thinking"`
							Signature   string `json:"signature"`
							PartialJSON string `json:"partial_json"`
						} `json:"delta"`
						Usage *struct {
							OutputTokens int64 `json:"output_tokens"`
						} `json:"usage"`
					}
					if json.Unmarshal([]byte(payload), &ev) == nil {
						if ev.Type == "error" || (ev.Error != nil && ev.Type == "") {
							if msg := extractSafeUpstreamErrorMsg([]byte(payload), p.apiKey); msg != "" {
								return ProviderResponse{}, problem.New(problem.Unavailable, "上游模型流式返回错误：%s", msg)
							}
							return ProviderResponse{}, problem.New(problem.Unavailable, "The model stream returned an error.")
						}
						switch ev.Type {
						case "message_start":
							if ev.Message != nil && ev.Message.Usage != nil {
								hasUsage = true
								u := ev.Message.Usage
								usage.PromptTokens = u.InputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens
								usage.PromptTokensDetails.CachedTokens = u.CacheReadInputTokens
							}
						case "content_block_start":
							if ev.ContentBlock != nil {
								acc := &blockAcc{
									typ:  ev.ContentBlock.Type,
									id:   ev.ContentBlock.ID,
									name: ev.ContentBlock.Name,
									data: ev.ContentBlock.Data,
								}
								if _, exists := blocks[ev.Index]; !exists {
									blockOrder = append(blockOrder, ev.Index)
								}
								blocks[ev.Index] = acc
							}
						case "content_block_delta":
							if ev.Delta == nil {
								break
							}
							acc := blocks[ev.Index]
							if acc == nil {
								acc = &blockAcc{}
								blocks[ev.Index] = acc
								blockOrder = append(blockOrder, ev.Index)
							}
							switch ev.Delta.Type {
							case "thinking_delta":
								if ev.Delta.Thinking != "" {
									if firstTokenAt.IsZero() {
										firstTokenAt = time.Now()
									}
									acc.thinking.WriteString(ev.Delta.Thinking)
									_ = emitExtended(p.emit, EventReasoningDelta, map[string]string{"delta": ev.Delta.Thinking})
								}
							case "signature_delta":
								acc.signature.WriteString(ev.Delta.Signature)
							case "text_delta":
								if ev.Delta.Text != "" {
									if firstTokenAt.IsZero() {
										firstTokenAt = time.Now()
									}
									acc.text.WriteString(ev.Delta.Text)
									textBuf.WriteString(ev.Delta.Text)
									if p.emit != nil {
										p.streamedDelta = true
										_ = p.emit(Event{Type: EventMessageDelta, Delta: ev.Delta.Text})
									}
								}
							case "input_json_delta":
								acc.inputJSON.WriteString(ev.Delta.PartialJSON)
							}
						case "message_delta":
							if ev.Usage != nil {
								hasUsage = true
								usage.CompletionTokens = ev.Usage.OutputTokens
								usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
							}
						}
					}
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
	}
	if readErr != nil {
		if errors.Is(readErr, errSSEIdleTimeout) {
			return ProviderResponse{}, problem.New(problem.Timeout, "%s", readErr.Error())
		}
		if errors.Is(readErr, errSSEWireLimitExceeded) {
			return ProviderResponse{}, problem.New(problem.Unavailable, "%s", readErr.Error())
		}
		return ProviderResponse{}, problem.New(problem.Unavailable, "The model stream was interrupted before completion.")
	}

	recorded := make([]AnthropicResponseContentBlock, 0, len(blockOrder))
	var toolCalls []ModelToolCall
	for _, idx := range blockOrder {
		acc := blocks[idx]
		blk := AnthropicResponseContentBlock{
			Type:      acc.typ,
			ID:        acc.id,
			Name:      acc.name,
			Text:      acc.text.String(),
			Thinking:  acc.thinking.String(),
			Signature: acc.signature.String(),
			Data:      acc.data,
		}
		if acc.typ == "tool_use" {
			rawInput := strings.TrimSpace(acc.inputJSON.String())
			if rawInput == "" {
				rawInput = "{}"
			}
			blk.Input = json.RawMessage(rawInput)
			toolCalls = append(toolCalls, ModelToolCall{
				CallID: acc.id, Name: acc.name, Arguments: blk.Input,
			})
		}
		recorded = append(recorded, blk)
	}
	if textBuf.Len() == 0 && len(toolCalls) == 0 && len(recorded) == 0 {
		return ProviderResponse{}, problem.New(problem.Unavailable, "上游模型流式响应未返回有效内容。")
	}
	p.thinkingKeeper.RecordAssistantTurn(recorded)

	ttft := time.Since(stepStart)
	if !firstTokenAt.IsZero() {
		ttft = firstTokenAt.Sub(stepStart)
	}
	var usagePtr *openAIUsage
	if hasUsage {
		usagePtr = &usage
	}
	p.recordUsage(stepStart, ttft, usagePtr, textBuf.String(), msgs)
	return ProviderResponse{Content: textBuf.String(), ToolCalls: toolCalls}, nil
}

// ============================================================================
// URL Normalization, Idle-Timeout SSE Reader & Redacted Upstream Error Mapping
// ============================================================================

const (
	maxSSEWireBytes      = 32 << 20
	defaultChunkIdleWait = 90 * time.Second
)

var (
	errSSEWireLimitExceeded = errors.New("上游模型单次流式响应体积超出 32 MiB 安全上限")
	errSSEIdleTimeout       = errors.New("等待上游模型流式响应超时")
	secretRedactionRe       = regexp.MustCompile(`(?i)(bearer\s+\S+|sk-[A-Za-z0-9_\-]{6,}|api[_-]?key[=:]\s*\S+)`)
)

// normalizeOpenAICompatBaseURL cleans accidental action suffixes
// (/chat/completions, /responses, /models) and supplies a /v1 candidate when
// the path is empty. For loopback endpoints (local Ollama or unit test mocks),
// the raw root is tried first with /v1 as fallback on 404; for remote hosts
// /v1 is tried first with root as fallback on 404.
func normalizeOpenAICompatBaseURL(raw string) (primary, fallback string) {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	for _, suffix := range []string{"/chat/completions", "/responses", "/models"} {
		if strings.HasSuffix(strings.ToLower(s), suffix) {
			s = strings.TrimRight(s[:len(s)-len(suffix)], "/")
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s, ""
	}
	cleanPath := strings.Trim(u.Path, "/")
	if strings.EqualFold(u.Host, "openrouter.ai") && strings.EqualFold(cleanPath, "api") {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1"
		return strings.TrimRight(u.String(), "/"), ""
	}
	if cleanPath == "" {
		u2 := *u
		u2.Path = "/v1"
		withV1 := strings.TrimRight(u2.String(), "/")
		host := strings.ToLower(u.Hostname())
		if host == "127.0.0.1" || host == "::1" || host == "localhost" {
			return s, withV1
		}
		return withV1, s
	}
	return s, ""
}

// normalizeAnthropicCLIBaseURL strips trailing /messages and /v1 before
// injecting ANTHROPIC_BASE_URL for Claude Code CLI (which appends /v1/messages).
func normalizeAnthropicCLIBaseURL(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if strings.HasSuffix(strings.ToLower(s), "/messages") {
		s = strings.TrimRight(s[:len(s)-len("/messages")], "/")
	}
	if strings.HasSuffix(strings.ToLower(s), "/v1") {
		s = strings.TrimRight(s[:len(s)-len("/v1")], "/")
	}
	return s
}

type idleTimeoutReader struct {
	reqCtx      context.Context
	cancelCause context.CancelCauseFunc
	raw         io.Reader
	idleLimit   time.Duration
	maxBytes    int64
	readTotal   int64
}

func newIdleTimeoutReader(reqCtx context.Context, cancelCause context.CancelCauseFunc, body io.Reader, idleLimit time.Duration, maxBytes int64) *idleTimeoutReader {
	if idleLimit <= 0 {
		idleLimit = defaultChunkIdleWait
	}
	if maxBytes <= 0 {
		maxBytes = maxSSEWireBytes
	}
	return &idleTimeoutReader{
		reqCtx:      reqCtx,
		cancelCause: cancelCause,
		raw:         body,
		idleLimit:   idleLimit,
		maxBytes:    maxBytes,
	}
}

func (ir *idleTimeoutReader) Read(p []byte) (int, error) {
	if err := ir.reqCtx.Err(); err != nil {
		if cause := context.Cause(ir.reqCtx); cause != nil {
			return 0, cause
		}
		return 0, err
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(ir.idleLimit, func() {
		timedOut.Store(true)
		if ir.cancelCause != nil {
			ir.cancelCause(fmt.Errorf("%w（连续 %s 无数据返回）", errSSEIdleTimeout, ir.idleLimit))
		}
	})
	n, err := ir.raw.Read(p)
	timer.Stop()
	if timedOut.Load() {
		return n, fmt.Errorf("%w（连续 %s 无数据返回）", errSSEIdleTimeout, ir.idleLimit)
	}
	if err != nil {
		if cause := context.Cause(ir.reqCtx); errors.Is(cause, errSSEIdleTimeout) {
			return n, cause
		}
		return n, err
	}
	ir.readTotal += int64(n)
	if ir.readTotal > ir.maxBytes {
		if ir.cancelCause != nil {
			ir.cancelCause(errSSEWireLimitExceeded)
		}
		return n, errSSEWireLimitExceeded
	}
	return n, nil
}

func readSSELineUnlimited(br *bufio.Reader, maxLineBytes int) (string, error) {
	if maxLineBytes <= 0 {
		maxLineBytes = 4 << 20
	}
	var buf []byte
	for {
		frag, isPrefix, err := br.ReadLine()
		buf = append(buf, frag...)
		if len(buf) > maxLineBytes {
			return "", fmt.Errorf("单条 SSE 数据帧超过 %d 字节上限", maxLineBytes)
		}
		if !isPrefix || err != nil {
			return string(buf), err
		}
	}
}

func formatUpstreamHTTPError(statusCode int, respBody []byte, apiKey []byte) error {
	detail := extractSafeUpstreamErrorMsg(respBody, apiKey)
	var base string
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		base = fmt.Sprintf("AI 接口鉴权失败 (HTTP %d)：请检查 API Key 是否正确、是否过期或有无该模型权限", statusCode)
	case http.StatusPaymentRequired:
		base = "AI 账户余额或配额不足 (HTTP 402)：请检查上游服务商账单额度"
	case http.StatusNotFound:
		base = "AI 接口地址或模型不存在 (HTTP 404)：请检查 Base URL 是否漏掉 /v1 以及模型名称是否拼写正确"
	case http.StatusTooManyRequests:
		base = "AI 接口请求过于频繁或额度受限 (HTTP 429)：请稍后重试或切换模型/渠道"
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		base = fmt.Sprintf("AI 模型拒绝了请求参数 (HTTP %d)：请检查模型名是否支持工具调用/思考强度设置", statusCode)
	default:
		if statusCode >= 500 {
			base = fmt.Sprintf("上游 AI 服务商内部故障或网关超时 (HTTP %d)", statusCode)
		} else {
			base = fmt.Sprintf("AI 接口请求异常 (HTTP %d)", statusCode)
		}
	}
	if detail != "" {
		return problem.New(problem.Unavailable, "%s —— 上游详情：%s", base, detail)
	}
	return problem.New(problem.Unavailable, "%s", base)
}

func extractSafeUpstreamErrorMsg(raw []byte, apiKey []byte) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ""
	}
	var envelope struct {
		Error any    `json:"error"`
		Msg   string `json:"message"`
	}
	if json.Unmarshal(raw, &envelope) == nil {
		switch v := envelope.Error.(type) {
		case string:
			trimmed = v
		case map[string]any:
			if m, ok := v["message"].(string); ok && strings.TrimSpace(m) != "" {
				trimmed = m
			}
		default:
			if envelope.Msg != "" {
				trimmed = envelope.Msg
			}
		}
	}
	return sanitizeUpstreamErrorDetail(trimmed, apiKey)
}

func sanitizeUpstreamErrorDetail(trimmed string, apiKey []byte) string {
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return ""
	}
	low := strings.ToLower(trimmed)
	if strings.HasPrefix(low, "<!doctype") || strings.HasPrefix(low, "<html") {
		return ""
	}
	if len(apiKey) > 0 {
		trimmed = strings.ReplaceAll(trimmed, string(apiKey), "[REDACTED]")
	}
	trimmed = secretRedactionRe.ReplaceAllString(trimmed, "[REDACTED]")
	trimmed = strings.Join(strings.Fields(trimmed), " ")
	return clipText(trimmed, 240)
}
