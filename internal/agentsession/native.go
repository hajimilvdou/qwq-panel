// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
)

// Defaults of the built-in native core.
const (
	defaultModelTimeout = 60 * time.Second
	maxModelTimeout     = 300 * time.Second
	defaultMaxSteps     = 8
	maxModelResponse    = 1 << 20
)

// nativeConfig is the session config of the native core. It never contains a
// secret nor a secret reference: the API key is stored per session with
// Service.SetAPIKey and reaches the core as Turn.APIKeyRef (AGT-02), so the
// config row, the SSE stream and the API responses stay safe to show. A legacy
// api_key_secret field in an old row is ignored.
type nativeConfig struct {
	BaseURL string `json:"base_url"`
	// ProviderID names a global AI provider (GAP-2, ADR-0017). When it is set
	// the endpoint, the default model and the API key come from the provider
	// and BaseURL must stay empty, so an administrator's key can never be sent
	// to an address the session picked.
	ProviderID     string   `json:"provider_id"`
	Model          string   `json:"model"`
	SystemPrompt   string   `json:"system_prompt"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	MaxSteps       int      `json:"max_steps"`
	Temperature    *float64 `json:"temperature"`
}

// decodeNativeConfig parses and validates the native section of a session
// config. A missing base_url/model is not an error here: an incomplete session
// may be created, and Send then answers UNAVAILABLE with a clear message.
func decodeNativeConfig(raw json.RawMessage) (*nativeConfig, error) {
	cfg := &nativeConfig{}
	if len(raw) == 0 {
		return cfg, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(cfg); err != nil {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID", Message: "config is not a valid native core configuration.",
		})
	}
	if cfg.BaseURL != "" {
		v, err := ValidateModelBaseURL(cfg.BaseURL, "/config/base_url")
		if err != nil {
			return nil, err
		}
		cfg.BaseURL = v
	}
	if cfg.ProviderID != "" {
		if !ids.Valid(cfg.ProviderID, providerPrefix) {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/provider_id", Code: "INVALID",
				Message: "provider_id is not an AI provider identifier.",
			})
		}
		if cfg.BaseURL != "" {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/config/base_url", Code: "CONFLICT",
				Message: "config.base_url must be empty when config.provider_id is set.",
			})
		}
	}
	if cfg.TimeoutSeconds < 0 || cfg.TimeoutSeconds > int(maxModelTimeout/time.Second) {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config/timeout_seconds", Code: "OUT_OF_RANGE",
			Message: "timeout_seconds must be between 1 and 300.",
		})
	}
	if cfg.MaxSteps < 0 || cfg.MaxSteps > defaultMaxSteps {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config/max_steps", Code: "OUT_OF_RANGE",
			Message: "max_steps must be between 1 and 8.",
		})
	}
	if cfg.Temperature != nil && (*cfg.Temperature < 0 || *cfg.Temperature > 2) {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/config/temperature", Code: "OUT_OF_RANGE",
			Message: "temperature must be between 0 and 2.",
		})
	}
	return cfg, nil
}

// configured reports whether the core can reach a model. Send uses it to answer
// UNAVAILABLE before a message is stored (design §4). It runs after the global
// provider filled the endpoint (GAP-2), so it only fails when neither the
// session nor a provider names an endpoint.
func (c *nativeConfig) configured() error {
	if c.BaseURL == "" || c.Model == "" {
		return problem.New(problem.Unavailable,
			"The native core is not configured: set config.base_url and config.model on the session, "+
				"or configure a default AI provider.")
	}
	return nil
}

// timeout is the deadline of one model request.
func (c *nativeConfig) timeout() time.Duration {
	if c.TimeoutSeconds > 0 {
		return time.Duration(c.TimeoutSeconds) * time.Second
	}
	return defaultModelTimeout
}

// steps is the tool-calling step limit of the turn.
func (c *nativeConfig) steps(def int) int {
	if c.MaxSteps > 0 {
		return c.MaxSteps
	}
	if def > 0 {
		return def
	}
	return defaultMaxSteps
}

// NativeOptions configure the built-in core.
type NativeOptions struct {
	Secrets *secrets.Store
	Client  *http.Client
	Logger  *slog.Logger
	// Providers resolves the global AI provider of a session (GAP-2). Nil
	// makes every session use the classic session-owned endpoint only.
	Providers ProviderResolver
	MaxSteps  int
	Timeout   time.Duration
	// Gate replaces the built-in permission policy. A nil Gate installs
	// nativeGate for the session's permission mode. The integration supplies a
	// gate when the host can mint an approval (approval_id) before a tool runs;
	// the built-in policy never invents one, because an approval without a host
	// operation id could not be decided by a human (ADR-0010 §4).
	Gate Gate
	// EgressAllowPrefixes and EgressAllowAddrs widen the default outbound policy
	// of the model client. Only the administrator's configuration fills them; a
	// session owner cannot. They are ignored when Client is set.
	EgressAllowPrefixes []netip.Prefix
	EgressAllowAddrs    []netip.AddrPort
}

// NativeCore is the host's built-in OpenAI-compatible core: chat completions
// with function calling, at most eight tool steps per turn (ADR-0010 §5,
// design §4). It is now only an adapter: the OpenAI protocol lives in
// openAIProvider, the host catalog and operation path in nativeTools, and the
// permission policy in nativeGate. The turn itself is RunLoop (loop.go).
type NativeCore struct {
	secrets   *secrets.Store
	client    *http.Client
	log       *slog.Logger
	steps     int
	timeout   time.Duration
	gate      Gate
	providers ProviderResolver
}

// NewNativeCore returns the core.
func NewNativeCore(opts NativeOptions) *NativeCore {
	client := opts.Client
	if client == nil {
		client = newModelClient(egressPolicy(opts.EgressAllowPrefixes, opts.EgressAllowAddrs))
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	timeout := opts.Timeout
	if timeout <= 0 || timeout > maxModelTimeout {
		timeout = defaultModelTimeout
	}
	steps := opts.MaxSteps
	if steps <= 0 || steps > defaultMaxSteps {
		steps = defaultMaxSteps
	}
	return &NativeCore{
		secrets: opts.Secrets, client: client, log: log, steps: steps, timeout: timeout, gate: opts.Gate,
		providers: opts.Providers,
	}
}

// Name implements Core.
func (c *NativeCore) Name() string { return string(CoreNative) }

// systemPrompt is the fixed instruction of the native core. The session's own
// system_prompt is appended; both are host text, never model output.
const systemPrompt = `You are the assistant of a server control panel. You can call the provided tools to
read or change the host; every call is executed by the host under the session's permission mode.
Never claim a change succeeded unless a tool result says so. Prefer read tools first, explain what
you are about to change in one short sentence, and answer in the user's language.`

// systemText is the system message the model sees.
func systemText(cfg *nativeConfig) string {
	if cfg.SystemPrompt == "" {
		return systemPrompt
	}
	return systemPrompt + "\n\n" + cfg.SystemPrompt
}

// Chat protocol types of the OpenAI-compatible endpoint.
type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	Name       string         `json:"name,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chatTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Tools       []chatTool    `json:"tools,omitempty"`
	ToolChoice  string        `json:"tool_choice,omitempty"`
	Temperature *float64      `json:"temperature,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message      chatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
}

// Run implements Core. It assembles the adapters around RunLoop and maps the
// loop outcome to the session contract: a paused loop is ErrWaitingApproval, a
// step limit is the product's UNAVAILABLE message, and every other error is
// returned as is for the service to publish.
func (c *NativeCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	cfg, err := decodeNativeConfig(turn.Config)
	if err != nil {
		return err
	}
	// One endpoint carries one credential (GAP-2, ADR-0017): a session with
	// its own base_url uses its own key and never the provider's; a session
	// without one takes the endpoint and the key from the provider
	// (config.provider_id, or the default provider).
	var apiKey []byte
	if cfg.BaseURL == "" {
		providerKey, err := c.applyProvider(ctx, cfg)
		if err != nil {
			return err
		}
		defer clear(providerKey)
		apiKey = providerKey
	} else {
		apiKey, err = c.apiKey(ctx, turn)
		if err != nil {
			return err
		}
		defer clear(apiKey)
	}
	if err := cfg.configured(); err != nil {
		return err
	}

	names := newToolNames(turn.Tools)
	tools := &nativeTools{names: names, runner: turn.Runner, turn: turn}
	gate := c.gate
	if gate == nil {
		gate = nativeGate{tools: tools, mode: turn.PermissionMode}
	}
	provider := &openAIProvider{core: c, cfg: cfg, apiKey: apiKey}

	messages := make([]ModelMessage, 0, len(turn.Messages)+1)
	messages = append(messages, ModelMessage{Role: LoopRoleSystem, Content: systemText(cfg)})
	messages = append(messages, historyMessages(turn.Messages, names)...)

	_, err = RunLoop(ctx, provider, tools, gate, nativeEmit(emit, names), LoopOptions{
		Messages:   messages,
		MaxSteps:   cfg.steps(c.steps),
		NextCallID: turn.NextCallID,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrLoopApproval):
		return ErrWaitingApproval
	case errors.Is(err, ErrLoopStepLimit):
		return problem.New(problem.Unavailable,
			"The agent did not finish within the tool-call step limit; send another message to continue.")
	default:
		return err
	}
}

// openAIProvider adapts the OpenAI chat-completions protocol to Provider. It
// owns the endpoint, the credential and the request deadline; the loop owns the
// transcript and the step bound.
type openAIProvider struct {
	core   *NativeCore
	cfg    *nativeConfig
	apiKey []byte
}

// Complete implements Provider.
func (p *openAIProvider) Complete(ctx context.Context, req ProviderRequest) (ProviderResponse, error) {
	body := chatRequest{
		Model:       p.cfg.Model,
		Messages:    toChatMessages(req.Messages),
		Tools:       chatToolsFromDefs(req.Tools),
		Temperature: p.cfg.Temperature,
	}
	if len(body.Tools) > 0 {
		body.ToolChoice = "auto"
	}
	msg, err := p.core.complete(ctx, p.cfg, p.apiKey, body)
	if err != nil {
		return ProviderResponse{}, err
	}
	out := ProviderResponse{Content: msg.Content}
	for _, call := range msg.ToolCalls {
		var args json.RawMessage
		if call.Function.Arguments != "" {
			args = json.RawMessage(call.Function.Arguments)
		}
		out.ToolCalls = append(out.ToolCalls, ModelToolCall{
			CallID: call.ID, Name: call.Function.Name, Arguments: args,
		})
	}
	return out, nil
}

// complete performs one chat-completions request.
func (c *NativeCore) complete(ctx context.Context, cfg *nativeConfig, apiKey []byte,
	body chatRequest) (chatMessage, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return chatMessage{}, problem.Wrap(err)
	}
	timeout := cfg.timeout()
	if c.timeout > 0 && c.timeout < timeout {
		timeout = c.timeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.BaseURL+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return chatMessage{}, problem.New(problem.Unavailable, "The native core's base_url cannot be used.")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if len(apiKey) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(apiKey))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		// The error names the endpoint, never the key: the request body and the
		// Authorization header are not part of a transport error.
		if errors.Is(err, errEgressDenied) {
			return chatMessage{}, problem.New(problem.PermissionDenied, "%s", egressDeniedDetail)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return chatMessage{}, problem.New(problem.Timeout, "The model did not answer before its deadline.")
		}
		return chatMessage{}, problem.New(problem.Unavailable, "The model endpoint could not be reached.")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxModelResponse+1))
	if err != nil {
		return chatMessage{}, problem.New(problem.Unavailable, "The model endpoint did not answer.")
	}
	if len(data) > maxModelResponse {
		return chatMessage{}, problem.New(problem.Unavailable, "The model answered more than 1 MiB.")
	}
	if resp.StatusCode != http.StatusOK {
		// The body is untrusted and may echo request headers; it is never
		// forwarded and never logged (it could contain the API key).
		c.log.DebugContext(ctx, "agent session: model request failed", "status", resp.StatusCode)
		return chatMessage{}, modelStatusError(resp.StatusCode)
	}
	var out chatResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return chatMessage{}, problem.New(problem.Unavailable, "The model endpoint returned an invalid response.")
	}
	if len(out.Choices) == 0 {
		return chatMessage{}, problem.New(problem.Unavailable, "The model returned no completion.")
	}
	return out.Choices[0].Message, nil
}

// modelStatusError names the class of a failed answer only: the exact status
// would turn the session into a port and path scanner.
func modelStatusError(status int) error {
	switch {
	case status >= 400 && status < 500:
		return problem.New(problem.Unavailable, "The model endpoint refused the request (4xx).")
	case status >= 500:
		return problem.New(problem.Unavailable, "The model endpoint failed (5xx).")
	default:
		return problem.New(problem.Unavailable, "The model endpoint gave an unexpected answer.")
	}
}

// applyProvider fills the endpoint of a session that carries no base_url from
// a global AI provider (GAP-2, ADR-0017). The provider named by
// config.provider_id wins; without one the default provider applies. A named
// provider that no longer exists is a clear UNAVAILABLE before anything is
// sent; without any provider the caller falls through to the classic "not
// configured" answer. The returned key belongs to the provider and is only
// ever sent to the provider's own base_url.
func (c *NativeCore) applyProvider(ctx context.Context, cfg *nativeConfig) ([]byte, error) {
	if c.providers == nil {
		return nil, nil
	}
	ep, found, err := c.providers.ResolveProvider(ctx, cfg.ProviderID)
	if err != nil {
		return nil, problem.From(err)
	}
	if !found {
		if cfg.ProviderID != "" {
			return nil, problem.New(problem.Unavailable,
				"The AI provider config.provider_id names no longer exists; pick another one or ask an administrator.")
		}
		return nil, nil
	}
	cfg.BaseURL = ep.BaseURL
	if cfg.Model == "" {
		cfg.Model = ep.Model
	}
	return ep.Key, nil
}

// apiKey reveals the session's own API key. Only a secret stored under the
// session's namespace with the API-key purpose opens (secrets.RevealOwned), so
// a planted reference to any other secret fails here, before the model endpoint
// is contacted. The plaintext never leaves this function except as the request
// header, and the caller wipes it.
func (c *NativeCore) apiKey(ctx context.Context, turn Turn) ([]byte, error) {
	if turn.APIKeyRef == "" {
		return nil, nil
	}
	unavailable := problem.New(problem.Unavailable,
		"The session's API key is not available; set it again with PUT /api/v1/agent-sessions/{session_id}/api-key.")
	if c.secrets == nil {
		return nil, unavailable
	}
	key, err := c.secrets.RevealOwned(ctx, turn.APIKeyRef, apiKeyOwner(turn.SessionID), apiKeyPurpose)
	if err != nil {
		return nil, unavailable
	}
	defer key.Clear()
	return key.Bytes(), nil
}

// nativeTools adapts the session's catalog and Runner to ToolRegistry. It is
// the only place where a model tool name becomes a host action id.
type nativeTools struct {
	names  toolNames
	runner Runner
	turn   Turn
}

// Tools implements ToolRegistry.
func (t *nativeTools) Tools() []ToolDef { return t.names.defs() }

// Spec implements ToolRegistry.
func (t *nativeTools) Spec(name string) (ToolDef, bool) {
	spec, ok := t.names.byName[name]
	if !ok {
		return ToolDef{}, false
	}
	return t.names.def(spec), true
}

// Execute implements ToolRegistry. Every call goes to the host Runner, which
// is the operation path; the core never executes anything itself.
func (t *nativeTools) Execute(ctx context.Context, call ModelToolCall) (ToolOutcome, error) {
	spec, ok := t.names.byName[call.Name]
	if !ok {
		return ToolOutcome{
			Status: ToolFailed,
			Error:  problem.New(problem.Unavailable, "The model called an unknown tool."),
		}, nil
	}
	if t.runner == nil {
		return ToolOutcome{
			Status: ToolFailed,
			Error:  problem.New(problem.Unavailable, "The host has no tool runner for this session."),
		}, nil
	}
	res, err := t.runner.RunTool(ctx, ToolCall{
		CallID: call.CallID, SessionID: t.turn.SessionID,
		PermissionMode: t.turn.PermissionMode, Action: spec.Action, Args: call.Arguments,
	})
	if err != nil {
		return ToolOutcome{}, err
	}
	out := ToolOutcome{
		Status: res.Status, Result: res.Result, Error: res.Error,
		OperationID: res.OperationID, ApprovalID: res.ApprovalID,
	}
	if res.Status == ToolAwaitingApproval || res.Approval != nil {
		info := res.Approval
		if info == nil || info.ApprovalID == "" {
			return ToolOutcome{}, problem.New(problem.Internal,
				"The tool runner asked for an approval without an approval id.")
		}
		out.Approval = &ApprovalRequest{
			ApprovalID: info.ApprovalID, OperationID: firstNonEmpty(info.OperationID, res.OperationID),
			Summary: info.Summary, Description: info.Description, Risk: info.Risk,
			Approval: info.Approval, Deadline: info.Deadline,
		}
	}
	return out, nil
}

// nativeGate is the built-in permission policy of the native core. The session
// permission mode is an upper bound that is enforced before the operation layer
// sees the call (ADR-0010 §2.1); approvals themselves stay with operations,
// because an approval needs an operation id a human can decide.
type nativeGate struct {
	tools *nativeTools
	mode  operations.PermissionMode
}

// Check implements Gate.
func (g nativeGate) Check(_ context.Context, _ ToolDef, call ModelToolCall) (GateDecision, error) {
	spec, ok := g.tools.names.byName[call.Name]
	if !ok {
		return GateDecision{Kind: GateDeny, Reason: "The tool is not available in this session."}, nil
	}
	mode := g.mode
	if mode == "" {
		mode = operations.PermissionSafe
	}
	switch mode {
	case operations.PermissionReadOnly:
		if nativeDangerous(spec) {
			return GateDecision{
				Kind:   GateDeny,
				Reason: "The session's permission mode is read_only, so this tool cannot run.",
			}, nil
		}
	case operations.PermissionSafe, operations.PermissionFull, operations.PermissionCustom:
		// The operations layer decides confirm/ai_confirm/destructive for safe
		// and full; full only skips plugin-level approvals (ADR-0010 §2.1).
	default:
		if nativeDangerous(spec) {
			return GateDecision{
				Kind:   GateDeny,
				Reason: "The session's permission mode is unknown, so this tool cannot run.",
			}, nil
		}
	}
	return GateDecision{Kind: GateAllow}, nil
}

// nativeDangerous classifies a host action for the permission gate. It is the
// host-side dangerous list: anything that is not a read tool may change the
// host, and a read tool declared high risk is treated the same way. The list is
// intentionally coarse: the per-action approval decision stays with operations
// (ADR-0010 §2), which sees the plugin's declared approval level and the risk.
func nativeDangerous(spec ToolSpec) bool {
	if spec.Effect != operations.EffectRead {
		return true
	}
	return spec.Risk == operations.RiskHigh
}

// nativeEmit maps loop events to session events. The loop's done and error
// events are not mapped: the service publishes turn.completed and error from
// the value Run returns, so duplicating them here would double the transcript
// and the stream.
func nativeEmit(emit Emit, names toolNames) LoopEmit {
	return func(e LoopEvent) error {
		switch e.Type {
		case LoopEventDelta:
			if e.Delta == "" {
				return nil
			}
			return emit(Event{Type: EventMessageDelta, Delta: e.Delta})
		case LoopEventAssistant:
			out := Event{Type: EventMessageCompleted}
			if len(e.Calls) > 0 {
				calls := make([]MessageToolCall, 0, len(e.Calls))
				for _, call := range e.Calls {
					spec := names.eventSpec(call.Name)
					calls = append(calls, MessageToolCall{
						CallID: call.CallID, Action: spec.Action, Arguments: storableArgs(call.Arguments),
					})
				}
				out.ToolCalls = calls
			}
			return emit(out)
		case LoopEventToolCall:
			if e.Call == nil {
				return nil
			}
			spec := names.eventSpec(e.Call.Name)
			return emit(Event{
				Type: EventToolCall, CallID: e.Call.CallID, Action: spec.Action,
				Args: storableArgs(e.Call.Arguments), Risk: spec.Risk, Approval: spec.Approval,
			})
		case LoopEventToolResult:
			if e.Call == nil || e.Outcome == nil {
				return nil
			}
			spec := names.eventSpec(e.Call.Name)
			status := e.Outcome.Status
			if !status.Valid() {
				status = ToolFailed
			}
			return emit(Event{
				Type: EventToolResult, CallID: e.Call.CallID, Action: spec.Action, Status: string(status),
				Result: e.Outcome.Result, Error: ErrorOf(e.Outcome.Error),
				OperationID: e.Outcome.OperationID, ApprovalID: e.Outcome.ApprovalID,
			})
		case LoopEventApproval:
			if e.Call == nil || e.Approval == nil {
				return nil
			}
			if e.Approval.ApprovalID == "" {
				return problem.New(problem.Internal, "The permission gate asked for an approval without an approval id.")
			}
			spec, _ := names.byName[e.Call.Name]
			return emit(Event{
				Type: EventApprovalRequired, CallID: e.Call.CallID, Action: spec.Action, Args: e.Call.Arguments,
				Risk: e.Approval.Risk, Approval: e.Approval.Approval, ApprovalID: e.Approval.ApprovalID,
				OperationID: e.Approval.OperationID, Summary: e.Approval.Summary,
				Description: e.Approval.Description, Deadline: e.Approval.Deadline,
			})
		default:
			return nil
		}
	}
}

// storableArgs keeps a persisted event valid JSON. The model may answer with
// malformed arguments (the loop reports that as a tool error), but the session
// row and the assistant content_json must stay parsable, so the invalid text is
// replaced by an empty object, exactly like the service does for tool calls,
// and oversized arguments by a summary.
func storableArgs(args json.RawMessage) json.RawMessage {
	if len(args) > MaxToolArgsBytes {
		return truncatedArgs(len(args))
	}
	if len(args) == 0 || !json.Valid(args) {
		return json.RawMessage("{}")
	}
	return args
}

// toolNames maps catalog action ids to the function names the model sees.
type toolNames struct {
	byName map[string]ToolSpec
	ofTool map[string]string
	order  []string
}

// newToolNames builds the name mapping of a turn. Two ids that sanitize to the
// same function name get a stable hash suffix, so the mapping is reproducible
// when a stored transcript is replayed.
func newToolNames(specs []ToolSpec) toolNames {
	names := toolNames{
		byName: make(map[string]ToolSpec, len(specs)),
		ofTool: make(map[string]string, len(specs)),
		order:  make([]string, 0, len(specs)),
	}
	used := make(map[string]bool, len(specs))
	for _, spec := range specs {
		name := uniqueToolName(spec.Action, used)
		names.byName[name] = spec
		names.ofTool[spec.Action] = name
		names.order = append(names.order, name)
	}
	return names
}

// eventSpec 只提供持久化标签；未知名称有界保留，执行权限仍只来自 Spec/gate/runner。
func (n toolNames) eventSpec(name string) ToolSpec {
	if spec, known := n.byName[name]; known {
		return spec
	}
	return ToolSpec{Action: firstNonEmpty(clipText(name, maxLoopToolNameBytes), "unknown")}
}

// name returns the function name of an action within this turn.
func (n toolNames) name(action string) string {
	if name, ok := n.ofTool[action]; ok {
		return name
	}
	return uniqueToolName(action, map[string]bool{})
}

// def builds the loop definition of one tool.
func (n toolNames) def(spec ToolSpec) ToolDef {
	params := spec.Parameters
	if len(params) == 0 || !json.Valid(params) {
		params = json.RawMessage(`{"type":"object","additionalProperties":true}`)
	}
	return ToolDef{
		Name:        n.name(spec.Action),
		Description: toolDescription(spec),
		Parameters:  params,
		Action:      spec.Action,
	}
}

// defs returns the tool definitions in catalog order.
func (n toolNames) defs() []ToolDef {
	out := make([]ToolDef, 0, len(n.order))
	for _, name := range n.order {
		spec, ok := n.byName[name]
		if !ok {
			continue
		}
		out = append(out, n.def(spec))
	}
	return out
}

// openAITools converts the catalog's tool specs to OpenAI function tools and
// returns the name maps used to resolve a call. It is kept for callers and
// tests that need the raw protocol shape; the core uses the loop's ToolDef.
func openAITools(specs []ToolSpec) ([]chatTool, toolNames) {
	names := newToolNames(specs)
	return chatToolsFromDefs(names.defs()), names
}

// chatToolsFromDefs converts loop tool definitions to the OpenAI wire shape.
func chatToolsFromDefs(defs []ToolDef) []chatTool {
	out := make([]chatTool, 0, len(defs))
	for _, def := range defs {
		params := def.Parameters
		if len(params) == 0 || !json.Valid(params) {
			params = json.RawMessage(`{"type":"object","additionalProperties":true}`)
		}
		tool := chatTool{Type: "function"}
		tool.Function.Name = def.Name
		tool.Function.Description = def.Description
		tool.Function.Parameters = params
		out = append(out, tool)
	}
	return out
}

// toolDescription is the one-line description shown to the model.
func toolDescription(spec ToolSpec) string {
	var b strings.Builder
	b.WriteString(spec.Summary)
	if spec.Effect != "" {
		b.WriteString(" (effect=")
		b.WriteString(spec.Effect)
		if spec.Risk != "" {
			b.WriteString(", risk=")
			b.WriteString(spec.Risk)
		}
		if spec.Approval != "" {
			b.WriteString(", approval=")
			b.WriteString(spec.Approval)
		}
		b.WriteString(")")
	}
	return clipText(b.String(), 400)
}

// uniqueToolName maps a catalog action id to a function name OpenAI accepts
// (letters, digits, underscore and dash, at most 64 characters). Two ids that
// sanitize to the same name get a stable hash suffix.
func uniqueToolName(action string, used map[string]bool) string {
	var b strings.Builder
	for i := 0; i < len(action); i++ {
		c := action[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	name := b.String()
	if name == "" {
		name = "tool"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	if !used[name] {
		used[name] = true
		return name
	}
	sum := sha256.Sum256([]byte(action))
	suffix := "_" + hex.EncodeToString(sum[:4])
	if len(name)+len(suffix) > 64 {
		name = name[:64-len(suffix)]
	}
	name += suffix
	used[name] = true
	return name
}

// historyMessages rebuilds the loop transcript from the stored session
// transcript. Sanitization happens in the loop; this function only maps the
// persisted shapes, including the action-to-function-name mapping.
func historyMessages(history []Message, names toolNames) []ModelMessage {
	out := make([]ModelMessage, 0, len(history))
	for _, msg := range history {
		switch msg.Role {
		case RoleUser, RoleSystem:
			if msg.Content != "" {
				out = append(out, ModelMessage{Role: msg.Role, Content: msg.Content})
			}
		case RoleAssistant:
			var ac assistantContent
			if len(msg.ContentJSON) > 0 {
				_ = json.Unmarshal(msg.ContentJSON, &ac)
			}
			m := ModelMessage{Role: RoleAssistant, Content: msg.Content}
			for _, call := range ac.ToolCalls {
				m.ToolCalls = append(m.ToolCalls, ModelToolCall{
					CallID: call.CallID, Name: names.name(call.Action), Arguments: call.Arguments,
				})
			}
			out = append(out, m)
		case RoleTool:
			var tc toolContent
			if len(msg.ContentJSON) > 0 {
				_ = json.Unmarshal(msg.ContentJSON, &tc)
			}
			if tc.CallID == "" {
				continue
			}
			out = append(out, ModelMessage{Role: RoleTool, ToolCallID: tc.CallID, Content: msg.Content})
		}
	}
	return out
}

// buildChatMessages rebuilds the model context from the stored transcript. A
// tool-call step is only included when every call of the step has a tool
// result; otherwise the step (and its orphan tool results) is dropped, so a
// pruned transcript can never produce an invalid request.
func buildChatMessages(history []Message, cfg *nativeConfig, names toolNames) []chatMessage {
	msgs := make([]ModelMessage, 0, len(history)+1)
	msgs = append(msgs, ModelMessage{Role: LoopRoleSystem, Content: systemText(cfg)})
	msgs = append(msgs, historyMessages(history, names)...)
	return toChatMessages(SanitizeHistory(msgs))
}

// toChatMessages converts the loop transcript to the OpenAI wire shape.
func toChatMessages(in []ModelMessage) []chatMessage {
	out := make([]chatMessage, 0, len(in))
	for _, msg := range in {
		wire := chatMessage{Role: msg.Role, Content: msg.Content, ToolCallID: msg.ToolCallID}
		for _, call := range msg.ToolCalls {
			tc := chatToolCall{ID: call.CallID, Type: "function"}
			tc.Function.Name = call.Name
			tc.Function.Arguments = string(call.Arguments)
			wire.ToolCalls = append(wire.ToolCalls, tc)
		}
		out = append(out, wire)
	}
	return out
}

// firstNonEmpty returns the first non-empty argument.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
