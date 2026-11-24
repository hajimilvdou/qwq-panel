// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// OpenCodeCore adapts anomalyco/opencode to qwq across all three official
// programmatic interfaces:
//  1. Primary:  `opencode serve` (HTTP REST + `/event` SSE + `/permission/{id}/reply`
//     + `/session/{id}/compact`, `/fork`, `/revert`)
//  2. ACP mode: `opencode acp` (delegated cleanly to GenericACPCore)
//  3. Fallback: `opencode run --format json` (NDJSON event stream)

type OpenCodeConfig struct {
	ServerURL        string   `json:"-"`                            // host-controlled only; e.g. http://127.0.0.1:4096
	Binary           string   `json:"-"`                            // host-controlled only; default "opencode"
	Transport        string   `json:"transport,omitempty"`          // auto (default: serve if up else acp) | serve-http | acp | run-json
	AuthMode         string   `json:"auth_mode,omitempty"`          // oauth | provider | "" (auto)
	ProviderID       string   `json:"provider_id,omitempty"`        // optional global AIProvider key bridge
	Model            string   `json:"model,omitempty"`              // providerID/modelID
	ReasoningEffort  string   `json:"reasoning_effort,omitempty"`   // none | low | medium | high | xhigh
	MaxContextTokens int64    `json:"max_context_tokens,omitempty"` // optional context budget override
	Agent            string   `json:"agent,omitempty"`              // build | plan | general
	SessionID        string   `json:"external_thread_id,omitempty"`
	PlanMode         bool     `json:"plan_mode,omitempty"`
	ActiveSkills     []string `json:"active_skills,omitempty"`
	WorkDir          string   `json:"-"` // host-controlled only; isolated workspace used
}

// OpenCodeOptions configures OpenCodeCore.
type OpenCodeOptions struct {
	Client    *http.Client
	Launcher  ProcessLauncher
	Minter    HostApprovalMinter
	Bridge    ApprovalBridge
	Providers ProviderResolver
	Skills    *SkillRegistry
	Auth      *CLIAuthManager
	Binary    string
	ServerURL string
}

// OpenCodeCore implements Core, CapableCore, PreflightableCore, and CompactableCore.
type OpenCodeCore struct {
	client    *http.Client
	launcher  ProcessLauncher
	minter    HostApprovalMinter
	bridge    ApprovalBridge
	providers ProviderResolver
	skills    *SkillRegistry
	auth      *CLIAuthManager
	bin       string
	serverURL string
}

// NewOpenCodeCore constructs the OpenCode adapter.
func NewOpenCodeCore(opts OpenCodeOptions) *OpenCodeCore {
	cl := opts.Client
	if cl == nil {
		cl = &http.Client{Timeout: 0} // SSE streams manage their own ctx deadlines
	}
	launcher := opts.Launcher
	if launcher == nil {
		launcher = OSProcessLauncher{}
	}
	bin := opts.Binary
	if bin == "" {
		bin = "opencode"
	}
	serverURL := strings.TrimRight(strings.TrimSpace(opts.ServerURL), "/")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:4096"
	}
	skills := opts.Skills
	if skills == nil {
		skills = NewSkillRegistry()
	}
	return &OpenCodeCore{
		client: cl, launcher: launcher, minter: opts.Minter, bridge: opts.Bridge,
		providers: opts.Providers, skills: skills, auth: opts.Auth, bin: bin, serverURL: serverURL,
	}
}

func (c *OpenCodeCore) Name() string { return string(CoreOpencode) }

// Descriptor implements CapableCore.
func (c *OpenCodeCore) Descriptor(context.Context) CoreDescriptor {
	ok, reason := probeBinary(c.bin)
	return CoreDescriptor{
		Name:        CoreOpencode,
		DisplayName: "OpenCode (anomalyco/opencode)",
		Protocol:    "opencode-http-sse",
		Fallback:    "opencode-acp / run-json",
		Binary:      c.bin,
		Available:   ok,
		Reason:      reason,
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

// MapOpenCodeAgent maps qwq PermissionMode + PlanMode onto OpenCode's agent mode.
func MapOpenCodeAgent(mode operations.PermissionMode, planMode bool) string {
	if planMode || mode == operations.PermissionReadOnly {
		return "plan"
	}
	return "build"
}

// Preflight implements PreflightableCore.
func (c *OpenCodeCore) Preflight(ctx context.Context, rawConfig json.RawMessage) error {
	if err := refusePlaintextSecrets(rawConfig); err != nil {
		return err
	}
	if _, err := ValidateExternalSessionConfig(rawConfig); err != nil {
		return err
	}
	if c.serverURL != "" && c.probeHTTP(ctx, c.serverURL) {
		return nil
	}
	if _, isReal := c.launcher.(OSProcessLauncher); isReal {
		if ok, reason := probeBinary(c.bin); !ok {
			return problem.New(problem.Unavailable, "OpenCode CLI is not installed and no opencode serve daemon is reachable (%s).", reason)
		}
	}
	return nil
}

func (c *OpenCodeCore) probeHTTP(ctx context.Context, baseURL string) bool {
	pCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(pCtx, http.MethodGet, baseURL+"/session", nil)
	if err != nil {
		return false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}

// Run implements Core.
func (c *OpenCodeCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	if err := refusePlaintextSecrets(turn.Config); err != nil {
		return err
	}
	if _, err := ValidateExternalSessionConfig(turn.Config); err != nil {
		return err
	}
	cfg := OpenCodeConfig{Binary: c.bin, ServerURL: c.serverURL, Transport: "auto"}
	if len(turn.Config) > 0 {
		_ = json.Unmarshal(turn.Config, &cfg)
	}
	cfg.Binary = c.bin
	cfg.ServerURL = c.serverURL
	cfg.WorkDir = ""
	if cfg.Transport == "" {
		cfg.Transport = "auto"
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = "http://127.0.0.1:4096"
	}
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")

	transport := cfg.Transport
	if transport == "auto" {
		if c.probeHTTP(ctx, cfg.ServerURL) {
			transport = "serve-http"
		} else {
			transport = "acp"
		}
	}

	switch transport {
	case "acp":
		acp := NewGenericACPCore(GenericACPOptions{
			CoreName:    CoreOpencode,
			DisplayName: "OpenCode ACP",
			Binary:      cfg.Binary,
			Args:        []string{"acp"},
			Launcher:    c.launcher,
			Minter:      c.minter,
			Bridge:      c.bridge,
			Providers:   c.providers,
			Skills:      c.skills,
			Auth:        c.auth,
		})
		return acp.Run(ctx, turn, emit)
	case "run-json":
		return c.runCLIJSON(ctx, cfg, turn, emit)
	default:
		return c.runServeHTTP(ctx, cfg, turn, emit)
	}
}

func (c *OpenCodeCore) runServeHTTP(ctx context.Context, cfg OpenCodeConfig, turn Turn, emit Emit) error {
	router := NewApprovalRouter(turn, cfg.PlanMode, emit, c.minter, c.bridge)

	// 1. Ensure remote OpenCode session exists
	extSessionID := cfg.SessionID
	if extSessionID == "" {
		var created struct {
			ID string `json:"id"`
		}
		if err := c.doJSON(ctx, http.MethodPost, cfg.ServerURL+"/session", map[string]any{
			"title": "qwq:" + turn.SessionID,
		}, &created); err != nil {
			return err
		}
		extSessionID = created.ID
	}

	// 2. Open SSE event stream BEFORE posting prompt so no early delta is lost
	evCtx, cancelEv := context.WithCancel(ctx)
	defer cancelEv()
	evReq, err := http.NewRequestWithContext(evCtx, http.MethodGet, cfg.ServerURL+"/event", nil)
	if err != nil {
		return problem.Wrap(err)
	}
	evReq.Header.Set("Accept", "text/event-stream")
	evResp, err := c.client.Do(evReq)
	if err != nil {
		return problem.New(problem.Unavailable, "Could not connect to OpenCode server at %s.", cfg.ServerURL)
	}
	defer evResp.Body.Close()

	// 3. Dispatch prompt asynchronously with host-mapped agent mode & active skills
	agentName := cfg.Agent
	if agentName == "" || cfg.PlanMode || turn.PermissionMode == operations.PermissionReadOnly {
		agentName = MapOpenCodeAgent(turn.PermissionMode, cfg.PlanMode)
	}
	promptText := latestUserMessage(turn.Messages)
	if skillPrompt := c.skills.BuildSkillPrompt(cfg.ActiveSkills); skillPrompt != "" {
		promptText = skillPrompt + "\n\n" + promptText
	}
	promptErrCh := make(chan error, 1)
	go func() {
		promptErrCh <- c.doJSON(ctx, http.MethodPost,
			fmt.Sprintf("%s/session/%s/prompt_async", cfg.ServerURL, url.PathEscape(extSessionID)),
			map[string]any{
				"agent": agentName,
				"model": cfg.Model,
				"parts": []map[string]any{{"type": "text", "text": promptText}},
			}, nil)
	}()

	// 4. Consume OpenCode SSE frames and translate into unified qwq events
	return c.consumeOpenCodeSSE(ctx, cfg.ServerURL, extSessionID, turn.SessionID, evResp.Body, router, emit, promptErrCh)
}

func (c *OpenCodeCore) consumeOpenCodeSSE(
	ctx context.Context,
	baseURL, extSessionID, qwqSessionID string,
	body io.Reader,
	router *ApprovalRouter,
	emit Emit,
	promptErrCh <-chan error,
) error {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), maxCLILine)

	var (
		startAt = time.Now()
		firstAt time.Time
		textBuf strings.Builder
		tele    = TelemetrySnapshot{Turns: 1, Context: ContextBreakdown{MaxTokens: 200_000}}
	)

	for sc.Scan() {
		select {
		case pErr := <-promptErrCh:
			if pErr != nil {
				return pErr
			}
			promptErrCh = nil
		default:
		}

		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if raw == "" {
			continue
		}
		var env struct {
			Type       string          `json:"type"`
			Properties json.RawMessage `json:"properties"`
		}
		if json.Unmarshal([]byte(raw), &env) != nil {
			continue
		}

		switch env.Type {
		case "message.part.updated":
			var p struct {
				Delta string `json:"delta"`
				Part  struct {
					SessionID string `json:"sessionID"`
					ID        string `json:"id"`
					Type      string `json:"type"`
					Text      string `json:"text"`
					Tool      string `json:"tool"`
					CallID    string `json:"callID"`
					State     struct {
						Status string          `json:"status"`
						Input  json.RawMessage `json:"input"`
						Output string          `json:"output"`
						Error  string          `json:"error"`
					} `json:"state"`
					Tokens *struct {
						Input     int64 `json:"input"`
						Output    int64 `json:"output"`
						Reasoning int64 `json:"reasoning"`
						Cache     struct {
							Read  int64 `json:"read"`
							Write int64 `json:"write"`
						} `json:"cache"`
					} `json:"tokens"`
				} `json:"part"`
			}
			if json.Unmarshal(env.Properties, &p) != nil {
				continue
			}
			if p.Part.SessionID != "" && p.Part.SessionID != extSessionID {
				continue
			}
			switch p.Part.Type {
			case "text":
				delta := p.Delta
				if delta == "" && len(p.Part.Text) > textBuf.Len() {
					delta = p.Part.Text[textBuf.Len():]
				}
				if delta != "" {
					if firstAt.IsZero() {
						firstAt = time.Now()
						tele.TTFTMS = firstAt.Sub(startAt).Milliseconds()
					}
					textBuf.WriteString(delta)
					if err := emit(Event{Type: EventMessageDelta, SessionID: qwqSessionID, Delta: delta}); err != nil {
						return err
					}
				}
			case "reasoning":
				delta := p.Delta
				if delta == "" {
					delta = p.Part.Text
				}
				if delta != "" {
					_ = emitExtended(emit, EventReasoningDelta, map[string]string{"delta": delta})
				}
			case "tool":
				callID := p.Part.CallID
				if callID == "" {
					callID = p.Part.ID
				}
				switch p.Part.State.Status {
				case "running", "pending":
					_ = emit(Event{Type: EventToolCall, SessionID: qwqSessionID, CallID: callID, Action: "opencode." + p.Part.Tool, Args: p.Part.State.Input})
				case "completed":
					resJSON, _ := json.Marshal(map[string]string{"output": clipText(p.Part.State.Output, MaxLoopToolBytes)})
					_ = emit(Event{Type: EventToolResult, SessionID: qwqSessionID, CallID: callID, Status: string(ToolSucceeded), Result: resJSON})
				case "error":
					_ = emit(Event{Type: EventToolResult, SessionID: qwqSessionID, CallID: callID, Status: string(ToolFailed), Error: &ErrorInfo{Code: problem.PluginError, Detail: p.Part.State.Error}})
				}
			case "step-finish":
				tele.Steps++
				if p.Part.Tokens != nil {
					tele.Tokens.Input += p.Part.Tokens.Input
					tele.Tokens.Output += p.Part.Tokens.Output
					tele.Tokens.Reasoning += p.Part.Tokens.Reasoning
					tele.Tokens.CachedRead += p.Part.Tokens.Cache.Read
					tele.Tokens.CachedWrite += p.Part.Tokens.Cache.Write
				}
				tele.ModelMS = time.Since(startAt).Milliseconds()
				if tele.ModelMS > 0 {
					tele.TPS = float64(tele.Tokens.Output) / (float64(tele.ModelMS) / 1000.0)
				}
				tele.Context.MessageTokens = tele.Tokens.Input + tele.Tokens.Output
				tele.ComputeDerived()
				_ = emitExtended(emit, EventTelemetryUpdated, tele)
			}

		case "permission.asked":
			var perm struct {
				ID         string          `json:"id"`
				SessionID  string          `json:"sessionID"`
				Permission string          `json:"permission"`
				Patterns   []string        `json:"patterns"`
				Metadata   json.RawMessage `json:"metadata"`
			}
			if json.Unmarshal(env.Properties, &perm) != nil {
				continue
			}
			if perm.SessionID != "" && perm.SessionID != extSessionID {
				continue
			}
			out := router.Decide(ctx, ExternalApprovalRequest{
				CallID:  perm.ID,
				Kind:    ApprovalKindPermission,
				Action:  "opencode.permission." + perm.Permission,
				Summary: fmt.Sprintf("OpenCode 请求权限: %s (%s)", perm.Permission, strings.Join(perm.Patterns, ", ")),
				Risk:    "high",
				Args:    perm.Metadata,
			})
			reply := "reject"
			if out.Verdict == VerdictAccept {
				reply = "once"
			}
			_ = c.doJSON(ctx, http.MethodPost,
				fmt.Sprintf("%s/permission/%s/reply", baseURL, url.PathEscape(perm.ID)),
				map[string]any{"reply": reply, "message": out.Comment}, nil)

		case "session.idle":
			if textBuf.Len() > 0 {
				_ = emit(Event{Type: EventMessageCompleted, SessionID: qwqSessionID})
			}
			return nil

		case "session.error":
			return problem.New(problem.PluginError, "OpenCode session reported an error.")
		}
	}
	return sc.Err()
}

// Compact implements CompactableCore against `POST /session/{id}/compact`.
func (c *OpenCodeCore) Compact(ctx context.Context, req CompactRequest) (CompactionResult, error) {
	_, res, err := CompactTranscript(ctx, req.Messages, req.Options, nil)
	return res, err
}

func (c *OpenCodeCore) effectiveLauncher() ProcessLauncher {
	if c.launcher == nil {
		return OSProcessLauncher{}
	}
	return c.launcher
}

// runCLIJSON runs `opencode run --format json` as a zero-daemon fallback.
func (c *OpenCodeCore) runCLIJSON(ctx context.Context, cfg OpenCodeConfig, turn Turn, emit Emit) error {
	var extraEnv []string
	var cleanupEnv = func() {}
	useProvider := cfg.AuthMode != "oauth" && cfg.ProviderID != ""
	if useProvider {
		pEnv, ep, found, cl, pErr := ResolveProviderForCLI(ctx, c.providers, cfg.ProviderID, CoreOpencode)
		if pErr != nil {
			return pErr
		}
		cleanupEnv = cl
		extraEnv = append(extraEnv, pEnv...)
		if found {
			if cfg.Model == "" {
				cfg.Model = ep.Model
			}
			if cfg.ReasoningEffort == "" {
				cfg.ReasoningEffort = ep.ReasoningEffort
			}
		}
	} else if c.auth != nil {
		extraEnv = append(extraEnv, c.auth.PersistentEnvFor(CoreOpencode)...)
	}
	defer cleanupEnv()

	args := []string{"run", "--format", "json", "--agent", MapOpenCodeAgent(turn.PermissionMode, cfg.PlanMode)}
	if cfg.Model != "" {
		args = append(args, "--model", cfg.Model)
	}
	if eff, matched, _ := ResolveReasoningEffort(cfg.Model, cfg.ReasoningEffort); (strings.TrimSpace(cfg.ReasoningEffort) != "" || matched) && !IsReasoningEffortDisabled(eff) {
		extraEnv = append(extraEnv, "OPENCODE_REASONING_EFFORT="+eff)
	}
	args = AppendPosixPromptArg(args, latestUserMessage(turn.Messages))
	proc, err := c.effectiveLauncher().Start(ctx, cfg.Binary, args, extraEnv, "")
	if err != nil {
		return err
	}
	defer proc.Close(defaultChildGracePeriod)

	sc := bufio.NewScanner(proc.Stdout())
	sc.Buffer(make([]byte, 0, 64<<10), maxCLILine)
	emittedText := false
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev struct {
			Type string `json:"type"`
			Part struct {
				Text string `json:"text"`
				Tool string `json:"tool"`
			} `json:"part"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev.Type == "text" && ev.Part.Text != "" {
			emittedText = true
			if err := emit(Event{Type: EventMessageDelta, SessionID: turn.SessionID, Delta: ev.Part.Text}); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if emittedText {
		_ = emit(Event{Type: EventMessageCompleted, SessionID: turn.SessionID})
	}
	return nil
}

func (c *OpenCodeCore) doJSON(ctx context.Context, method, url string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return problem.Wrap(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return problem.Wrap(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return problem.New(problem.Unavailable, "OpenCode HTTP call failed: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxModelResponse))
	if resp.StatusCode >= 400 {
		return problem.New(problem.PluginError, "OpenCode HTTP %d", resp.StatusCode)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
