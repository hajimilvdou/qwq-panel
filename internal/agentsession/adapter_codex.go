// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// CodexCore adapts OpenAI's open-source Codex CLI (`openai/codex`) to qwq.
//
// Transports supported:
//  1. Primary: `codex app-server` — bidirectional JSON-RPC 2.0 over stdio:
//     - thread/start & thread/resume (persistent multi-turn context)
//     - turn/start & turn/interrupt
//     - item/agentMessage/delta & item/reasoning/delta (streaming)
//     - turn/plan/updated (Task Execution Sheet)
//     - thread/tokenUsage/updated (DSH telemetry parity)
//     - execCommandApproval & applyPatchApproval -> host ApprovalRouter
//     - thread/compact/start (/compact support)
//  2. Fallback: `codex exec --json` — headless JSONL stream for older CLI builds.
//
// Security: qwq's PermissionMode + PlanMode + ApprovalRouter remain authoritative.

type CodexConfig struct {
	Binary           string   `json:"-"`                     // host-controlled only; default "codex"
	Transport        string   `json:"transport,omitempty"`   // app-server (default) | exec-json
	AuthMode         string   `json:"auth_mode,omitempty"`   // oauth | provider | "" (auto)
	ProviderID       string   `json:"provider_id,omitempty"` // optional global AIProvider key bridge
	Model            string   `json:"model,omitempty"`
	ReasoningEffort  string   `json:"reasoning_effort,omitempty"`   // none | low | medium | high | xhigh
	MaxContextTokens int64    `json:"max_context_tokens,omitempty"` // optional context budget override
	WorkDir          string   `json:"-"`                            // host-controlled only; isolated workspace used
	ThreadID         string   `json:"external_thread_id,omitempty"`
	PlanMode         bool     `json:"plan_mode,omitempty"`
	ActiveSkills     []string `json:"active_skills,omitempty"`
}

// CodexOptions configures CodexCore.
type CodexOptions struct {
	Launcher  ProcessLauncher
	Minter    HostApprovalMinter
	Bridge    ApprovalBridge
	Providers ProviderResolver
	Skills    *SkillRegistry
	Auth      *CLIAuthManager
	Workspace *WorkspaceManager
	Binary    string
}

// CodexCore implements Core, CapableCore, PreflightableCore, and CompactableCore.
type CodexCore struct {
	launcher  ProcessLauncher
	minter    HostApprovalMinter
	bridge    ApprovalBridge
	providers ProviderResolver
	skills    *SkillRegistry
	auth      *CLIAuthManager
	workspace *WorkspaceManager
	bin       string
}

// NewCodexCore constructs the Codex adapter.
func NewCodexCore(opts CodexOptions) *CodexCore {
	launcher := opts.Launcher
	if launcher == nil {
		launcher = OSProcessLauncher{}
	}
	bin := opts.Binary
	if bin == "" {
		bin = "codex"
	}
	skills := opts.Skills
	if skills == nil {
		skills = NewSkillRegistry()
	}
	return &CodexCore{
		launcher: opts.Launcher, minter: opts.Minter, bridge: opts.Bridge,
		providers: opts.Providers, skills: skills, auth: opts.Auth, workspace: opts.Workspace, bin: bin,
	}
}

func (c *CodexCore) Name() string { return string(CoreCodex) }

// Descriptor implements CapableCore.
func (c *CodexCore) Descriptor(context.Context) CoreDescriptor {
	ok, reason := probeBinary(c.bin)
	return CoreDescriptor{
		Name:        CoreCodex,
		DisplayName: "OpenAI Codex CLI",
		Protocol:    "codex-app-server-jsonrpc",
		Fallback:    "codex-exec-jsonl",
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

// MapCodexSandboxAndApproval translates qwq's authoritative PermissionMode into
// Codex's sandbox & approval policy hints (host ApprovalRouter still enforces ceiling).
func MapCodexSandboxAndApproval(mode operations.PermissionMode, planMode bool) (sandbox, approvalPolicy string) {
	if planMode || mode == operations.PermissionReadOnly {
		return "read-only", "untrusted"
	}
	switch mode {
	case operations.PermissionFull:
		return "workspace-write", "on-failure"
	default:
		return "workspace-write", "untrusted"
	}
}

// Preflight implements PreflightableCore so missing binaries answer 503 before
// persisting a user turn.
func (c *CodexCore) Preflight(_ context.Context, rawConfig json.RawMessage) error {
	if err := refusePlaintextSecrets(rawConfig); err != nil {
		return err
	}
	if _, err := ValidateExternalSessionConfig(rawConfig); err != nil {
		return err
	}
	if _, isReal := c.effectiveLauncher().(OSProcessLauncher); isReal {
		if ok, reason := probeBinary(c.bin); !ok {
			return problem.New(problem.Unavailable, "Codex CLI is not installed on this host (%s).", reason)
		}
	}
	return nil
}

func (c *CodexCore) effectiveLauncher() ProcessLauncher {
	if c.launcher == nil {
		return OSProcessLauncher{}
	}
	return c.launcher
}

// Run implements Core.
func (c *CodexCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	if err := refusePlaintextSecrets(turn.Config); err != nil {
		return err
	}
	if _, err := ValidateExternalSessionConfig(turn.Config); err != nil {
		return err
	}
	cfg := CodexConfig{Binary: c.bin, Transport: "app-server"}
	if len(turn.Config) > 0 {
		_ = json.Unmarshal(turn.Config, &cfg)
		cfg.Binary = c.bin
		cfg.WorkDir = ""
		if cfg.Transport == "" {
			cfg.Transport = "app-server"
		}
	}
	if cfg.Transport == "exec-json" {
		return c.runExecJSONL(ctx, cfg, turn, emit)
	}
	return c.runAppServer(ctx, cfg, turn, emit)
}

func (c *CodexCore) runAppServer(ctx context.Context, cfg CodexConfig, turn Turn, emit Emit) error {
	router := NewApprovalRouter(turn, cfg.PlanMode, emit, c.minter, c.bridge)
	mcpBridge := NewMCPBridge(turn, cfg.PlanMode, emit, c.bridge)

	args := []string{"app-server"}
	var extraEnv []string
	var cleanupEnv = func() {}
	useProvider := cfg.AuthMode != "oauth" && cfg.ProviderID != ""
	if useProvider {
		pEnv, ep, found, cl, pErr := ResolveProviderForCLI(ctx, c.providers, cfg.ProviderID, CoreCodex)
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
			if cfg.MaxContextTokens == 0 {
				cfg.MaxContextTokens = ep.MaxContextTokens
			}
		}
	} else if c.auth != nil {
		extraEnv = append(extraEnv, c.auth.PersistentEnvFor(CoreCodex)...)
	}
	defer cleanupEnv()

	if len(turn.Tools) > 0 && turn.Runner != nil {
		if mcpSrv, mErr := StartLoopbackMCPServerWithContext(ctx, mcpBridge); mErr == nil {
			defer mcpSrv.Close()
			args = append(args,
				"-c", "mcp_servers.qwq.url="+mcpSrv.URL,
				"-c", "mcp_servers.qwq.bearer_token_env_var=QWQ_MCP_TOKEN",
			)
			extraEnv = append(extraEnv, "QWQ_MCP_TOKEN="+mcpSrv.Token)
		}
	}

	proc, err := c.effectiveLauncher().Start(ctx, cfg.Binary, args, extraEnv, cfg.WorkDir)
	if err != nil {
		return err
	}
	defer proc.Close(defaultChildGracePeriod)

	maxCtx := cfg.MaxContextTokens
	if maxCtx <= 0 {
		maxCtx = 200_000
	}
	var (
		turnDone = make(chan error, 1)
		textBuf  strings.Builder
		startAt  = time.Now()
		firstAt  time.Time
		tele     = TelemetrySnapshot{Turns: 1, Steps: 1, Context: ContextBreakdown{MaxTokens: maxCtx}}
	)

	onNotify := func(_ context.Context, method string, params json.RawMessage) error {
		switch method {
		case "item/agentMessage/delta":
			var p struct {
				Delta string `json:"delta"`
			}
			if json.Unmarshal(params, &p) == nil && p.Delta != "" {
				if firstAt.IsZero() {
					firstAt = time.Now()
					tele.TTFTMS = firstAt.Sub(startAt).Milliseconds()
				}
				textBuf.WriteString(p.Delta)
				return emit(Event{Type: EventMessageDelta, SessionID: turn.SessionID, Delta: p.Delta})
			}

		case "item/reasoning/delta":
			var p struct {
				Delta string `json:"delta"`
			}
			if json.Unmarshal(params, &p) == nil && p.Delta != "" {
				if firstAt.IsZero() {
					firstAt = time.Now()
					tele.TTFTMS = firstAt.Sub(startAt).Milliseconds()
				}
				return emitExtended(emit, EventReasoningDelta, map[string]string{"delta": p.Delta})
			}

		case "turn/plan/updated":
			var p struct {
				Plan []struct {
					Step   string `json:"step"`
					Status string `json:"status"`
				} `json:"plan"`
			}
			if json.Unmarshal(params, &p) == nil {
				items := make([]PlanItem, 0, len(p.Plan))
				for i, st := range p.Plan {
					items = append(items, PlanItem{
						ID:     fmt.Sprintf("step_%d", i+1),
						Title:  st.Step,
						Status: normalizePlanStatus(st.Status),
					})
				}
				return emitExtended(emit, EventPlanUpdated, items)
			}

		case "item/started":
			var p struct {
				Item struct {
					ID      string          `json:"id"`
					Type    string          `json:"type"`
					Command string          `json:"command"`
					Name    string          `json:"name"`
					Args    json.RawMessage `json:"arguments"`
				} `json:"item"`
			}
			if json.Unmarshal(params, &p) == nil && (p.Item.Type == "commandExecution" || p.Item.Type == "mcpToolCall" || p.Item.Type == "fileChange") {
				tele.Steps++
				action := p.Item.Name
				if action == "" {
					action = "codex." + p.Item.Type
				}
				args := p.Item.Args
				if len(args) == 0 && p.Item.Command != "" {
					args, _ = json.Marshal(map[string]string{"command": p.Item.Command})
				}
				return emit(Event{Type: EventToolCall, SessionID: turn.SessionID, CallID: p.Item.ID, Action: action, Args: args})
			}

		case "item/completed":
			var p struct {
				Item struct {
					ID     string `json:"id"`
					Type   string `json:"type"`
					Status string `json:"status"`
					Output string `json:"aggregatedOutput"`
				} `json:"item"`
			}
			if json.Unmarshal(params, &p) == nil && (p.Item.Type == "commandExecution" || p.Item.Type == "mcpToolCall" || p.Item.Type == "fileChange") {
				st := ToolSucceeded
				if strings.EqualFold(p.Item.Status, "failed") {
					st = ToolFailed
				} else if strings.EqualFold(p.Item.Status, "declined") {
					st = ToolRejected
				}
				resJSON, _ := json.Marshal(map[string]string{"output": clipText(p.Item.Output, MaxLoopToolBytes)})
				return emit(Event{Type: EventToolResult, SessionID: turn.SessionID, CallID: p.Item.ID, Status: string(st), Result: resJSON})
			}

		case "thread/tokenUsage/updated":
			var p struct {
				InputTokens     int64 `json:"input_tokens"`
				CachedInput     int64 `json:"cached_input_tokens"`
				OutputTokens    int64 `json:"output_tokens"`
				ReasoningTokens int64 `json:"reasoning_output_tokens"`
			}
			if json.Unmarshal(params, &p) == nil {
				tele.Tokens.Input = p.InputTokens
				tele.Tokens.CachedRead = p.CachedInput
				tele.Tokens.Output = p.OutputTokens
				tele.Tokens.Reasoning = p.ReasoningTokens
				tele.ModelMS = time.Since(startAt).Milliseconds()
				if tele.ModelMS > 0 {
					tele.TPS = float64(tele.Tokens.Output) / (float64(tele.ModelMS) / 1000.0)
				}
				tele.Context.MessageTokens = p.InputTokens + p.OutputTokens
				tele.ComputeDerived()
				return emitExtended(emit, EventTelemetryUpdated, tele)
			}

		case "turn/completed":
			var p struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			}
			_ = json.Unmarshal(params, &p)
			if textBuf.Len() > 0 {
				_ = emit(Event{Type: EventMessageCompleted, SessionID: turn.SessionID})
			}
			if strings.EqualFold(p.Status, "failed") {
				select {
				case turnDone <- problem.New(problem.PluginError, "Codex turn failed: %s", p.Error):
				default:
				}
			} else {
				select {
				case turnDone <- nil:
				default:
				}
			}
		}
		return nil
	}

	onRequest := func(reqCtx context.Context, method string, params json.RawMessage) (any, error) {
		switch method {
		case "execCommandApproval", "item/commandExecution/requestApproval":
			var p struct {
				CallID  string   `json:"callId"`
				Command []string `json:"command"`
				Cwd     string   `json:"cwd"`
				Reason  string   `json:"reason"`
			}
			_ = json.Unmarshal(params, &p)
			cmdStr := strings.Join(p.Command, " ")
			args, _ := json.Marshal(map[string]any{"command": cmdStr, "cwd": p.Cwd})
			out := router.Decide(reqCtx, ExternalApprovalRequest{
				CallID:      p.CallID,
				Kind:        ApprovalKindShell,
				Action:      "codex.exec_command",
				Summary:     "Codex 请求执行命令: " + clipText(cmdStr, 120),
				Description: p.Reason,
				Risk:        "high",
				Args:        args,
			})
			return map[string]any{"decision": string(out.Verdict)}, nil

		case "applyPatchApproval", "item/fileChange/requestApproval":
			var p struct {
				CallID  string `json:"callId"`
				Summary string `json:"summary"`
				Reason  string `json:"reason"`
			}
			_ = json.Unmarshal(params, &p)
			out := router.Decide(reqCtx, ExternalApprovalRequest{
				CallID:      p.CallID,
				Kind:        ApprovalKindPatch,
				Action:      "codex.apply_patch",
				Summary:     "Codex 请求修改文件: " + clipText(p.Summary, 120),
				Description: p.Reason,
				Risk:        "medium",
				Args:        params,
			})
			return map[string]any{"decision": string(out.Verdict)}, nil

		case "tools/list", "tools/call":
			return mcpBridge.HandleRequest(reqCtx, method, params)

		default:
			return nil, problem.New(problem.NotFound, "Unsupported Codex callback %q.", method)
		}
	}

	rpc := NewJSONRPCConn(ctx, proc.Stdout(), proc.Stdin(), onNotify, onRequest)

	// 1. Handshake
	if err := rpc.Call(ctx, "initialize", map[string]any{
		"clientInfo": map[string]any{"name": "qwq-panel", "version": "1.0.0"},
	}, nil); err != nil {
		return err
	}

	// 2. Start or resume thread with host-mapped sandbox & approval policy
	sandbox, approvalPolicy := MapCodexSandboxAndApproval(turn.PermissionMode, cfg.PlanMode)
	threadID := cfg.ThreadID
	if threadID == "" {
		var tResp struct {
			Thread struct {
				ID string `json:"id"`
			} `json:"thread"`
			ThreadID string `json:"threadId"`
		}
		devPrompt := c.skills.BuildSkillPrompt(cfg.ActiveSkills)
		if c.workspace != nil {
			if agentsMD := c.workspace.ReadPromptForCore(CoreCodex); agentsMD != "" {
				devPrompt += "\n\n" + agentsMD
			}
			if customSkills := c.workspace.LoadCustomSkillsPrompt(); customSkills != "" {
				devPrompt += customSkills
			}
		}
		eff, matched, _ := ResolveReasoningEffort(cfg.Model, cfg.ReasoningEffort)
		if (strings.TrimSpace(cfg.ReasoningEffort) == "" && !matched) || IsReasoningEffortDisabled(eff) {
			eff = ""
		}
		startParams := map[string]any{
			"model":           cfg.Model,
			"sandbox":         sandbox,
			"approvalPolicy":  approvalPolicy,
			"cwd":             cfg.WorkDir,
			"developerPrompt": strings.TrimSpace(devPrompt),
		}
		if eff != "" {
			startParams["reasoningEffort"] = eff
		}
		if err := rpc.Call(ctx, "thread/start", startParams, &tResp); err != nil {
			return err
		}
		threadID = tResp.Thread.ID
		if threadID == "" {
			threadID = tResp.ThreadID
		}
	}

	// 3. Kick off turn with newest user prompt
	prompt := latestUserMessage(turn.Messages)
	if err := rpc.Call(ctx, "turn/start", map[string]any{
		"threadId": threadID,
		"input":    []map[string]any{{"type": "text", "text": prompt}},
	}, nil); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		_ = rpc.Notify("turn/interrupt", map[string]any{"threadId": threadID})
		return ctx.Err()
	case err := <-turnDone:
		return err
	case <-rpc.Done():
		if rpc.Err() != nil {
			return rpc.Err()
		}
		return nil
	}
}

// runExecJSONL implements the fallback `codex exec --json` NDJSON parser.
func (c *CodexCore) runExecJSONL(ctx context.Context, cfg CodexConfig, turn Turn, emit Emit) error {
	var extraEnv []string
	var cleanupEnv = func() {}
	useProvider := cfg.AuthMode != "oauth" && cfg.ProviderID != ""
	if useProvider {
		pEnv, ep, found, cl, pErr := ResolveProviderForCLI(ctx, c.providers, cfg.ProviderID, CoreCodex)
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
		extraEnv = append(extraEnv, c.auth.PersistentEnvFor(CoreCodex)...)
	}
	defer cleanupEnv()

	sandbox, _ := MapCodexSandboxAndApproval(turn.PermissionMode, cfg.PlanMode)
	args := []string{"exec", "--json", "--sandbox", sandbox}
	if cfg.Model != "" {
		args = append(args, "--model", cfg.Model)
	}
	if eff, matched, _ := ResolveReasoningEffort(cfg.Model, cfg.ReasoningEffort); (strings.TrimSpace(cfg.ReasoningEffort) != "" || matched) && !IsReasoningEffortDisabled(eff) {
		args = append(args, "-c", FormatCodexEffortConfigOverride(eff))
	}
	args = AppendPosixPromptArg(args, latestUserMessage(turn.Messages))

	proc, err := c.effectiveLauncher().Start(ctx, cfg.Binary, args, extraEnv, "")
	if err != nil {
		return err
	}
	defer proc.Close(defaultChildGracePeriod)

	return ParseCodexExecStream(proc.Stdout(), turn.SessionID, emit)
}

// ParseCodexExecStream translates `codex exec --json` JSONL events into qwq events.
func ParseCodexExecStream(r io.Reader, sessionID string, emit Emit) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxCLILine)
	events := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if events++; events > maxExternalTurnEvents {
			return problem.New(problem.PluginError, "Codex exec exceeded maximum event limit.")
		}
		var ev struct {
			Type string `json:"type"`
			Item struct {
				ID      string `json:"id"`
				Type    string `json:"type"`
				Text    string `json:"text"`
				Command string `json:"command"`
				Output  string `json:"aggregated_output"`
				Status  string `json:"status"`
			} `json:"item"`
			Usage *struct {
				InputTokens       int64 `json:"input_tokens"`
				CachedInputTokens int64 `json:"cached_input_tokens"`
				OutputTokens      int64 `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		switch ev.Type {
		case "item.completed":
			switch ev.Item.Type {
			case "agent_message":
				if ev.Item.Text != "" {
					if err := emit(Event{Type: EventMessageDelta, SessionID: sessionID, MessageID: ev.Item.ID, Delta: ev.Item.Text}); err != nil {
						return err
					}
					if err := emit(Event{Type: EventMessageCompleted, SessionID: sessionID, MessageID: ev.Item.ID, Delta: ev.Item.Text}); err != nil {
						return err
					}
				}
			case "reasoning":
				if ev.Item.Text != "" {
					_ = emitExtended(emit, EventReasoningDelta, map[string]string{"delta": ev.Item.Text})
				}
			case "command_execution":
				args, _ := json.Marshal(map[string]string{"command": ev.Item.Command})
				_ = emit(Event{Type: EventToolCall, SessionID: sessionID, CallID: ev.Item.ID, Action: "codex.command_execution", Args: args})
				res, _ := json.Marshal(map[string]string{"output": clipText(ev.Item.Output, MaxLoopToolBytes)})
				_ = emit(Event{Type: EventToolResult, SessionID: sessionID, CallID: ev.Item.ID, Status: string(ToolSucceeded), Result: res})
			}
		case "turn.completed":
			if ev.Usage != nil {
				t := TelemetrySnapshot{
					Turns: 1,
					Tokens: TokenUsage{
						Input:      ev.Usage.InputTokens,
						CachedRead: ev.Usage.CachedInputTokens,
						Output:     ev.Usage.OutputTokens,
					},
					Context: ContextBreakdown{MaxTokens: 200_000, MessageTokens: ev.Usage.InputTokens + ev.Usage.OutputTokens},
				}
				t.ComputeDerived()
				_ = emitExtended(emit, EventTelemetryUpdated, t)
			}
		}
	}
	return sc.Err()
}

func latestUserMessage(msgs []Message) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == RoleUser && strings.TrimSpace(msgs[i].Content) != "" {
			return msgs[i].Content
		}
	}
	return ""
}

func normalizePlanStatus(raw string) PlanItemStatus {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "completed", "done":
		return PlanCompleted
	case "in_progress", "running", "active":
		return PlanInProgress
	case "skipped", "cancelled":
		return PlanSkipped
	default:
		return PlanPending
	}
}
