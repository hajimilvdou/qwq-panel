// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// GenericACPCore implements the Agent Client Protocol (ACP, JSON-RPC 2.0 over
// stdio). It directly powers:
//   - DeepSeek Harness (`dsh acp`)
//   - OpenCode (`opencode acp`)
//   - Future ACP-compliant agents (Claude Code ACP, Gemini CLI ACP, custom)
//
// Standard ACP flow implemented:
//   1. Client -> Agent: `initialize`
//   2. Client -> Agent: `session/new` (cwd, mcpServers)
//   3. Client -> Agent: `session/prompt` (prompt blocks + active skills)
//   4. Agent -> Client Notifications: `session/update`
//      - `agent_message_chunk`  -> EventMessageDelta
//      - `agent_thought_chunk`  -> EventReasoningDelta
//      - `plan`                 -> EventPlanUpdated
//      - `tool_call`            -> EventToolCall
//      - `tool_call_update`     -> EventToolResult
//      - `telemetry` / `dsh/telemetry` -> EventTelemetryUpdated
//   5. Agent -> Client Bidirectional Requests:
//      - `session/request_permission` -> host ApprovalRouter -> allow_once / reject_once
//      - `tools/list`, `tools/call`   -> host MCPBridge -> Runner -> operations.Run

// GenericACPOptions configures an ACP-backed core.
type GenericACPOptions struct {
	CoreName    CoreName
	DisplayName string
	Binary      string
	Args        []string
	Launcher    ProcessLauncher
	Minter      HostApprovalMinter
	Bridge      ApprovalBridge
	Providers   ProviderResolver
	Skills      *SkillRegistry
}

// GenericACPCore implements Core, CapableCore, and PreflightableCore for any ACP agent.
type GenericACPCore struct {
	name        CoreName
	displayName string
	bin         string
	args        []string
	launcher    ProcessLauncher
	minter      HostApprovalMinter
	bridge      ApprovalBridge
	providers   ProviderResolver
	skills      *SkillRegistry
}

// NewGenericACPCore constructs a reusable ACP adapter.
func NewGenericACPCore(opts GenericACPOptions) *GenericACPCore {
	name := opts.CoreName
	if name == "" {
		name = CoreACP
	}
	disp := opts.DisplayName
	if disp == "" {
		disp = "Generic ACP Agent"
	}
	launcher := opts.Launcher
	if launcher == nil {
		launcher = OSProcessLauncher{}
	}
	skills := opts.Skills
	if skills == nil {
		skills = NewSkillRegistry()
	}
	return &GenericACPCore{
		name:        name,
		displayName: disp,
		bin:         opts.Binary,
		args:        append([]string(nil), opts.Args...),
		launcher:    launcher,
		minter:      opts.Minter,
		bridge:      opts.Bridge,
		providers:   opts.Providers,
		skills:      skills,
	}
}

// Preflight implements PreflightableCore.
func (c *GenericACPCore) Preflight(_ context.Context, rawConfig json.RawMessage) error {
	if err := refusePlaintextSecrets(rawConfig); err != nil {
		return err
	}
	cfg := acpSessionConfig{Binary: c.bin}
	if len(rawConfig) > 0 {
		_ = json.Unmarshal(rawConfig, &cfg)
		if cfg.Binary == "" {
			cfg.Binary = c.bin
		}
	}
	if _, isReal := c.launcher.(OSProcessLauncher); isReal {
		if ok, reason := probeBinary(cfg.Binary); !ok {
			return problem.New(problem.Unavailable, "ACP agent binary is not installed on this host (%s).", reason)
		}
	}
	return nil
}

func (c *GenericACPCore) Name() string { return string(c.name) }

// Descriptor implements CapableCore.
func (c *GenericACPCore) Descriptor(context.Context) CoreDescriptor {
	ok, reason := probeBinary(c.bin)
	return CoreDescriptor{
		Name:        c.name,
		DisplayName: c.displayName,
		Protocol:    "acp-jsonrpc-2.0",
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
		},
	}
}

type acpSessionConfig struct {
	Binary       string   `json:"binary,omitempty"`
	Args         []string `json:"args,omitempty"`
	ProviderID   string   `json:"provider_id,omitempty"`
	WorkDir      string   `json:"work_dir,omitempty"`
	PlanMode     bool     `json:"plan_mode,omitempty"`
	ActiveSkills []string `json:"active_skills,omitempty"`
}

// Run implements Core via bidirectional ACP JSON-RPC 2.0 over stdio.
func (c *GenericACPCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	if err := refusePlaintextSecrets(turn.Config); err != nil {
		return err
	}
	cfg := acpSessionConfig{Binary: c.bin, Args: c.args}
	if len(turn.Config) > 0 {
		_ = json.Unmarshal(turn.Config, &cfg)
		if cfg.Binary == "" {
			cfg.Binary = c.bin
		}
		if len(cfg.Args) == 0 {
			cfg.Args = c.args
		}
	}

	router := NewApprovalRouter(turn, cfg.PlanMode, emit, c.minter, c.bridge)
	mcpBridge := NewMCPBridge(turn, cfg.PlanMode, emit, c.bridge)

	mcpServers := []map[string]any{}
	if len(turn.Tools) > 0 && turn.Runner != nil {
		if mcpSrv, mErr := StartLoopbackMCPServerWithContext(ctx, mcpBridge); mErr == nil {
			defer mcpSrv.Close()
			mcpServers = append(mcpServers, map[string]any{
				"name": "qwq",
				"type": "http",
				"url":  mcpSrv.URL,
				"headers": []map[string]string{
					{"name": "Authorization", "value": "Bearer " + mcpSrv.Token},
				},
			})
		}
	}

	var extraEnv []string
	if pEnv, cleanup, pErr := ResolveProviderEnv(ctx, c.providers, cfg.ProviderID, c.name); pErr == nil {
		defer cleanup()
		extraEnv = append(extraEnv, pEnv...)
	}

	proc, err := c.launcher.Start(ctx, cfg.Binary, cfg.Args, extraEnv, cfg.WorkDir)
	if err != nil {
		return err
	}
	defer proc.Close(defaultChildGracePeriod)

	var (
		textBuf strings.Builder
		msgID   = string(c.name) + "_msg_" + turn.SessionID
		startAt = time.Now()
		firstAt time.Time
		tele    = TelemetrySnapshot{Turns: 1, Steps: 1, Context: ContextBreakdown{MaxTokens: 200_000}}
	)

	onNotify := func(_ context.Context, method string, params json.RawMessage) error {
		switch method {
		case "session/update":
			var p struct {
				Update struct {
					SessionUpdate string `json:"sessionUpdate"`
					Content       struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"content"`
					Entries []struct {
						ID      string `json:"id"`
						Content string `json:"content"`
						Status  string `json:"status"`
					} `json:"entries"`
					ToolCallID string          `json:"toolCallId"`
					Title      string          `json:"title"`
					Status     string          `json:"status"`
					RawInput   json.RawMessage `json:"rawInput"`
					RawOutput  json.RawMessage `json:"rawOutput"`
				} `json:"update"`
			}
			if json.Unmarshal(params, &p) != nil {
				return nil
			}
			u := p.Update
			switch u.SessionUpdate {
			case "agent_message_chunk":
				if u.Content.Text != "" {
					if firstAt.IsZero() {
						firstAt = time.Now()
						tele.TTFTMS = firstAt.Sub(startAt).Milliseconds()
					}
					textBuf.WriteString(u.Content.Text)
					return emit(Event{Type: EventMessageDelta, SessionID: turn.SessionID, MessageID: msgID, Delta: u.Content.Text})
				}
			case "agent_thought_chunk":
				if u.Content.Text != "" {
					return emitExtended(emit, EventReasoningDelta, map[string]string{"message_id": msgID, "delta": u.Content.Text})
				}
			case "plan":
				items := make([]PlanItem, 0, len(u.Entries))
				for i, e := range u.Entries {
					id := e.ID
					if id == "" {
						id = fmt.Sprintf("plan_%d", i+1)
					}
					items = append(items, PlanItem{ID: id, Title: e.Content, Status: normalizePlanStatus(e.Status)})
				}
				return emitExtended(emit, EventPlanUpdated, items)
			case "tool_call":
				tele.Steps++
				return emit(Event{
					Type:      EventToolCall,
					SessionID: turn.SessionID,
					CallID:    u.ToolCallID,
					Action:    u.Title,
					Args:      u.RawInput,
				})
			case "tool_call_update":
				if u.Status == "completed" || u.Status == "failed" {
					st := ToolSucceeded
					if u.Status == "failed" {
						st = ToolFailed
					}
					return emit(Event{
						Type:      EventToolResult,
						SessionID: turn.SessionID,
						CallID:    u.ToolCallID,
						Status:    string(st),
						Result:    u.RawOutput,
					})
				}
			}

		case "dsh/telemetry", "session/telemetry":
			var snap TelemetrySnapshot
			if json.Unmarshal(params, &snap) == nil {
				snap.ComputeDerived()
				tele = snap
				return emitExtended(emit, EventTelemetryUpdated, snap)
			}
		}
		return nil
	}

	onRequest := func(reqCtx context.Context, method string, params json.RawMessage) (any, error) {
		switch method {
		case "session/request_permission":
			var p struct {
				ToolCall struct {
					ToolCallID string          `json:"toolCallId"`
					Title      string          `json:"title"`
					Kind       string          `json:"kind"`
					RawInput   json.RawMessage `json:"rawInput"`
				} `json:"toolCall"`
				Options []struct {
					OptionID string `json:"optionId"`
					Kind     string `json:"kind"`
				} `json:"options"`
			}
			_ = json.Unmarshal(params, &p)
			out := router.Decide(reqCtx, ExternalApprovalRequest{
				CallID:  p.ToolCall.ToolCallID,
				Kind:    ApprovalKindPermission,
				Action:  string(c.name) + "." + p.ToolCall.Kind,
				Summary: p.ToolCall.Title,
				Risk:    "high",
				Args:    p.ToolCall.RawInput,
			})
			allowID, rejectID := "allow_once", "reject_once"
			for _, opt := range p.Options {
				if strings.HasPrefix(opt.Kind, "allow") && allowID == "allow_once" {
					allowID = opt.OptionID
				}
				if strings.HasPrefix(opt.Kind, "reject") && rejectID == "reject_once" {
					rejectID = opt.OptionID
				}
			}
			if out.Verdict == VerdictAccept {
				return map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": allowID}}, nil
			}
			if out.Verdict == VerdictCancel {
				return map[string]any{"outcome": map[string]any{"outcome": "cancelled"}}, nil
			}
			return map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": rejectID}}, nil

		case "tools/list", "tools/call":
			return mcpBridge.HandleRequest(reqCtx, method, params)

		default:
			return nil, problem.New(problem.NotFound, "Unsupported ACP callback %q.", method)
		}
	}

	rpc := NewJSONRPCConn(ctx, proc.Stdout(), proc.Stdin(), onNotify, onRequest)

	// 1. ACP initialize
	if err := rpc.Call(ctx, "initialize", map[string]any{
		"protocolVersion": 1,
		"clientInfo":      map[string]any{"name": "qwq-panel", "version": "1.0.0"},
		"clientCapabilities": map[string]any{
			"fs":       map[string]any{"readTextFile": false, "writeTextFile": false},
			"terminal": false,
		},
	}, nil); err != nil {
		return err
	}

	// 2. ACP session/new (attaching ephemeral loopback qwq MCP server when tools exist)
	var newSess struct {
		SessionID string `json:"sessionId"`
	}
	if err := rpc.Call(ctx, "session/new", map[string]any{
		"cwd":        cfg.WorkDir,
		"mcpServers": mcpServers,
	}, &newSess); err != nil {
		return err
	}

	// 3. ACP session/prompt (blocks until agent finishes prompt turn)
	promptText := latestUserMessage(turn.Messages)
	if skillPrompt := c.skills.BuildSkillPrompt(cfg.ActiveSkills); skillPrompt != "" {
		promptText = skillPrompt + "\n\n" + promptText
	}
	var promptRes struct {
		StopReason string `json:"stopReason"`
	}
	err = rpc.Call(ctx, "session/prompt", map[string]any{
		"sessionId": newSess.SessionID,
		"prompt":    []map[string]any{{"type": "text", "text": promptText}},
	}, &promptRes)
	if err != nil {
		if ctx.Err() != nil {
			_ = rpc.Notify("session/cancel", map[string]any{"sessionId": newSess.SessionID})
		}
		return err
	}

	if textBuf.Len() > 0 {
		_ = emit(Event{Type: EventMessageCompleted, SessionID: turn.SessionID, MessageID: msgID, Delta: textBuf.String()})
	}
	tele.ModelMS = time.Since(startAt).Milliseconds()
	tele.ComputeDerived()
	_ = emitExtended(emit, EventTelemetryUpdated, tele)
	return nil
}
