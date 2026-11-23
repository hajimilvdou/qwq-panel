// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ClaudeCodeCore integrates Anthropic's `claude` CLI (`claude-code`) into qwq's
// AgentSession runtime (Track 06 / ADR-0028):
//   - Headless NDJSON streaming (`claude -p <prompt> --output-format stream-json --verbose`);
//   - Ephemeral authenticated loopback MCP server (`127.0.0.1:0` + 256-bit Bearer token)
//     passed via mode-0600 `--mcp-config <file>` so every host/plugin action flows
//     strictly through `Runner.RunTool -> operations.Run` under the session actor;
//   - Host PermissionMode mapped to `--permission-mode` (plan / default / acceptEdits)
//     while the host MCP bridge and ApprovalRouter remain the authoritative ceiling;
//   - Preserves host OAuth/XDG Claude credentials via EnvGuard allowlist, with
//     optional `provider_id` key bridge (`ANTHROPIC_API_KEY` / `ANTHROPIC_BASE_URL`).

type ClaudeCodeConfig struct {
	Binary           string   `json:"-"`                            // host-controlled only; never deserialized from session JSON
	AuthMode         string   `json:"auth_mode,omitempty"`          // oauth | provider | "" (auto)
	ProviderID       string   `json:"provider_id,omitempty"`        // optional global AIProvider key bridge
	Model            string   `json:"model,omitempty"`              // optional --model override
	ReasoningEffort  string   `json:"reasoning_effort,omitempty"`   // none | low | medium | high | xhigh
	MaxContextTokens int64    `json:"max_context_tokens,omitempty"` // optional context budget override
	ResumeSessionID  string   `json:"resume_session_id,omitempty"`  // optional --resume <id>
	WorkDir          string   `json:"-"`                            // host-controlled only; isolated temp workspace used
	PlanMode         bool     `json:"plan_mode,omitempty"`
	ActiveSkills     []string `json:"active_skills,omitempty"`
	MaxTurns         int      `json:"max_turns,omitempty"`
}

func decodeClaudeCodeConfig(raw json.RawMessage) (ClaudeCodeConfig, error) {
	cfg := ClaudeCodeConfig{Binary: "claude"}
	if len(raw) == 0 {
		return cfg, nil
	}
	if _, err := ValidateExternalSessionConfig(raw); err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, problem.Validation(problem.Violation{
			Pointer: "/config", Code: "INVALID", Message: "config is not valid claude-code configuration.",
		})
	}
	cfg.Binary = "claude"
	cfg.WorkDir = ""
	return cfg, nil
}

// ClaudeCodeOptions configure ClaudeCodeCore.
type ClaudeCodeOptions struct {
	Binary    string
	Launcher  ProcessLauncher
	Bridge    ApprovalBridge
	Providers ProviderResolver
	Skills    *SkillRegistry
	Auth      *CLIAuthManager
	Workspace *WorkspaceManager
}

// ClaudeCodeCore implements Core, CapableCore, and PreflightableCore.
type ClaudeCodeCore struct {
	binary    string
	launcher  ProcessLauncher
	bridge    ApprovalBridge
	providers ProviderResolver
	skills    *SkillRegistry
	auth      *CLIAuthManager
	workspace *WorkspaceManager
}

// NewClaudeCodeCore constructs a Claude Code CLI adapter.
func NewClaudeCodeCore(opts ClaudeCodeOptions) *ClaudeCodeCore {
	bin := opts.Binary
	if bin == "" {
		bin = "claude"
	}
	launcher := opts.Launcher
	if launcher == nil {
		launcher = OSProcessLauncher{}
	}
	skills := opts.Skills
	if skills == nil {
		skills = NewSkillRegistry()
	}
	return &ClaudeCodeCore{
		binary:    bin,
		launcher:  launcher,
		bridge:    opts.Bridge,
		providers: opts.Providers,
		skills:    skills,
		auth:      opts.Auth,
		workspace: opts.Workspace,
	}
}

func (c *ClaudeCodeCore) Name() string { return string(CoreClaudeCode) }

// Preflight verifies the `claude` CLI binary is installed before creating a turn.
func (c *ClaudeCodeCore) Preflight(ctx context.Context, raw json.RawMessage) error {
	if _, err := decodeClaudeCodeConfig(raw); err != nil {
		return err
	}
	bin := c.binary
	if _, err := exec.LookPath(bin); err != nil {
		return problem.New(problem.Unavailable,
			"Claude Code CLI (%s) is not installed on this host. Install via `npm i -g @anthropic-ai/claude-code` or switch to the native core.",
			bin)
	}
	return nil
}

// Descriptor implements CapableCore with live binary probing.
func (c *ClaudeCodeCore) Descriptor(context.Context) CoreDescriptor {
	avail, reason := probeBinary(c.binary)
	return CoreDescriptor{
		Name:        CoreClaudeCode,
		DisplayName: "Claude Code (Anthropic)",
		Protocol:    "claude-stream-json",
		Available:   avail,
		Reason:      reason,
		Capabilities: CoreCapabilities{
			Streaming:             true,
			Reasoning:             true,
			PlanChecklist:         true,
			PlanMode:              true,
			Telemetry:             true,
			Skills:                true,
			BidirectionalApproval: true,
			MCPHostTools:          true,
			ReasoningEffort:       true,
		},
	}
}

func claudePermissionFlag(mode operations.PermissionMode, planMode bool) string {
	if planMode || mode == operations.PermissionReadOnly {
		return "plan"
	}
	if mode == operations.PermissionFull {
		return "acceptEdits"
	}
	return "default"
}

// Run executes one turn against `claude -p --output-format stream-json --verbose`.
func (c *ClaudeCodeCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	cfg, err := decodeClaudeCodeConfig(turn.Config)
	if err != nil {
		return err
	}
	bin := c.binary
	prompt := latestUserMessage(turn.Messages)
	if prompt == "" {
		return problem.New(problem.ValidationFailed, "No user prompt found in turn.")
	}

	var extraEnv []string
	var cleanupEnv = func() {}
	useProvider := cfg.AuthMode != "oauth" && cfg.ProviderID != ""
	if useProvider {
		pEnv, ep, found, cl, pErr := ResolveProviderForCLI(ctx, c.providers, cfg.ProviderID, CoreClaudeCode)
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
		extraEnv = append(extraEnv, c.auth.PersistentEnvFor(CoreClaudeCode)...)
	}
	defer cleanupEnv()

	effectiveMode := turn.PermissionMode
	if cfg.PlanMode {
		effectiveMode = operations.PermissionReadOnly
	}

	args := []string{
		"-p",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-mode", claudePermissionFlag(turn.PermissionMode, cfg.PlanMode),
		"--disallowedTools", "Bash,Write,Edit,MultiEdit,NotebookEdit",
	}
	if cfg.Model != "" {
		args = append(args, "--model", cfg.Model)
	}
	if eff, _, _ := ResolveReasoningEffort(cfg.Model, cfg.ReasoningEffort); !IsReasoningEffortDisabled(eff) && !strings.EqualFold(eff, "none") {
		extraEnv = append(extraEnv, "CLAUDE_CODE_EFFORT_LEVEL="+eff)
	}
	if cfg.ResumeSessionID != "" {
		args = append(args, "--resume", cfg.ResumeSessionID)
	}
	if cfg.MaxTurns > 0 {
		args = append(args, "--max-turns", fmt.Sprintf("%d", cfg.MaxTurns))
	}
	sysPrompt := c.skills.BuildSkillPrompt(cfg.ActiveSkills)
	if c.workspace != nil {
		if claudeMD := c.workspace.ReadPromptForCore(CoreClaudeCode); claudeMD != "" {
			sysPrompt += "\n\n" + claudeMD
		}
		if customSkills := c.workspace.LoadCustomSkillsPrompt(); customSkills != "" {
			sysPrompt += customSkills
		}
	}
	if strings.TrimSpace(sysPrompt) != "" {
		args = append(args, "--append-system-prompt", strings.TrimSpace(sysPrompt))
	}

	// Start an ephemeral authenticated loopback MCP bridge so Claude Code invokes
	// qwq panel tools solely through Runner.RunTool -> operations.Run, plus any
	// enabled user-installed MCP servers from agent-workspace/mcp/servers.json.
	mcpServers := map[string]any{}
	if turn.Runner != nil && len(turn.Tools) > 0 {
		mcpTurn := turn
		mcpTurn.PermissionMode = effectiveMode
		srv, err := StartLoopbackMCPServerWithContext(ctx, NewMCPBridge(mcpTurn, cfg.PlanMode, emit, c.bridge))
		if err != nil {
			return problem.New(problem.Internal, "Failed to start loopback MCP bridge: %v", err)
		}
		defer srv.Close()
		mcpServers["qwq"] = map[string]any{
			"type": "http",
			"url":  srv.URL,
			"headers": map[string]string{
				"Authorization": "Bearer " + srv.Token,
			},
		}
	}
	if c.workspace != nil {
		if userMCPs, merr := c.workspace.ListMCPServers(); merr == nil {
			for _, u := range userMCPs {
				if !u.Enabled || u.ID == "" || u.ID == "qwq" {
					continue
				}
				if u.Transport == "http" && u.URL != "" {
					mcpServers[u.ID] = map[string]any{"type": "http", "url": u.URL}
				} else if u.Command != "" {
					entry := map[string]any{"command": u.Command, "args": u.Args}
					if len(u.Env) > 0 {
						entry["env"] = u.Env
					}
					mcpServers[u.ID] = entry
				}
			}
		}
	}
	if len(mcpServers) > 0 {
		tmpDir, err := os.MkdirTemp("", "qwq-claude-mcp-*")
		if err != nil {
			return problem.New(problem.Internal, "Failed to create temporary MCP config dir.")
		}
		defer os.RemoveAll(tmpDir)

		mcpCfgPath := filepath.Join(tmpDir, "mcp.json")
		mcpPayload, err := json.Marshal(map[string]any{"mcpServers": mcpServers})
		if err != nil {
			return problem.Wrap(err)
		}
		if err := os.WriteFile(mcpCfgPath, mcpPayload, 0o600); err != nil {
			return problem.New(problem.Internal, "Failed to write temporary MCP config.")
		}
		args = append(args, "--mcp-config", mcpCfgPath, "--strict-mcp-config")
	}

	args = AppendPosixPromptArg(args, prompt)

	proc, err := c.launcher.Start(ctx, bin, args, extraEnv, "")
	if err != nil {
		return err
	}
	if proc.Stdin() != nil {
		_ = proc.Stdin().Close()
	}

	parseErr := ParseClaudeStreamJSON(ctx, proc.Stdout(), emit)
	closeErr := proc.Close(defaultChildGracePeriod)
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return problem.New(problem.Unavailable, "Claude Code CLI exited with error: %s", strings.TrimSpace(proc.StderrText()))
	}
	return nil
}

// ParseClaudeStreamJSON decodes Claude Code's `--output-format stream-json` NDJSON
// stream into qwq session events. Exported for deterministic protocol testing.
func ParseClaudeStreamJSON(ctx context.Context, r io.Reader, emit Emit) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	start := time.Now()
	var (
		firstTokenAt time.Time
		msgID        = "claude_msg_1"
		emittedText  bool
		telemetry    = TelemetrySnapshot{Turns: 1}
	)

	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev struct {
			Type    string `json:"type"`
			Subtype string `json:"subtype"`
			Message struct {
				ID      string `json:"id"`
				Content []struct {
					Type     string          `json:"type"`
					Text     string          `json:"text"`
					Thinking string          `json:"thinking"`
					ID       string          `json:"id"`
					Name     string          `json:"name"`
					Input    json.RawMessage `json:"input"`
				} `json:"content"`
			} `json:"message"`
			Result     string `json:"result"`
			IsError    bool   `json:"is_error"`
			DurationMS int64  `json:"duration_ms"`
			NumTurns   int    `json:"num_turns"`
			Usage      *struct {
				InputTokens              int64 `json:"input_tokens"`
				OutputTokens             int64 `json:"output_tokens"`
				CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return problem.New(problem.PluginError, "Claude Code wrote malformed JSON output.")
		}

		switch ev.Type {
		case "assistant":
			telemetry.Steps++
			if ev.Message.ID != "" {
				msgID = ev.Message.ID
			}
			for _, block := range ev.Message.Content {
				switch block.Type {
				case "thinking":
					if block.Thinking != "" {
						if firstTokenAt.IsZero() {
							firstTokenAt = time.Now()
						}
						_ = emitExtended(emit, EventReasoningDelta, map[string]string{"delta": block.Thinking})
					}
				case "text":
					if block.Text != "" {
						if firstTokenAt.IsZero() {
							firstTokenAt = time.Now()
						}
						emittedText = true
						_ = emit(Event{Type: EventMessageDelta, MessageID: msgID, Delta: block.Text})
					}
				case "tool_use":
					if strings.EqualFold(block.Name, "TodoWrite") {
						var todo struct {
							Todos []struct {
								ID      string `json:"id"`
								Content string `json:"content"`
								Status  string `json:"status"`
							} `json:"todos"`
						}
						if json.Unmarshal(block.Input, &todo) == nil && len(todo.Todos) > 0 {
							items := make([]PlanItem, 0, len(todo.Todos))
							for i, td := range todo.Todos {
								id := td.ID
								if id == "" {
									id = fmt.Sprintf("step_%d", i+1)
								}
								st := PlanPending
								switch strings.ToLower(td.Status) {
								case "completed", "done":
									st = PlanCompleted
								case "in_progress", "running":
									st = PlanInProgress
								}
								items = append(items, PlanItem{ID: id, Title: td.Content, Status: st})
							}
							_ = emitExtended(emit, EventPlanUpdated, items)
						}
						continue
					}
					callID := block.ID
					if callID == "" {
						callID = fmt.Sprintf("claude_call_%d", telemetry.Steps)
					}
					_ = emit(Event{
						Type:   EventToolCall,
						CallID: callID,
						Action: block.Name,
						Args:   block.Input,
						Status: string(ToolRunning),
					})
				}
			}

		case "user":
			// Tool results echoed back in verbose stream-json.
			for _, block := range ev.Message.Content {
				if block.Type == "tool_result" {
					_ = emit(Event{
						Type:   EventToolResult,
						CallID: block.ID,
						Status: string(ToolSucceeded),
					})
				}
			}

		case "result":
			if ev.IsError {
				msg := ev.Result
				if msg == "" {
					msg = "Claude Code reported an error result."
				}
				return problem.New(problem.Unavailable, "%s", msg)
			}
			if !emittedText && ev.Result != "" {
				emittedText = true
				_ = emit(Event{Type: EventMessageDelta, MessageID: msgID, Delta: ev.Result})
			}
			if emittedText {
				_ = emit(Event{Type: EventMessageCompleted, MessageID: msgID})
			}
			if ev.NumTurns > 0 {
				telemetry.Turns = ev.NumTurns
			}
			if ev.DurationMS > 0 {
				telemetry.ModelMS = ev.DurationMS
			} else {
				telemetry.ModelMS = time.Since(start).Milliseconds()
			}
			if !firstTokenAt.IsZero() {
				telemetry.TTFTMS = firstTokenAt.Sub(start).Milliseconds()
			}
			if ev.Usage != nil {
				telemetry.Tokens.Input = ev.Usage.InputTokens + ev.Usage.CacheReadInputTokens + ev.Usage.CacheCreationInputTokens
				telemetry.Tokens.CachedRead = ev.Usage.CacheReadInputTokens
				telemetry.Tokens.CachedWrite = ev.Usage.CacheCreationInputTokens
				telemetry.Tokens.Output = ev.Usage.OutputTokens
				if telemetry.ModelMS > 0 && telemetry.Tokens.Output > 0 {
					telemetry.TPS = float64(telemetry.Tokens.Output) / (float64(telemetry.ModelMS) / 1000.0)
				}
			}
			telemetry.Context.MaxTokens = 200000
			telemetry.Context.MessageTokens = telemetry.Tokens.Input + telemetry.Tokens.Output
			telemetry.ComputeDerived()
			telemetry.UpdatedAt = time.Now().UTC()
			_ = emitExtended(emit, EventTelemetryUpdated, telemetry)
		}
	}

	if err := sc.Err(); err != nil {
		return problem.New(problem.Unavailable, "Claude Code stream read error: %v", err)
	}
	return nil
}

// Compile-time assertions.
var (
	_ Core              = (*ClaudeCodeCore)(nil)
	_ CapableCore       = (*ClaudeCodeCore)(nil)
	_ PreflightableCore = (*ClaudeCodeCore)(nil)
)
