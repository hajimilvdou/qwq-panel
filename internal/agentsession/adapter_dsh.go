// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// DSHCore adapts DeepSeek Harness (`deepseek-ai/deepseek-harness`, CLI `dsh`)
// to qwq.
//
// Transports supported:
//  1. Primary: `dsh acp` (Agent Client Protocol JSON-RPC 2.0 over stdio via
//     GenericACPCore), including:
//     - `agent_message_chunk` & `agent_thought_chunk` (streaming + reasoning)
//     - `plan` entries -> `plan.updated` (Task Execution Sheet)
//     - `tool_call` / `tool_call_update` -> unified tool timeline
//     - `session/request_permission` -> host ApprovalRouter (allow_once / reject_once)
//     - `dsh/telemetry` -> DSH-grade Session Stats / Token Cache / Context Breakdown
//     - Direct `@deepseek-ai/dsh-commands` bridge & `@deepseek-ai/dsh-skill` sync
//  2. Fallback: `dsh --profile headless` NDJSON stream.

type DSHConfig struct {
	Binary           string   `json:"-"`                     // host-controlled only; default "dsh"
	Transport        string   `json:"transport,omitempty"`   // acp (default) | headless
	Profile          string   `json:"profile,omitempty"`     // code | standard | headless
	AuthMode         string   `json:"auth_mode,omitempty"`   // oauth | provider | "" (auto)
	ProviderID       string   `json:"provider_id,omitempty"` // optional global AIProvider key bridge
	Model            string   `json:"model,omitempty"`
	ReasoningEffort  string   `json:"reasoning_effort,omitempty"`   // none | low | medium | high | xhigh
	MaxContextTokens int64    `json:"max_context_tokens,omitempty"` // optional context budget override
	WorkDir          string   `json:"-"`                            // host-controlled only; isolated workspace used
	PlanMode         bool     `json:"plan_mode,omitempty"`
	ActiveSkills     []string `json:"active_skills,omitempty"`
}

// DSHOptions configures DSHCore.
type DSHOptions struct {
	Launcher  ProcessLauncher
	Minter    HostApprovalMinter
	Bridge    ApprovalBridge
	Providers ProviderResolver
	Skills    *SkillRegistry
	Auth      *CLIAuthManager
	Binary    string
}

// DSHCore implements Core, CapableCore, PreflightableCore, and CompactableCore.
type DSHCore struct {
	launcher  ProcessLauncher
	minter    HostApprovalMinter
	bridge    ApprovalBridge
	providers ProviderResolver
	skills    *SkillRegistry
	auth      *CLIAuthManager
	bin       string
}

// NewDSHCore constructs the DeepSeek Harness adapter.
func NewDSHCore(opts DSHOptions) *DSHCore {
	launcher := opts.Launcher
	if launcher == nil {
		launcher = OSProcessLauncher{}
	}
	bin := opts.Binary
	if bin == "" {
		bin = "dsh"
	}
	skills := opts.Skills
	if skills == nil {
		skills = NewSkillRegistry()
	}
	return &DSHCore{
		launcher: launcher, minter: opts.Minter, bridge: opts.Bridge,
		providers: opts.Providers, skills: skills, auth: opts.Auth, bin: bin,
	}
}

// Preflight implements PreflightableCore.
func (c *DSHCore) Preflight(_ context.Context, rawConfig json.RawMessage) error {
	if err := refusePlaintextSecrets(rawConfig); err != nil {
		return err
	}
	if _, err := ValidateExternalSessionConfig(rawConfig); err != nil {
		return err
	}
	if _, isReal := c.launcher.(OSProcessLauncher); isReal {
		if ok, reason := probeBinary(c.bin); !ok {
			return problem.New(problem.Unavailable, "DeepSeek Harness (dsh) is not installed on this host (%s).", reason)
		}
	}
	return nil
}

func (c *DSHCore) Name() string { return string(CoreDSH) }

// Descriptor implements CapableCore.
func (c *DSHCore) Descriptor(context.Context) CoreDescriptor {
	ok, reason := probeBinary(c.bin)
	return CoreDescriptor{
		Name:        CoreDSH,
		DisplayName: "DeepSeek Harness (dsh)",
		Protocol:    "dsh-acp-jsonrpc",
		Fallback:    "dsh-headless-jsonl",
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

// MapDSHMode maps qwq PermissionMode + PlanMode onto DSH session mode identifiers.
func MapDSHMode(mode operations.PermissionMode, planMode bool) string {
	if planMode || mode == operations.PermissionReadOnly {
		return "plan"
	}
	if mode == operations.PermissionFull {
		return "workspace_write"
	}
	return "ask"
}

// Run implements Core.
func (c *DSHCore) Run(ctx context.Context, turn Turn, emit Emit) error {
	if err := refusePlaintextSecrets(turn.Config); err != nil {
		return err
	}
	if _, err := ValidateExternalSessionConfig(turn.Config); err != nil {
		return err
	}
	cfg := DSHConfig{Binary: c.bin, Transport: "acp", Profile: "code"}
	if len(turn.Config) > 0 {
		_ = json.Unmarshal(turn.Config, &cfg)
		cfg.Binary = c.bin
		cfg.WorkDir = ""
		if cfg.Transport == "" {
			cfg.Transport = "acp"
		}
	}
	if cfg.Transport == "headless" {
		return c.runHeadless(ctx, cfg, turn, emit)
	}

	acp := NewGenericACPCore(GenericACPOptions{
		CoreName:    CoreDSH,
		DisplayName: "DeepSeek Harness (dsh)",
		Binary:      cfg.Binary,
		Args:        []string{"acp", "--mode", MapDSHMode(turn.PermissionMode, cfg.PlanMode)},
		Launcher:    c.launcher,
		Minter:      c.minter,
		Bridge:      c.bridge,
		Providers:   c.providers,
		Skills:      c.skills,
		Auth:        c.auth,
	})
	return acp.Run(ctx, turn, emit)
}

// Compact implements CompactableCore.
func (c *DSHCore) Compact(ctx context.Context, req CompactRequest) (CompactionResult, error) {
	_, res, err := CompactTranscript(ctx, req.Messages, req.Options, nil)
	return res, err
}

// runHeadless drives `dsh --profile headless` as a non-ACP fallback.
func (c *DSHCore) runHeadless(ctx context.Context, cfg DSHConfig, turn Turn, emit Emit) error {
	if turn.PermissionMode != operations.PermissionReadOnly && !cfg.PlanMode {
		return problem.New(problem.PermissionDenied,
			"非交互式回退传输 (headless) 无法桥接宿主人工审批，仅允许在只读或计划模式下使用。")
	}
	pEnv, ep, found, cleanupEnv, pErr := resolveCLIAuthEnvForSession(ctx, c.providers, c.auth, CoreDSH, cfg.AuthMode, cfg.ProviderID, turn.SessionID)
	if pErr != nil {
		return pErr
	}
	defer cleanupEnv()
	extraEnv := append([]string(nil), pEnv...)
	if found && cfg.Model == "" {
		cfg.Model = ep.Model
	}

	args := []string{"--profile", "headless", "--mode", "plan", "--format", "jsonl"}
	if cfg.Model != "" {
		args = append(args, "--model", cfg.Model)
	}
	args = AppendPosixPromptArg(args, latestUserMessage(turn.Messages))

	proc, err := c.launcher.Start(ctx, cfg.Binary, args, extraEnv, "")
	if err != nil {
		return err
	}
	defer proc.Close(defaultChildGracePeriod)

	sc := bufio.NewScanner(proc.Stdout())
	sc.Buffer(make([]byte, 0, 64<<10), maxCLILine)
	events := 0
	emittedText := false
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if events++; events > maxExternalTurnEvents {
			return problem.New(problem.PluginError, "DSH headless stream exceeded event limit.")
		}
		var ev struct {
			Type      string             `json:"type"`
			Delta     string             `json:"delta"`
			Plan      []PlanItem         `json:"plan"`
			Telemetry *TelemetrySnapshot `json:"telemetry"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		switch strings.ToLower(ev.Type) {
		case "delta", "message.delta":
			if ev.Delta != "" {
				emittedText = true
				if err := emit(Event{Type: EventMessageDelta, SessionID: turn.SessionID, Delta: ev.Delta}); err != nil {
					return err
				}
			}
		case "reasoning", "reasoning.delta":
			_ = emitExtended(emit, EventReasoningDelta, map[string]string{"delta": ev.Delta})
		case "plan", "plan.updated":
			_ = emitExtended(emit, EventPlanUpdated, ev.Plan)
		case "telemetry", "telemetry.updated":
			if ev.Telemetry != nil {
				ev.Telemetry.ComputeDerived()
				_ = emitExtended(emit, EventTelemetryUpdated, *ev.Telemetry)
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
