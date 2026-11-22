// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"os/exec"
	"slices"
	"sync"
)

// Additional core identifiers extending CoreName in types.go.
// Merge note: include CoreDSH and CoreACP in CoreName.Valid() inside types.go.
const (
	// CoreDSH is DeepSeek Harness (deepseek-ai/deepseek-harness), driven via
	// ACP JSON-RPC over stdio (`dsh acp`) with headless JSONL fallback.
	CoreDSH CoreName = "dsh"
	// CoreACP is a generic Agent Client Protocol adapter so future open-source
	// or commercial ACP-compliant agents can plug in without modifying host code.
	CoreACP CoreName = "acp"
)

// ExtendedCoreValid reports whether c is any built-in, open-source or ACP core.
func ExtendedCoreValid(c CoreName) bool {
	switch c {
	case CoreNative, CoreClaudeCode, CoreCodex, CoreOpencode, CoreDSH, CoreACP:
		return true
	}
	return false
}

// CoreCapabilities declares the exact feature set a core supports. The Web UI
// reads GET /api/v1/agent-cores and adapts controls cleanly so users never hit
// dead buttons or opaque 503 errors.
type CoreCapabilities struct {
	Streaming             bool `json:"streaming"`
	Reasoning             bool `json:"reasoning"`
	PlanChecklist         bool `json:"plan_checklist"`
	PlanMode              bool `json:"plan_mode"`
	Telemetry             bool `json:"telemetry"`
	Compaction            bool `json:"compaction"`
	SlashCommands         bool `json:"slash_commands"`
	Skills                bool `json:"skills"`
	Fork                  bool `json:"fork"`
	Revert                bool `json:"revert"`
	BidirectionalApproval bool `json:"bidirectional_approval"`
	MCPHostTools          bool `json:"mcp_host_tools"`
	ReasoningEffort       bool `json:"reasoning_effort"`
}

// CoreDescriptor is the public discovery view of one registered core.
type CoreDescriptor struct {
	Name         CoreName         `json:"name"`
	DisplayName  string           `json:"display_name"`
	Protocol     string           `json:"protocol"`
	Fallback     string           `json:"fallback,omitempty"`
	Binary       string           `json:"binary,omitempty"`
	Available    bool             `json:"available"`
	Reason       string           `json:"reason,omitempty"`
	Capabilities CoreCapabilities `json:"capabilities"`
}

// CapableCore is an optional extension of Core for backends that advertise
// structured capabilities and support lifecycle operations beyond Run.
type CapableCore interface {
	Core
	Descriptor(ctx context.Context) CoreDescriptor
}

// PreflightableCore is implemented by cores that verify binary availability or
// provider configuration synchronously during Send before storing a user message.
type PreflightableCore interface {
	Preflight(ctx context.Context, rawConfig json.RawMessage) error
}

// CompactableCore is implemented by cores that support native or remote context
// compaction (`POST /api/v1/agent-sessions/{id}/compact` or `/compact`).
type CompactableCore interface {
	Compact(ctx context.Context, req CompactRequest) (CompactionResult, error)
}

// CommandCapableCore is implemented by cores that support direct runtime slash
// commands (such as DSH `@deepseek-ai/dsh-commands`, Codex `/status`, OpenCode
// custom commands) without injecting the command into model history.
type CommandCapableCore interface {
	Commands(ctx context.Context) []SlashCommandSpec
	ExecCommand(ctx context.Context, req CommandExecRequest) (CommandResult, error)
}

// CoreRegistry holds all registered cores and probes binary availability safely
// without executing untrusted binaries during discovery.
type CoreRegistry struct {
	mu    sync.RWMutex
	cores map[CoreName]Core
	order []CoreName
}

// NewCoreRegistry constructs a registry pre-populated with cores.
func NewCoreRegistry(cores ...Core) *CoreRegistry {
	r := &CoreRegistry{cores: map[CoreName]Core{}}
	for _, c := range cores {
		r.Register(c)
	}
	return r
}

// Register adds or replaces one core implementation.
func (r *CoreRegistry) Register(c Core) {
	if c == nil || c.Name() == "" {
		return
	}
	name := CoreName(c.Name())
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.cores[name]; !exists {
		r.order = append(r.order, name)
	}
	r.cores[name] = c
}

// Lookup returns the registered core for name.
func (r *CoreRegistry) Lookup(name CoreName) (Core, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.cores[name]
	return c, ok
}

// Descriptors returns the discovery descriptors in registration order.
func (r *CoreRegistry) Descriptors(ctx context.Context) []CoreDescriptor {
	r.mu.RLock()
	order := slices.Clone(r.order)
	cores := make([]Core, 0, len(order))
	for _, name := range order {
		cores = append(cores, r.cores[name])
	}
	r.mu.RUnlock()

	out := make([]CoreDescriptor, 0, len(cores))
	for _, c := range cores {
		if cc, ok := c.(CapableCore); ok {
			out = append(out, cc.Descriptor(ctx))
			continue
		}
		out = append(out, CoreDescriptor{
			Name:        CoreName(c.Name()),
			DisplayName: c.Name(),
			Protocol:    "custom",
			Available:   true,
		})
	}
	return out
}

// probeBinary checks whether a CLI executable exists on PATH without launching it.
func probeBinary(bin string) (bool, string) {
	if bin == "" {
		return false, "no executable configured"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return false, "binary '" + bin + "' not found on host PATH"
	}
	return true, ""
}
