// SPDX-License-Identifier: Apache-2.0

package manifest

// Manifest is a parsed, schema-valid manifest.json (schema
// urn:qwq:plugin-manifest:v1). JSON tags match the schema exactly.
//
// Encoding conventions, chosen so that decode → encode keeps the meaning:
//   - Optional booleans are pointers, because absent and false differ when
//     the schema default is true (lifecycle.overlap_safe) and to keep the
//     author's explicit false. Use the Effective* helpers for the value.
//   - Optional integers use omitzero: 0 is below every schema minimum, so
//     zero always means absent.
//   - Optional arrays and objects use omitzero: nil means absent, an empty
//     non-nil slice is encoded as [].
//   - Optional strings use omitempty: the schema gives every optional string
//     a minimum length or pattern that excludes "", so "" always means absent.
//
// All integers are int64; Parse guarantees |n| <= MaxSafeInteger.
type Manifest struct {
	SchemaVersion    string            `json:"schema_version"`
	ID               string            `json:"id"`
	Version          string            `json:"version"`
	Name             string            `json:"name"`
	Summary          string            `json:"summary"`
	Description      string            `json:"description,omitempty"`
	License          string            `json:"license,omitempty"`
	Homepage         string            `json:"homepage,omitempty"`
	Icon             string            `json:"icon,omitempty"`
	Publisher        Publisher         `json:"publisher"`
	ABI              ABI               `json:"abi"`
	EngineConstraint string            `json:"engine_constraint"`
	Target           string            `json:"target"`
	Entrypoint       string            `json:"entrypoint"`
	Files            map[string]string `json:"files"` // relpath -> "sha256:<hex>"
	Provenance       Provenance        `json:"provenance"`
	Placement        string            `json:"placement"`
	Lifecycle        Lifecycle         `json:"lifecycle"`
	NodeRequirements *NodeRequirements `json:"node_requirements,omitzero"`
	Operations       []Operation       `json:"operations"`
	Capabilities     []Capability      `json:"capabilities"`
	Dependencies     []Dependency      `json:"dependencies"`
	Conflicts        []Conflict        `json:"conflicts,omitzero"`
	Replaces         []string          `json:"replaces,omitzero"`
	State            State             `json:"state"`
	Config           Config            `json:"config"`
	Resources        Resources         `json:"resources"`
	UI               *UI               `json:"ui,omitzero"`
}

// Publisher identifies the signer. KeyID is the KeyID of the signing key.
type Publisher struct {
	ID    string `json:"id"`
	KeyID string `json:"key_id"`
}

// ABI is the Platform ABI requirement (ARCH §5.2).
type ABI struct {
	Major        int64 `json:"major"`
	MinimumMinor int64 `json:"minimum_minor"`
}

// CompatibleWith reports whether a host speaking hostMajor.hostMinor can load
// the plugin. It compares in int64, so no value is truncated.
func (a ABI) CompatibleWith(hostMajor, hostMinor uint32) bool {
	return a.Major == int64(hostMajor) && a.MinimumMinor <= int64(hostMinor)
}

// Provenance points at attestations inside the package.
type Provenance struct {
	SBOM  string `json:"sbom"`
	Build string `json:"build,omitempty"`
}

// Lifecycle controls startup and update behaviour (ARCH §5.3, §6.3).
type Lifecycle struct {
	Startup        string `json:"startup"` // eager | on_demand
	Background     bool   `json:"background"`
	UpdateStrategy string `json:"update_strategy"` // auto | blue_green | restart
	OverlapSafe    *bool  `json:"overlap_safe,omitempty"`
}

// EffectiveOverlapSafe applies the schema default (true).
func (l Lifecycle) EffectiveOverlapSafe() bool { return l.OverlapSafe == nil || *l.OverlapSafe }

// NodeRequirements are checked against the node before staging.
type NodeRequirements struct {
	CgroupV2     *bool    `json:"cgroup_v2,omitempty"`
	SystemdMin   int64    `json:"systemd_min,omitzero"`
	KernelMin    string   `json:"kernel_min,omitempty"`
	HostFeatures []string `json:"host_features,omitzero"`
}

// Approval levels of an operation (ADR-0010 §1, §2).
const (
	// ApprovalAuto asks for nothing beyond the host's own hard rules.
	ApprovalAuto = "auto"
	// ApprovalConfirm asks for a human decision on every call.
	ApprovalConfirm = "confirm"
	// ApprovalAIConfirm asks for a human decision only when an AI agent or a
	// delegation calls the operation.
	ApprovalAIConfirm = "ai_confirm"
)

// Operation is one entry of the plugin's operation surface (ADR-0004 D5).
type Operation struct {
	Name       string `json:"name"`
	APIVersion string `json:"api_version"`
	Permission string `json:"permission"`
	// Capabilities this operation may use, each one also declared in
	// Manifest.Capabilities. nil = omitted = all of the plugin's capabilities
	// (ADR-0007); a non-nil empty slice was written as [].
	Capabilities []CapabilityRef `json:"capabilities,omitzero"`
	Mode         string          `json:"mode"`   // invoke | job
	Effect       string          `json:"effect"` // read | write | destructive
	Risk         string          `json:"risk"`   // low | medium | high
	Idempotent   bool            `json:"idempotent"`
	Plannable    *bool           `json:"plannable,omitempty"`
	TimeoutMS    int64           `json:"timeout_ms"`
	Summary      string          `json:"summary"`
	Docs         string          `json:"docs,omitempty"`
	Undo         string          `json:"undo,omitempty"`
	UIRoute      string          `json:"ui_route,omitempty"`
	// Approval is the declared level; "" means the author declared none and
	// the host derives it from Effect (see EffectiveApproval).
	Approval string `json:"approval,omitempty"`
	// ApprovalSummary is the confirmation-card title (single line, untrusted).
	ApprovalSummary string `json:"approval_summary,omitempty"`
	// ApprovalDescription is the expandable confirmation text (multi-line
	// Markdown, untrusted).
	ApprovalDescription string `json:"approval_description,omitempty"`
	// Reachability marks an operation that can cut the administrator off from
	// the server or the panel (schema 1.3, ADR-0018). nil means the author did
	// not declare it; use EffectiveReachability for the value.
	Reachability   *bool  `json:"reachability,omitempty"`
	RequestSchema  string `json:"request_schema"`
	ResponseSchema string `json:"response_schema"`
}

// EffectivePlannable applies the schema default (false).
func (o Operation) EffectivePlannable() bool { return o.Plannable != nil && *o.Plannable }

// EffectiveReachability applies the schema default (false). It is only what the
// author declared: the host may also set the flag from the capabilities the
// operation uses, and that decision is not visible here.
func (o Operation) EffectiveReachability() bool { return o.Reachability != nil && *o.Reachability }

// EffectiveApproval returns the approval level that governs the operation: the
// declared one, or the ADR-0010 §2 default derived from the effect when the
// author declared none (read -> auto, write -> confirm, destructive -> confirm).
// The host's hard rules (destructive, high effective risk) are applied on top
// and can never be relaxed by the declaration.
func (o Operation) EffectiveApproval() string {
	switch o.Approval {
	case ApprovalAuto, ApprovalConfirm, ApprovalAIConfirm:
		return o.Approval
	}
	if o.Effect == "read" {
		return ApprovalAuto
	}
	return ApprovalConfirm
}

// Capability is a requested capability (ARCH §10.3).
type Capability struct {
	Name   string `json:"name"`
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
}

// CapabilityRef names a declared capability (Operation.Capabilities).
type CapabilityRef struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

// Dependency on another plugin or a host service.
type Dependency struct {
	Kind       string `json:"kind"` // plugin | service
	ID         string `json:"id"`
	Constraint string `json:"constraint"`
	Required   bool   `json:"required"`
}

// Conflict names plugin versions that cannot be installed alongside.
type Conflict struct {
	ID         string `json:"id"`
	Constraint string `json:"constraint"`
}

// State describes the plugin's private persistent state.
type State struct {
	SchemaVersion          string   `json:"schema_version"`
	MinimumRollbackVersion string   `json:"minimum_rollback_version"`
	BackupPaths            []string `json:"backup_paths"`
}

// Config points at the configuration schema.
type Config struct {
	Schema   string `json:"schema"`
	HotApply bool   `json:"hot_apply"`
}

// Resources is the plugin's resource budget.
type Resources struct {
	MemoryMaxMB     int64 `json:"memory_max_mb"`
	CPUQuotaPercent int64 `json:"cpu_quota_percent"`
	PIDsMax         int64 `json:"pids_max"`
	FDsMax          int64 `json:"fds_max"`
	DiskMaxMB       int64 `json:"disk_max_mb"`
	KVMaxKB         int64 `json:"kv_max_kb,omitzero"`
}

// DefaultKVMaxKB is the schema default of resources.kv_max_kb.
const DefaultKVMaxKB = 4096

// EffectiveKVMaxKB applies the schema default.
func (r Resources) EffectiveKVMaxKB() int64 {
	if r.KVMaxKB == 0 {
		return DefaultKVMaxKB
	}
	return r.KVMaxKB
}

// UI is the optional sandboxed front end (ARCH §5.5).
type UI struct {
	Entry          string    `json:"entry"`
	Sandbox        bool      `json:"sandbox"`
	KitMajor       int64     `json:"kit_major,omitzero"`
	ConnectSources []string  `json:"connect_sources"`
	Routes         []UIRoute `json:"routes"`
	// Widgets are the overview cards the Web Shell draws itself (schema 1.3,
	// ADR-0018). nil means the member is absent.
	Widgets []UIWidget `json:"widgets,omitzero"`
}

// UIRoute is one route contributed to the Web Shell.
type UIRoute struct {
	Path       string `json:"path"`
	Title      string `json:"title"`
	Nav        *bool  `json:"nav,omitempty"`
	Permission string `json:"permission"`
}

// EffectiveNav applies the schema default (false).
func (r UIRoute) EffectiveNav() bool { return r.Nav != nil && *r.Nav }

// Widget kinds: each one fixes the result shape the Web Shell expects from the
// widget's operation.
const (
	WidgetStat   = "stat"
	WidgetSeries = "series"
	WidgetChecks = "checks"
	WidgetList   = "list"
)

// UIWidget is one declarative overview card. The Web Shell polls Operation (a
// read, mode=invoke operation of the same plugin) with an empty payload every
// RefreshSeconds and renders the result natively; the plugin's own UI code is
// not involved.
type UIWidget struct {
	ID             string `json:"id"`
	Title          string `json:"title"` // untrusted, single line
	Kind           string `json:"kind"`  // stat | series | checks | list
	Operation      string `json:"operation"`
	RefreshSeconds int64  `json:"refresh_seconds"`
	Size           string `json:"size"` // s | m | l
	Icon           string `json:"icon,omitempty"`
	Color          string `json:"color,omitempty"`
}
