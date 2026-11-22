// SPDX-License-Identifier: AGPL-3.0-only

// Package catalog is the action catalog behind find_actions and
// describe_action (ADR-0004 D5, D8; ADR-0006 D4). It merges the host actions
// generated from the OpenAPI document (host_gen.go, `go generate`) with the
// operations of installed plugins, and searches them locally: no model is
// called, so a search costs the AI client only the few lines it returns.
package catalog

//go:generate sh -c "cd ../../tools/catalog && GOWORK=off go run . -in ../../api/public/v1/openapi.yaml -out ../../internal/catalog/host_gen.go"

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Source of an action.
type Source string

const (
	Host   Source = "host"
	Plugin Source = "plugin"
)

// Capability is a capability an action may use.
type Capability struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

// Entry is one catalog action. Field names follow the public ActionMeta schema.
type Entry struct {
	ID           string `json:"id"`
	Source       Source `json:"source"`
	Summary      string `json:"summary"` // untrusted for plugin actions
	Effect       string `json:"effect"`
	DeclaredRisk string `json:"declared_risk"`
	// Risk is the effective risk: DeclaredRisk raised to the capability floor.
	Risk       string `json:"risk"`
	Mode       string `json:"mode"`
	Idempotent bool   `json:"idempotent"`
	Plannable  bool   `json:"plannable"`
	Undo       string `json:"undo,omitempty"`
	UIRoute    string `json:"ui_route,omitempty"`
	Permission string `json:"permission"`
	TimeoutMS  int    `json:"timeout_ms"`

	// Plugin actions only.
	PluginID     string       `json:"plugin_id,omitempty"`
	Operation    string       `json:"operation,omitempty"`
	APIVersion   string       `json:"api_version,omitempty"`
	Placement    string       `json:"placement,omitempty"` // node | controller
	Capabilities []Capability `json:"capabilities,omitempty"`
	Docs         string       `json:"docs,omitempty"` // package path of the Markdown docs

	// Approval metadata of a plugin action (ADR-0010), mapped 1:1 onto the
	// ActionMeta schema. Approval is the level that governs the operation: the
	// declared one or the value derived from Effect when the author declared
	// none. The two texts are the confirmation-card title and body written by
	// the plugin author and are untrusted. Host actions carry none of them: the
	// host defines its own approval policy per route.
	Approval            string `json:"approval,omitempty"`
	ApprovalSummary     string `json:"approval_summary,omitempty"`
	ApprovalDescription string `json:"approval_description,omitempty"`

	// Reachability marks an action that can cut the administrator off from the
	// server or the panel (ADR-0016). For plugin actions it is the manifest
	// declaration or the capability-derived forcing; for host actions the
	// x-qwq-reachability extension of the route. Risk and Approval are already
	// clamped to its floor when the entry is built.
	Reachability bool `json:"reachability,omitempty"`

	// Host actions only: the route the action is served at.
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`

	// WidgetRefreshSeconds is the refresh floor of the overview widget bound to
	// this operation, 0 when no widget uses it. The host rate-limits widget reads
	// by it (GAPS gap 7); it is not part of the public ActionMeta.
	WidgetRefreshSeconds int64 `json:"-"`

	ArgsSchema   json.RawMessage `json:"args_schema"`
	ResultSchema json.RawMessage `json:"result_schema,omitempty"`

	index []string // search tokens, built once
}

// Brief is the find_actions entry (ActionSummary).
type Brief struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Effect  string `json:"effect"`
	Risk    string `json:"risk"`
}

// RiskFloor returns the effective risk of an action from its declared risk,
// effect and the capabilities it may use. The operations package owns the
// rule (ADR-0004 D6, ADR-0007 #4); the controller passes it in so the catalog
// shows the same risk the approval policy uses.
type RiskFloor func(declared, effect string, caps []Capability) string

// ReachabilityRule reports whether an operation must be treated as
// reachability-changing because of its effect and the capabilities it may use,
// even when its manifest does not say so (ADR-0016). Like RiskFloor, the
// operations package owns the rule and the controller passes it in.
type ReachabilityRule func(effect string, caps []Capability) bool

// riskHigh is the top risk level, and the floor of a reachability action
// (ADR-0016): raising a risk to "at least high" is setting it to high.
const riskHigh = "high"

// Catalog is safe for concurrent use. Reads take a read lock; installs and
// uninstalls replace one plugin's entries.
type Catalog struct {
	floor   RiskFloor
	forced  ReachabilityRule
	mu      sync.RWMutex
	host    []*Entry
	plugins map[string][]*Entry // plugin ID -> entries
	grants  map[string]pluginGrants
	byID    map[string]*Entry
}

// pluginGrants is what a verified manifest grants the plugin as a whole.
type pluginGrants struct {
	capabilities []Capability
	placement    string
}

// New returns a catalog holding the generated host actions. Both rules are
// required: a catalog without them would show risks and approval levels the
// operation manager does not enforce.
func New(floor RiskFloor, forced ReachabilityRule) (*Catalog, error) {
	if floor == nil {
		return nil, errors.New("catalog: nil risk floor")
	}
	if forced == nil {
		return nil, errors.New("catalog: nil reachability rule")
	}
	var host []*Entry
	if err := json.Unmarshal([]byte(hostActionsJSON), &host); err != nil {
		return nil, fmt.Errorf("catalog: generated host actions: %w", err)
	}
	c := &Catalog{
		floor: floor, forced: forced,
		plugins: map[string][]*Entry{}, grants: map[string]pluginGrants{}, byID: map[string]*Entry{},
	}
	for _, e := range host {
		e.Source = Host
		e.DeclaredRisk = e.Risk
		e.Risk = floor(e.DeclaredRisk, e.Effect, nil)
		if e.Reachability {
			// x-qwq-reachability on the route (ADR-0016). A host action declares
			// no approval level: its high risk asks in every permission mode.
			e.Risk = riskHigh
		}
		e.index = tokensOf(e)
		c.byID[e.ID] = e
	}
	c.host = host
	return c, nil
}

// LoadFile reads a file from a plugin package; SetPlugin uses it for request
// and response schemas.
type LoadFile func(path string) ([]byte, error)

// maxSchema bounds a plugin schema kept in memory and returned to AI clients.
const maxSchema = 64 << 10

// SetPlugin adds or replaces the actions of a verified plugin manifest. A
// failure leaves the previous entries in place.
func (c *Catalog) SetPlugin(m *manifest.Manifest, load LoadFile) error {
	entries := make([]*Entry, 0, len(m.Operations))
	declared := make([]Capability, 0, len(m.Capabilities))
	for _, cp := range m.Capabilities {
		declared = append(declared, Capability{Name: cp.Name, Scope: cp.Scope})
	}
	// The slowest widget bound to an operation sets its refresh floor: two cards
	// reading the same operation must not out-poll the slower one.
	widgetFloor := map[string]int64{}
	if m.UI != nil {
		for _, w := range m.UI.Widgets {
			if w.RefreshSeconds > widgetFloor[w.Operation] {
				widgetFloor[w.Operation] = w.RefreshSeconds
			}
		}
	}
	for _, op := range m.Operations {
		e := &Entry{
			ID: m.ID + "/" + op.Name, Source: Plugin, Summary: cleanText(op.Summary, 120),
			Effect: op.Effect, DeclaredRisk: op.Risk, Mode: op.Mode, Idempotent: op.Idempotent,
			Plannable: op.Plannable != nil && *op.Plannable, UIRoute: op.UIRoute, Permission: op.Permission,
			TimeoutMS: int(op.TimeoutMS), PluginID: m.ID, Operation: op.Name, APIVersion: op.APIVersion,
			Placement: m.Placement, Docs: op.Docs, WidgetRefreshSeconds: widgetFloor[op.Name],
			// The declared level, or the ADR-0010 default derived from the
			// effect, so every plugin action carries an explicit level and the
			// operation manager never has to guess for a signed manifest.
			Approval:            op.EffectiveApproval(),
			ApprovalSummary:     cleanText(op.ApprovalSummary, maxApprovalSummary),
			ApprovalDescription: cleanTextBlock(op.ApprovalDescription, maxApprovalDescription),
		}
		if op.Undo != "" {
			e.Undo = m.ID + "/" + op.Undo
		}
		// Omitted operation capabilities mean every capability of the plugin (ADR-0007 #4).
		if op.Capabilities == nil {
			e.Capabilities = declared
		} else {
			for _, cp := range op.Capabilities {
				e.Capabilities = append(e.Capabilities, Capability{Name: cp.Name, Scope: cp.Scope})
			}
		}
		// ADR-0016: the declared flag, or the forcing that a non-read operation
		// which may use a lockout capability implies. The floor is applied here,
		// at load, so every consumer of the entry (approvals, the DTO, the
		// action catalog) sees the same clamped risk and approval.
		e.Reachability = op.EffectiveReachability() || c.forced(e.Effect, e.Capabilities)
		e.Risk = c.floor(e.DeclaredRisk, e.Effect, e.Capabilities)
		if e.Reachability {
			e.Risk = riskHigh
			if e.Approval == manifest.ApprovalAuto {
				// auto is the only level below ai_confirm; confirm is stricter
				// and stays.
				e.Approval = manifest.ApprovalAIConfirm
			}
		}
		var err error
		if e.ArgsSchema, err = loadSchema(load, op.RequestSchema); err != nil {
			return fmt.Errorf("catalog: %s: %w", e.ID, err)
		}
		if e.ResultSchema, err = loadSchema(load, op.ResponseSchema); err != nil {
			return fmt.Errorf("catalog: %s: %w", e.ID, err)
		}
		e.index = tokensOf(e)
		entries = append(entries, e)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, old := range c.plugins[m.ID] {
		delete(c.byID, old.ID)
	}
	c.plugins[m.ID] = entries
	c.grants[m.ID] = pluginGrants{capabilities: declared, placement: m.Placement}
	for _, e := range entries {
		c.byID[e.ID] = e
	}
	return nil
}

func loadSchema(load LoadFile, path string) (json.RawMessage, error) {
	b, err := load(path)
	if err != nil {
		return nil, err
	}
	if len(b) > maxSchema {
		return nil, fmt.Errorf("schema %s larger than %d bytes", path, maxSchema)
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("schema %s is not JSON", path)
	}
	return json.RawMessage(b), nil
}

// RemovePlugin drops a plugin's actions.
func (c *Catalog) RemovePlugin(pluginID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.plugins[pluginID] {
		delete(c.byID, e.ID)
	}
	delete(c.plugins, pluginID)
	delete(c.grants, pluginID)
}

// PluginGrants returns the plugin-level capabilities and the placement of an
// installed plugin, as its verified manifest declares them. They are the
// security boundary of the plugin's host calls (ADR-0007 #4, ADR-0011 §4);
// nothing a plugin reports at run time can add to them.
func (c *Catalog) PluginGrants(pluginID string) ([]Capability, string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	g, ok := c.grants[pluginID]
	if !ok {
		return nil, "", false
	}
	return append([]Capability(nil), g.capabilities...), g.placement, true
}

// Get returns an action by ID.
func (c *Catalog) Get(id string) (*Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.byID[id]
	return e, ok
}

// Entries returns every action of the catalog: the host actions in their
// generated order, then the plugin actions by plugin ID and action ID. It is the
// enumeration Get and Find cannot express, and what the native agent session
// adapter needs to offer a core its tools (ADR-0010 §5,
// docs/design/agent-sessions.md §11.3). The returned slice is a copy; the
// entries are immutable until the plugin that owns one is replaced.
func (c *Catalog) Entries() []*Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*Entry, 0, len(c.byID))
	out = append(out, c.host...)
	plugins := make([]string, 0, len(c.plugins))
	for id := range c.plugins {
		plugins = append(plugins, id)
	}
	sort.Strings(plugins)
	for _, id := range plugins {
		entries := append([]*Entry(nil), c.plugins[id]...)
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
		out = append(out, entries...)
	}
	return out
}

// Scope filters Find (FindActionsRequest.scope).
type Scope struct {
	PluginID string
	Effect   string
}

// Allow reports whether the caller may use an action; Find skips the others,
// so an AI client is never offered what its delegation cannot do.
type Allow func(*Entry) bool

// Limits of find_actions (FindActionsRequest).
const (
	DefaultLimit = 8
	MaxLimit     = 20
)

// Find returns the best matches for query and whether more matches exist. A
// query without tokens matches nothing: find_actions requires a search term.
func (c *Catalog) Find(query string, scope Scope, limit int, allow Allow) ([]Brief, bool) {
	if len(queryTokens(query)) == 0 {
		return nil, false
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	entries, truncated := c.Search(query, scope, min(limit, MaxLimit), allow)
	out := make([]Brief, len(entries))
	for i, e := range entries {
		out[i] = Brief{ID: e.ID, Summary: e.Summary, Effect: e.Effect, Risk: e.Risk}
	}
	return out, truncated
}

// Search is Find with the full catalog metadata instead of the ActionSummary
// projection, for the human action catalog (GAPS gap 5). The caller owns the
// limit: it is only defaulted here, never capped at the find_actions maximum.
// An empty query enumerates the catalog in Entries order instead of scoring, so
// a browser can page through everything it is allowed to use.
func (c *Catalog) Search(query string, scope Scope, limit int, allow Allow) ([]*Entry, bool) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	q := queryTokens(query)
	var hits []*Entry
	if len(q) == 0 {
		for _, e := range c.Entries() {
			if inScope(e, scope) && (allow == nil || allow(e)) {
				hits = append(hits, e)
			}
		}
	} else {
		type scored struct {
			e     *Entry
			score int
		}
		var matches []scored
		c.mu.RLock()
		for _, e := range c.byID {
			if !inScope(e, scope) || (allow != nil && !allow(e)) {
				continue
			}
			if s := score(e, q, query); s > 0 {
				matches = append(matches, scored{e, s})
			}
		}
		c.mu.RUnlock()
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].score != matches[j].score {
				return matches[i].score > matches[j].score
			}
			if matches[i].e.Source != matches[j].e.Source {
				return matches[i].e.Source == Host
			}
			return matches[i].e.ID < matches[j].e.ID
		})
		for _, m := range matches {
			hits = append(hits, m.e)
		}
	}
	truncated := len(hits) > limit
	if truncated {
		hits = hits[:limit]
	}
	return hits, truncated
}

// inScope reports whether e passes the plugin and effect filters.
func inScope(e *Entry, scope Scope) bool {
	if scope.PluginID != "" && e.PluginID != scope.PluginID {
		return false
	}
	return scope.Effect == "" || e.Effect == scope.Effect
}

// cleanText drops control and bidi-override characters from untrusted text and
// cuts it to max runes; manifests are already validated, this is defense in depth.
func cleanText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
			break
		}
		if unicode.IsControl(r) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == utf8.RuneError {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// cleanTextBlock is cleanText for the multi-line approval description of
// ADR-0010: the line breaks are part of the text, everything else that is a
// control or a bidi override is dropped.
func cleanTextBlock(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
			break
		}
		if r != '\n' && (unicode.IsControl(r) || (r >= 0x202a && r <= 0x202e) ||
			(r >= 0x2066 && r <= 0x2069) || r == utf8.RuneError) {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// Approval card limits of a plugin manifest operation (ADR-0010 §1).
const (
	maxApprovalSummary     = 200
	maxApprovalDescription = 2000
)
