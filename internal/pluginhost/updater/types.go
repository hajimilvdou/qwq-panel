// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// VersionStatus is the lifecycle of one plugin version on this node
// (ARCH §6.1). It is independent of InstallStatus on purpose: a version can be
// installed and running, installed and rejected, or stopped while its files
// are still retained for rollback.
type VersionStatus string

// Version lifecycle states of ARCH §6.1.
const (
	VersionStaged      VersionStatus = "STAGED"
	VersionStarting    VersionStatus = "STARTING"
	VersionCandidate   VersionStatus = "CANDIDATE"
	VersionActive      VersionStatus = "ACTIVE"
	VersionDraining    VersionStatus = "DRAINING"
	VersionStopped     VersionStatus = "STOPPED"
	VersionRejected    VersionStatus = "REJECTED"
	VersionRolledBack  VersionStatus = "ROLLED_BACK"
	VersionQuarantined VersionStatus = "QUARANTINED"
)

// InstallStatus is the separate installation axis (ARCH §6.6).
type InstallStatus string

// Installation states recorded by this package. Installation itself is a
// single step here; the full REQUESTED…COMPLETED transaction of §6.6 belongs
// to the uninstall workflow and is out of scope.
const (
	InstallStaged    InstallStatus = "STAGED"
	InstallInstalled InstallStatus = "INSTALLED"
	InstallRemoved   InstallStatus = "REMOVED"
)

// Strategy selects how an update uses processes (ARCH §6.3).
type Strategy string

const (
	// StrategyOverlap runs the candidate next to the old version (blue-green).
	StrategyOverlap Strategy = "overlap"
	// StrategyRestart briefly stops the old version, then starts the new one.
	StrategyRestart Strategy = "restart"
	// StrategyInstall is recorded for a fresh install, which has no old
	// version to overlap or restart.
	StrategyInstall Strategy = "install"
)

// SagaState is the terminal or running state of an update saga.
type SagaState string

const (
	SagaRunning    SagaState = "RUNNING"
	SagaCommitted  SagaState = "COMMITTED"
	SagaRolledBack SagaState = "ROLLED_BACK"
	SagaFailed     SagaState = "FAILED"
)

// Version is one row of plugin_versions plus its parsed manifest.
type Version struct {
	PluginID       string             `json:"plugin_id"`
	Version        string             `json:"version"`
	Digest         string             `json:"digest"`
	Manifest       *manifest.Manifest `json:"manifest"`
	Status         VersionStatus      `json:"status"`
	InstallStatus  InstallStatus      `json:"install_status"`
	Active         bool               `json:"active"`
	InstalledAt    time.Time          `json:"installed_at"`
	ActivatedAt    time.Time          `json:"activated_at,omitempty"`
	RejectedReason string             `json:"rejected_reason,omitempty"`
	// Revision is the resource.changed sequence of the last write to the row.
	Revision int64 `json:"revision"`
}

// InstallRequest installs a plugin that has no active version yet. Replacing
// an active version is Update.
type InstallRequest struct {
	// PluginID is optional; when set it must match the staged manifest.
	PluginID string
	// PackagePath is the plugin package to verify and stage.
	PackagePath string
	// ExpectedRevision is the active version revision the caller saw; 0 skips
	// the check, and a mismatch is REVISION_CONFLICT. A plugin with no active
	// version expects 0.
	ExpectedRevision int64
	// AcceptedCapabilities are the capability names the user approved. Every
	// capability of a fresh install must appear here.
	AcceptedCapabilities []string
	// Timeout bounds the whole install; 0 uses Options.Timeout.
	Timeout time.Duration
}

// UpdateRequest replaces the active version of an existing plugin.
type UpdateRequest struct {
	PluginID    string
	PackagePath string
	// Strategy is the requested strategy: "" chooses automatically,
	// StrategyOverlap or StrategyRestart force one. Memory preflight may still
	// downgrade overlap to restart; restart is never upgraded to overlap.
	Strategy Strategy
	// ExpectedRevision is the active version revision the caller saw; 0 skips
	// the check, and a mismatch is REVISION_CONFLICT.
	ExpectedRevision int64
	// AcceptedCapabilities must cover every capability the new version adds
	// relative to the active one.
	AcceptedCapabilities []string
	// AcceptPublisherChange allows a package whose publisher.id differs from
	// the active version's (ADR-0015). Callers only set it for a human request.
	AcceptPublisherChange bool
	Timeout               time.Duration
}

// ConfigRequest applies one immutable configuration snapshot.
type ConfigRequest struct {
	PluginID string
	// Config is the JSON object; sensitive members hold secret references.
	Config json.RawMessage
	// ExpectedRevision is the active configuration revision the caller saw; 0
	// expects no active configuration yet. A mismatch is REVISION_CONFLICT.
	ExpectedRevision int64
	Timeout          time.Duration
}

// ConfigRevision is one immutable configuration snapshot.
type ConfigRevision struct {
	PluginID string          `json:"plugin_id"`
	Revision int64           `json:"revision"`
	Config   json.RawMessage `json:"config"`
	Active   bool            `json:"active"`
	// Seq is the resource.changed sequence of the last write to the row.
	Seq       int64     `json:"seq"`
	CreatedAt time.Time `json:"created_at"`
	AppliedAt time.Time `json:"applied_at,omitempty"`
}

// UpdateResult reports a committed install, update or rollback saga.
type UpdateResult struct {
	SagaID   string `json:"saga_id"`
	PluginID string `json:"plugin_id"`
	// FromVersion is empty for a fresh install.
	FromVersion string    `json:"from_version,omitempty"`
	ToVersion   string    `json:"to_version"`
	Strategy    Strategy  `json:"strategy"`
	State       SagaState `json:"state"`
	// Restarted is true when the service was briefly down because the saga
	// used the controlled-restart strategy.
	Restarted bool    `json:"restarted"`
	Version   Version `json:"version"`
}

// Route is the routing target of one plugin.
type Route struct {
	PluginID string `json:"plugin_id"`
	Version  string `json:"version"`
}

// RouteTable is an immutable snapshot of the plugin routing targets.
//
// The updater never mutates a published table: every change builds a new
// table and hands it to Runtime.SwapRoutes, and Routes returns the pointer
// that was last published. Callers must treat a snapshot as read-only; the
// methods are safe for concurrent use.
type RouteTable struct {
	revision uint64
	routes   map[string]Route
}

// NewRouteTable builds a table from routes. The routes are copied; a
// duplicate plugin id keeps the last entry (the updater always builds unique
// lists).
func NewRouteTable(routes []Route) *RouteTable {
	t := &RouteTable{routes: make(map[string]Route, len(routes))}
	for _, r := range routes {
		t.routes[r.PluginID] = r
	}
	return t
}

// Revision is the monotonic revision of the snapshot; it increases on every
// published change.
func (t *RouteTable) Revision() uint64 {
	if t == nil {
		return 0
	}
	return t.revision
}

// Len is the number of routed plugins.
func (t *RouteTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.routes)
}

// Lookup returns the route of pluginID.
func (t *RouteTable) Lookup(pluginID string) (Route, bool) {
	if t == nil {
		return Route{}, false
	}
	r, ok := t.routes[pluginID]
	return r, ok
}

// List returns the routes sorted by plugin id. The result is a copy.
func (t *RouteTable) List() []Route {
	if t == nil {
		return nil
	}
	out := make([]Route, 0, len(t.routes))
	for _, r := range t.routes {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PluginID < out[j].PluginID })
	return out
}

// clone returns a copy of the table with the same revision.
func (t *RouteTable) clone() *RouteTable {
	n := &RouteTable{revision: t.Revision(), routes: make(map[string]Route, len(t.routes)+1)}
	for k, v := range t.routes {
		n.routes[k] = v
	}
	return n
}
