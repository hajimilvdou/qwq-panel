// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/qwq-panel/qwq/internal/buildinfo"
)

// The system overview (GAPS gap 7). Every signed-in principal may read it; the
// listener address and the data directory are administrator information, so they
// are omitted for everyone else rather than redacted to a placeholder.

// systemInfoDTO is the SystemInfo schema.
type systemInfoDTO struct {
	Version        string       `json:"version"`
	Commit         string       `json:"commit,omitempty"`
	Role           string       `json:"role"`
	StartedAt      string       `json:"started_at"`
	TLS            systemTLSDTO `json:"tls"`
	Listen         string       `json:"listen,omitempty"`
	DataDir        string       `json:"data_dir,omitempty"`
	PluginsEnabled bool         `json:"plugins_enabled"`
}

// systemTLSDTO is the tls member of SystemInfo.
type systemTLSDTO struct {
	Mode        string   `json:"mode"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	Domains     []string `json:"domains,omitempty"`
}

// getSystem implements GET /api/v1/system.
func (a *api) getSystem(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.system:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	info := buildinfo.Read()
	out := systemInfoDTO{
		Version:   info.Version,
		Commit:    info.Revision,
		Role:      a.d.Config.Role,
		StartedAt: ts(a.startedAt),
		TLS:       systemTLSDTO{Mode: a.d.Config.HTTP.TLS.Mode, Domains: a.d.Config.HTTP.TLS.Domains},
	}
	if a.d.TLS != nil {
		status := a.d.TLS.Status(r.Context())
		out.TLS.Mode = a.d.TLS.Mode()
		out.TLS.Fingerprint = status.Fingerprint
		out.TLS.NotAfter = ts(status.NotAfter)
	}
	if a.isAdmin(r.Context(), act) {
		out.Listen = a.d.Config.HTTP.Listen
		out.DataDir = a.d.Config.DataDir
	}
	out.PluginsEnabled = a.pluginsEnabled(r)
	a.writeResource(w, r, http.StatusOK, out, nil)
}

// pluginsEnabled reports whether any plugin has an active version. A host
// without an updater has none.
func (a *api) pluginsEnabled(r *http.Request) bool {
	if a.d.Plugins == nil {
		return false
	}
	plugins, err := a.d.Plugins.List(r.Context())
	if err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: count enabled plugins", "error", err)
		return false
	}
	for _, p := range plugins {
		if p.ActiveVersion != "" {
			return true
		}
	}
	return false
}
