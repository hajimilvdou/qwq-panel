// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/panelaccess"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// panelAccessDTO is the PanelAccessSettings schema.
type panelAccessDTO struct {
	ListenHost          string `json:"listen_host"`
	Port                int    `json:"port"`
	Listen              string `json:"listen"`
	TLSMode             string `json:"tls_mode"`
	EntryPath           string `json:"entry_path"`
	EffectiveEntryPath  string `json:"effective_entry_path"`
	EntryGateActive     bool   `json:"entry_gate_active"`
	Disguise            string `json:"disguise"`
	DisguiseHTML        string `json:"disguise_html"`
	PanelDomain         string `json:"panel_domain"`
	AutoDisableOnDomain bool   `json:"auto_disable_on_domain"`
	BypassReason        string `json:"bypass_reason,omitempty"`
	PortChanged         bool   `json:"port_changed,omitempty"`
	Revision            int64  `json:"revision"`
	UpdatedAt           string `json:"updated_at"`
}

type panelAccessUpdateRequest struct {
	Port                    *int    `json:"port,omitempty"`
	EntryPath               *string `json:"entry_path,omitempty"`
	GenerateRandomEntryPath bool    `json:"generate_random_entry_path,omitempty"`
	Disguise                *string `json:"disguise,omitempty"`
	DisguiseHTML            *string `json:"disguise_html,omitempty"`
	PanelDomain             *string `json:"panel_domain,omitempty"`
	AutoDisableOnDomain     *bool   `json:"auto_disable_on_domain,omitempty"`
	ExpectedRevision        *int64  `json:"expected_revision,omitempty"`
}

func panelAccessToDTO(s panelaccess.Snapshot, portChanged bool) panelAccessDTO {
	return panelAccessDTO{
		ListenHost:          s.ListenHost,
		Port:                s.Port,
		Listen:              s.ListenAddr(),
		TLSMode:             s.TLSMode,
		EntryPath:           s.EntryPath,
		EffectiveEntryPath:  s.EffectiveEntryPath(),
		EntryGateActive:     s.EntryGateActive(),
		Disguise:            s.EffectiveDisguise(),
		DisguiseHTML:        s.DisguiseHTML,
		PanelDomain:         s.PanelDomain,
		AutoDisableOnDomain: s.AutoDisableOnDomain,
		BypassReason:        s.DomainAutoBypassReason(),
		PortChanged:         portChanged,
		Revision:            s.Revision,
		UpdatedAt:           ts(s.UpdatedAt),
	}
}

// getSystemAccess implements GET /api/v1/system/access (administrators only).
func (a *api) getSystemAccess(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Access == nil {
		a.fail(w, r, problem.New(problem.Unavailable, "Panel access settings are not available."))
		return
	}
	a.writeResource(w, r, http.StatusOK, panelAccessToDTO(a.d.Access.Snapshot(), false), nil)
}

// putSystemAccess implements PUT /api/v1/system/access (administrators only).
func (a *api) putSystemAccess(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Identity != nil {
		u, uerr := a.d.Identity.User(r.Context(), act.ID)
		if uerr != nil {
			a.fail(w, r, uerr)
			return
		}
		if u.MFAEnabled && !act.MFA {
			a.fail(w, r, problem.New(problem.MFARequired,
				"Updating panel access settings requires a fresh second factor."))
			return
		}
	}
	if a.d.Access == nil {
		a.fail(w, r, problem.New(problem.Unavailable, "Panel access settings are not available."))
		return
	}
	var req panelAccessUpdateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	snap, portChanged, err := a.d.Access.Update(r.Context(), panelaccess.UpdateInput{
		Port:                    req.Port,
		EntryPath:               req.EntryPath,
		GenerateRandomEntryPath: req.GenerateRandomEntryPath,
		Disguise:                req.Disguise,
		DisguiseHTML:            req.DisguiseHTML,
		PanelDomain:             req.PanelDomain,
		AutoDisableOnDomain:     req.AutoDisableOnDomain,
		ExpectedRevision:        req.ExpectedRevision,
		AuditTx: func(ctx context.Context, tx *storage.Tx, next panelaccess.Snapshot, changed bool) error {
			details, _ := json.Marshal(map[string]any{
				"port":              next.Port,
				"port_changed":      changed,
				"entry_gate_active": next.EntryGateActive(),
				"disguise":          next.EffectiveDisguise(),
				"panel_domain":      next.PanelDomain,
				"bypass_reason":     next.DomainAutoBypassReason(),
			})
			return operations.Audit(ctx, tx, operations.AuditRecord{
				Actor:     act,
				Action:    "system.access.update",
				Subject:   "system/access",
				Outcome:   operations.AuditSuccess,
				Details:   details,
				NodeID:    a.d.NodeID,
				TraceID:   gateway.TraceID(r.Context()),
				RequestID: requestID(r),
			})
		},
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// Keep the administrator's current browser tab authorized immediately when
	// a secret entry path is configured or rotated (including bare-IP rescue).
	if rawEntry := config.NormalizeEntryPath(snap.EntryPath); rawEntry != "" {
		secure := snap.TLSMode != "" || r.TLS != nil
		snap.SetGateCookieForPath(w, rawEntry, secure)
	}
	a.d.Logger.InfoContext(r.Context(), "panel access settings updated",
		"actor", act.ID,
		"port", snap.Port,
		"port_changed", portChanged,
		"entry_gate_active", snap.EntryGateActive(),
		"disguise", snap.EffectiveDisguise(),
		"panel_domain", snap.PanelDomain,
		"bypass_reason", snap.DomainAutoBypassReason(),
	)
	a.writeResource(w, r, http.StatusOK, panelAccessToDTO(snap, portChanged), nil)
}
