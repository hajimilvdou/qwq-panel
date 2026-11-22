// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/panelaccess"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestSystemAccessCRUDAndRebind(t *testing.T) {
	var reboundTo string
	var mgr *panelaccess.Manager
	e := newEnvWith(t, func(d *api.Deps) {
		var err error
		mgr, err = panelaccess.NewManager(t.Context(), panelaccess.Options{
			DB:    d.DB,
			Clock: d.Clock,
			Bootstrap: config.HTTP{
				Listen:    "127.0.0.1:41234",
				TLS:       config.TLS{Mode: config.TLSSelfSigned},
				EntryPath: "jsnsjx8k",
				Disguise:  config.DisguiseDrop,
			},
			Rebind: func(newAddr string) error {
				reboundTo = newAddr
				return nil
			},
		})
		if err != nil {
			t.Fatalf("panelaccess.NewManager: %v", err)
		}
		d.Access = mgr
	})

	admin := e.setupAdmin(adminUser)

	// 1. Admin can read current panel access settings.
	var got struct {
		Port                int    `json:"port"`
		Listen              string `json:"listen"`
		EntryPath           string `json:"entry_path"`
		EffectiveEntryPath  string `json:"effective_entry_path"`
		EntryGateActive     bool   `json:"entry_gate_active"`
		Disguise            string `json:"disguise"`
		PanelDomain         string `json:"panel_domain"`
		AutoDisableOnDomain bool   `json:"auto_disable_on_domain"`
		BypassReason        string `json:"bypass_reason"`
		PortChanged         bool   `json:"port_changed"`
		Revision            int64  `json:"revision"`
	}
	e.do(admin.sign(http.MethodGet, "/api/v1/system/access", "")).expect(t, http.StatusOK).decode(t, &got)
	if got.Port != 41234 || got.EntryPath != "jsnsjx8k" || !got.EntryGateActive || got.Disguise != "drop" || !got.AutoDisableOnDomain {
		t.Fatalf("GET /api/v1/system/access = %+v", got)
	}

	// 2. Admin can update port, secret entry path, and disguise mode.
	putResp := e.do(admin.sign(http.MethodPut, "/api/v1/system/access",
		`{"port":45678,"entry_path":"mysecret99","disguise":"nginx_404","expected_revision":1}`)).expect(t, http.StatusOK)
	putResp.decode(t, &got)
	if !got.PortChanged || got.Port != 45678 || reboundTo != "127.0.0.1:45678" || got.EntryPath != "mysecret99" || got.Disguise != "nginx_404" || got.Revision != 2 {
		t.Fatalf("PUT /api/v1/system/access = %+v (reboundTo=%q)", got, reboundTo)
	}
	// Verify fresh gate cookie is set on the response so the admin tab doesn't lock out.
	var hasGateCookie bool
	for _, c := range (&http.Response{Header: putResp.header}).Cookies() {
		if c.Name == panelaccess.GateCookieName && c.HttpOnly {
			hasGateCookie = true
		}
	}
	if !hasGateCookie {
		t.Fatalf("expected %s cookie on PUT response, got %v", panelaccess.GateCookieName, putResp.header.Values("Set-Cookie"))
	}

	// 3. Stale revision returns 409 CONFLICT.
	e.do(admin.sign(http.MethodPut, "/api/v1/system/access",
		`{"disguise":"blank_404","expected_revision":1}`)).expectProblem(t, http.StatusConflict, problem.RevisionConflict)

	// 4. Setting a reverse-proxy panel_domain automatically disables entry gate & disguise.
	e.do(admin.sign(http.MethodPut, "/api/v1/system/access",
		`{"panel_domain":"panel.example.com","expected_revision":2}`)).expect(t, http.StatusOK).decode(t, &got)
	if got.PanelDomain != "panel.example.com" || got.EntryGateActive || got.EffectiveEntryPath != "" || got.BypassReason != "panel_domain" {
		t.Fatalf("domain auto-disable = %+v", got)
	}

	// 5. GET /api/v1/system reflects the live rebound port.
	var sys struct {
		Listen string `json:"listen"`
	}
	e.do(admin.sign(http.MethodGet, "/api/v1/system", "")).expect(t, http.StatusOK).decode(t, &sys)
	if sys.Listen != "127.0.0.1:45678" {
		t.Fatalf("GET /api/v1/system listen = %q, want 127.0.0.1:45678", sys.Listen)
	}
}
