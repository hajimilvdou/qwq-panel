// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

type agentCoreAuthList struct {
	Items []agentsession.CoreAuthStatus `json:"items"`
}

// listAgentCoreAuth implements GET /api/v1/agent/cores/auth.
// Any signed-in principal sees installation and logged_in status (so NewSession
// can show whether official login is ready); in-flight OAuth device URLs and
// output logs are restricted to human administrators.
func (a *api) listAgentCoreAuth(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	mgr := svc.CLIAuth()
	if mgr == nil {
		a.writeResource(w, r, http.StatusOK, agentCoreAuthList{Items: []agentsession.CoreAuthStatus{}}, nil)
		return
	}
	admin := a.isAdmin(r.Context(), act)
	items := mgr.StatusList()
	if !admin {
		for i := range items {
			items[i].ActiveLogin = nil
		}
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, agentCoreAuthList{Items: items}, fields)
}

// startAgentCoreLogin implements POST /api/v1/agent/cores/{core}/login (admin-only).
func (a *api) startAgentCoreLogin(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	mgr := svc.CLIAuth()
	if mgr == nil {
		a.fail(w, r, problem.New(problem.Unavailable, "External CLI login manager is unavailable."))
		return
	}
	var req agentsession.CLILoginInput
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	core := agentsession.CoreName(r.PathValue("core"))
	st, err := mgr.StartLogin(r.Context(), core, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, st, nil)
}

// logoutAgentCore implements DELETE /api/v1/agent/cores/{core}/login (admin-only).
func (a *api) logoutAgentCore(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	mgr := svc.CLIAuth()
	if mgr == nil {
		a.fail(w, r, problem.New(problem.Unavailable, "External CLI login manager is unavailable."))
		return
	}
	core := agentsession.CoreName(r.PathValue("core"))
	st, err := mgr.Logout(core)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, st, nil)
}
