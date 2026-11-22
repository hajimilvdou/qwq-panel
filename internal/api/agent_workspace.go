// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// listAgentWorkspaceFiles implements GET /api/v1/agent/workspace/files?area=mcp|skills|prompts.
func (a *api) listAgentWorkspaceFiles(w http.ResponseWriter, r *http.Request) {
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
	area := r.URL.Query().Get("area")
	res, err := svc.Workspace().ListFiles(area)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, res, fields)
}

// getAgentWorkspaceFile implements GET /api/v1/agent/workspace/file?area=...&path=...
func (a *api) getAgentWorkspaceFile(w http.ResponseWriter, r *http.Request) {
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
	q := r.URL.Query()
	res, err := svc.Workspace().ReadFile(q.Get("area"), q.Get("path"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, res, fields)
}

// putAgentWorkspaceFile implements PUT /api/v1/agent/workspace/file (text save or drag-and-drop upload).
func (a *api) putAgentWorkspaceFile(w http.ResponseWriter, r *http.Request) {
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
	var req agentsession.WorkspaceWriteInput
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	entry, err := svc.Workspace().WriteFile(req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, entry, nil)
}

// deleteAgentWorkspaceFile implements DELETE /api/v1/agent/workspace/file?area=...&path=...
func (a *api) deleteAgentWorkspaceFile(w http.ResponseWriter, r *http.Request) {
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
	q := r.URL.Query()
	if err := svc.Workspace().DeletePath(q.Get("area"), q.Get("path")); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// searchAgentRegistry implements GET /api/v1/agent/registry.
func (a *api) searchAgentRegistry(w http.ResponseWriter, r *http.Request) {
	if _, err := a.caller(r); err != nil {
		a.fail(w, r, err)
		return
	}
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	reg := svc.Registry()
	if reg == nil {
		a.fail(w, r, problem.New(problem.Unavailable, "Official agent registry is unavailable."))
		return
	}
	q := r.URL.Query()
	res := reg.Search(r.Context(), agentsession.RegistryQuery{
		Kind:    q.Get("kind"),
		Source:  q.Get("source"),
		Query:   q.Get("q"),
		Refresh: q.Get("refresh") == "1" || q.Get("refresh") == "true",
	})
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, res, fields)
}

// installAgentRegistryItem implements POST /api/v1/agent/registry/install (admin-only).
func (a *api) installAgentRegistryItem(w http.ResponseWriter, r *http.Request) {
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
	reg := svc.Registry()
	if reg == nil {
		a.fail(w, r, problem.New(problem.Unavailable, "Official agent registry is unavailable."))
		return
	}
	var req agentsession.RegistryInstallInput
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := reg.Install(r.Context(), req.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, res, nil)
}
