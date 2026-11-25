// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/qwq-panel/qwq/internal/capability/firewall"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/storage"
)

func capabilitySocketPath() string {
	if env := strings.TrimSpace(os.Getenv("QWQ_CAPABILITY_SOCKET")); env != "" {
		return env
	}
	return sandbox.DefaultCapabilitySocket
}

func (a *api) callFirewallCapability(r *http.Request, op string, params any) (firewall.TakeoverStatusResponse, error) {
	var out firewall.TakeoverStatusResponse
	sock := capabilitySocketPath()
	if _, err := os.Stat(sock); err != nil {
		return out, problem.New(problem.Unavailable, "系统特权能力通道（qwq-capability）当前不可用，请检查 qwq-capability.socket 服务状态。")
	}
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return out, problem.Wrap(err)
		}
		rawParams = b
	}
	client := sandbox.NewCapabilityClient(sock)
	resp, err := client.Call(r.Context(), sandbox.CapabilityRequest{
		Op:         op,
		ID:         "security.basic",
		ParamsJSON: rawParams,
	})
	if err != nil {
		return out, err
	}
	if !resp.OK {
		code := problem.Code(resp.Code)
		if code == "" {
			code = problem.Unavailable
		}
		msg := resp.Error
		if msg == "" {
			msg = "接管操作未能完成"
		}
		return out, problem.New(code, "%s", msg)
	}
	if len(resp.ResultJSON) > 0 {
		if err := json.Unmarshal(resp.ResultJSON, &out); err != nil {
			return out, problem.Wrap(err)
		}
	}
	if out.Managers == nil {
		out.Managers = []firewall.TakeoverStatusEntry{}
	}
	return out, nil
}

// getSecurityTakeover implements GET /api/v1/system/security/takeover (admin only).
func (a *api) getSecurityTakeover(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := a.callFirewallCapability(r, "firewall.takeover_status", nil)
	if err != nil {
		// Gracefully return empty list when capability socket is absent in non-systemd environments.
		if pErr, ok := err.(*problem.Error); ok && pErr.Code == problem.Unavailable {
			a.writeResource(w, r, http.StatusOK, firewall.TakeoverStatusResponse{
				Managers: []firewall.TakeoverStatusEntry{},
			}, nil)
			return
		}
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, res, nil)
}

type securityTakeoverRequest struct {
	Manager string `json:"manager"`
}

func validateTakeoverManager(raw string) (string, error) {
	m := strings.ToLower(strings.TrimSpace(raw))
	switch m {
	case "ufw", "firewalld", "fail2ban":
		return m, nil
	default:
		return "", problem.Validation(problem.Violation{
			Pointer: "/manager",
			Code:    "INVALID_VALUE",
			Message: "manager must be one of ufw, firewalld, or fail2ban.",
		})
	}
}

// postSecurityTakeover implements POST /api/v1/system/security/takeover (admin only).
// Backs up existing firewall / fail2ban configs, imports open ports into inet qwq,
// and disables the competing service so qwq manages it directly.
func (a *api) postSecurityTakeover(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	var req securityTakeoverRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	mgr, err := validateTakeoverManager(req.Manager)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := a.callFirewallCapability(r, "firewall.takeover", map[string]string{"manager": mgr})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	details, _ := json.Marshal(map[string]any{"manager": mgr, "action": "takeover"})
	_ = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		return operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor:     act,
			Action:    "system.security.takeover",
			Subject:   "system/security/" + mgr,
			Outcome:   operations.AuditSuccess,
			Details:   details,
			NodeID:    a.d.NodeID,
			TraceID:   gateway.TraceID(r.Context()),
			RequestID: requestID(r),
		})
	})
	a.writeResource(w, r, http.StatusOK, res, nil)
}

// postSecurityRestore implements POST /api/v1/system/security/restore (admin only).
// Clears qwq's takeover state and re-enables the backed-up original manager.
func (a *api) postSecurityRestore(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	var req securityTakeoverRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	mgr, err := validateTakeoverManager(req.Manager)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := a.callFirewallCapability(r, "firewall.restore_manager", map[string]string{"manager": mgr})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	details, _ := json.Marshal(map[string]any{"manager": mgr, "action": "restore"})
	_ = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		return operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor:     act,
			Action:    "system.security.restore",
			Subject:   "system/security/" + mgr,
			Outcome:   operations.AuditSuccess,
			Details:   details,
			NodeID:    a.d.NodeID,
			TraceID:   gateway.TraceID(r.Context()),
			RequestID: requestID(r),
		})
	})
	a.writeResource(w, r, http.StatusOK, res, nil)
}
