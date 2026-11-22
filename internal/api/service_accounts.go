// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 服务账号通用管理 CRUD 与受限续期账号入口 ========================

type serviceAccountDTO struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Role        string              `json:"role"`
	TokenPrefix string              `json:"token_prefix"`
	Status      string              `json:"status"`
	Disabled    bool                `json:"disabled"`
	CreatedBy   string              `json:"created_by"`
	CreatedAt   string              `json:"created_at"`
	UpdatedAt   string              `json:"updated_at"`
	LastUsedAt  string              `json:"last_used_at,omitempty"`
	Scope       *authz.ServiceScope `json:"scope,omitempty"`
	Revision    string              `json:"revision"`
}

type serviceAccountCreatedDTO struct {
	serviceAccountDTO
	Token string `json:"token"`
}

type serviceAccountCreateRequest struct {
	Name  string              `json:"name"`
	Role  string              `json:"role"`
	Scope *authz.ServiceScope `json:"scope,omitempty"`
}

func newServiceAccountDTO(sa authz.ServiceAccount, now time.Time) serviceAccountDTO {
	status := "active"
	if sa.Disabled {
		status = "revoked"
	} else if sa.Scope != nil && !now.Before(sa.Scope.ExpiresAt) {
		status = "expired"
	}
	dto := serviceAccountDTO{
		ID:          sa.ID,
		Name:        sa.Name,
		Role:        string(sa.Role),
		TokenPrefix: sa.TokenPrefix,
		Status:      status,
		Disabled:    sa.Disabled,
		CreatedBy:   sa.CreatedBy,
		CreatedAt:   sa.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   sa.UpdatedAt.UTC().Format(time.RFC3339),
		Scope:       sa.Scope,
		Revision:    strconv.FormatInt(sa.Revision, 10),
	}
	if !sa.LastUsedAt.IsZero() {
		dto.LastUsedAt = sa.LastUsedAt.UTC().Format(time.RFC3339)
	}
	return dto
}

// listServiceAccounts 实现 GET /api/v1/service-accounts（永不返回明文 token）。
func (a *api) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.service_accounts:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	q, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	accounts, err := a.d.Authz.ListServiceAccounts(r.Context(), pageLimit(q.Limit))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	accounts, next := nextCursor(accounts, q.Limit, func(s authz.ServiceAccount) string { return s.ID })
	now := a.d.Clock.Now().UTC()
	items := make([]any, 0, len(accounts))
	for _, sa := range accounts {
		items = append(items, newServiceAccountDTO(sa, now))
	}
	a.writeList(w, r, listResponse{Items: items, NextCursor: next, Revision: a.watermark()}, q.Fields)
}

// createServiceAccount 实现 POST /api/v1/service-accounts（仅真人会话管理员，单次返回 token）。
func (a *api) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.service_accounts:create", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req serviceAccountCreateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/name", Code: "REQUIRED", Message: "A service account name is required.",
		}))
		return
	}
	key, err := a.idempotency(r, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	response, err := a.catalogWrite(r, act, key, "host.service_accounts:create", http.StatusCreated, "token", func(tx *storage.Tx) (any, error) {
		created, err := a.d.Authz.CreateServiceAccount(r.Context(), tx, authz.CreateServiceAccountInput{
			Actor: act,
			Name:  req.Name,
			Role:  authz.Role(strings.TrimSpace(req.Role)),
			Scope: req.Scope,
		})
		if err != nil {
			return nil, err
		}
		if err := operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor: act, Action: "service_account.create", Subject: created.Subject(),
			Outcome: operations.AuditSuccess, TraceID: traceID(r),
			RequestID: requestID(r),
		}); err != nil {
			return nil, err
		}
		return serviceAccountCreatedDTO{
			serviceAccountDTO: newServiceAccountDTO(created.ServiceAccount, tx.Now()),
			Token:             created.Token,
		}, nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeCatalogResponse(w, r, response)
}

// deleteServiceAccount 实现 DELETE /api/v1/service-accounts/{service_id}。
func (a *api) deleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.service_accounts:delete", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	expected, err := gateway.ExpectedRevisionQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	revision, err := parseExpectedRevision(expected)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id := r.PathValue("service_id")
	key, err := a.idempotency(r, expected)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	response, err := a.catalogWrite(r, act, key, "host.service_accounts:delete", http.StatusNoContent, "", func(tx *storage.Tx) (any, error) {
		if rerr := a.d.Authz.RevokeServiceAccount(r.Context(), tx, authz.RevokeServiceAccountInput{
			Actor: act, ServiceAccountID: id, ExpectedRevision: revision,
		}); rerr != nil {
			return nil, rerr
		}
		if err := operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor: act, Action: "service_account.revoke", Subject: "service_accounts/" + id,
			Outcome: operations.AuditSuccess, TraceID: traceID(r),
			RequestID: requestID(r),
		}); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeCatalogResponse(w, r, response)
}

// ======================== 真人确认的受限续期账号入口 ========================

func (a *api) bootstrapRenewalService(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.service_accounts:create", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var request hostauth.RenewalBootstrapArgs
	if err := a.decodeJSON(r, &request); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := request.Validate(); err != nil {
		a.fail(w, r, err)
		return
	}
	args, err := json.Marshal(request)
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	idem, err := a.idempotency(r, request)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	resp, err := a.d.Ops.Run(r.Context(), operations.RunRequest{
		Actor: act, NodeID: a.d.NodeID, Action: hostauth.RenewalBootstrapAction,
		Args: args, Target: operations.Target{Subject: request.Subject()},
		TraceID: traceID(r), RequestID: requestID(r), Idempotency: idem,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}
