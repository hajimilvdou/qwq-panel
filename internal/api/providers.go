// SPDX-License-Identifier: AGPL-3.0-only

package api

// ============================================================================
//  Global AI providers (GAP-2, ADR-0017)
//
//  Providers are an administrator's resource: create, update and delete run as
//  ordinary host operations (host.ai_providers.*) with permission
//  host.ai_providers:*, which only an administrator holds, and the resource is
//  human-only, so no AI operator or service account reaches it — that is what
//  keeps a prompt-injected agent from repointing where the installation sends
//  model traffic. Listing is open to every signed-in principal: anyone may pick
//  a provider for a session, but a non-administrator never sees base_url.
//
//  The API key is not part of these routes: it is written with
//  PUT/DELETE /api/v1/ai/providers/{provider_id}/api-key, a catalog-exempt
//  route (the plaintext must not reach an operation record or a replay).
// ============================================================================

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Action IDs of the AI provider host actions.
const (
	actionAIProviderCreate = "host.ai_providers.create"
	actionAIProviderUpdate = "host.ai_providers.update"
	actionAIProviderDelete = "host.ai_providers.delete"
)

// aiProviderDTO is the AiProvider schema in its full (administrator) shape.
type aiProviderDTO struct {
	ProviderID       string   `json:"provider_id"`
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	BaseURL          string   `json:"base_url"`
	Model            string   `json:"model"`
	Models           []string `json:"models"`
	ReasoningEffort  string   `json:"reasoning_effort,omitempty"`
	MaxContextTokens int64    `json:"max_context_tokens,omitempty"`
	HasAPIKey        bool     `json:"has_api_key"`
	IsDefault        bool     `json:"is_default"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
	Revision         string   `json:"revision"`
}

// aiProviderReducedDTO is the projection every non-administrator gets: names
// and state only. base_url (and the timestamps) stay with the administrator,
// so a low-privileged user cannot map the installation's model traffic
// (GAPS 缺口 2).
type aiProviderReducedDTO struct {
	ProviderID       string   `json:"provider_id"`
	Name             string   `json:"name"`
	Model            string   `json:"model"`
	Models           []string `json:"models"`
	ReasoningEffort  string   `json:"reasoning_effort,omitempty"`
	MaxContextTokens int64    `json:"max_context_tokens,omitempty"`
	HasAPIKey        bool     `json:"has_api_key"`
	IsDefault        bool     `json:"is_default"`
}

// newAIProviderDTO renders one provider for the given projection.
func newAIProviderDTO(p *agentsession.AIProvider, admin bool) any {
	models := p.Models
	if models == nil {
		models = []string{}
	}
	if !admin {
		return aiProviderReducedDTO{
			ProviderID: p.ID, Name: p.Name, Model: p.Model,
			Models: models, ReasoningEffort: p.ReasoningEffort, MaxContextTokens: p.MaxContextTokens,
			HasAPIKey: p.HasAPIKey(), IsDefault: p.IsDefault,
		}
	}
	return aiProviderDTO{
		ProviderID: p.ID, Name: p.Name, Kind: p.Kind, BaseURL: p.BaseURL, Model: p.Model,
		Models: models, ReasoningEffort: p.ReasoningEffort, MaxContextTokens: p.MaxContextTokens,
		HasAPIKey: p.HasAPIKey(), IsDefault: p.IsDefault,
		CreatedAt: ts(p.CreatedAt), UpdatedAt: ts(p.UpdatedAt), Revision: p.Revision,
	}
}

// aiProviderList is the AiProviderList schema. The list is bounded (providers
// are a handful of administrator rows), so it carries no cursor or revision.
type aiProviderList struct {
	Items []any `json:"items"`
}

// aiProviderCreateRequest is the AiProviderCreateRequest schema.
type aiProviderCreateRequest struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	BaseURL          string   `json:"base_url"`
	Model            string   `json:"model"`
	Models           []string `json:"models,omitempty"`
	ReasoningEffort  string   `json:"reasoning_effort,omitempty"`
	MaxContextTokens int64    `json:"max_context_tokens,omitempty"`
	IsDefault        bool     `json:"is_default"`
}

// aiProviderCreateArgs are the arguments of host.ai_providers.create: the
// request body, verbatim (the route has no path parameters).
type aiProviderCreateArgs struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	BaseURL          string   `json:"base_url"`
	Model            string   `json:"model"`
	Models           []string `json:"models,omitempty"`
	ReasoningEffort  string   `json:"reasoning_effort,omitempty"`
	MaxContextTokens int64    `json:"max_context_tokens,omitempty"`
	IsDefault        bool     `json:"is_default"`
}

// aiProviderUpdateRequest is the AiProviderUpdateRequest schema.
type aiProviderUpdateRequest struct {
	ExpectedRevision string    `json:"expected_revision"`
	Name             *string   `json:"name,omitempty"`
	Kind             *string   `json:"kind,omitempty"`
	BaseURL          *string   `json:"base_url,omitempty"`
	Model            *string   `json:"model,omitempty"`
	Models           *[]string `json:"models,omitempty"`
	ReasoningEffort  *string   `json:"reasoning_effort,omitempty"`
	MaxContextTokens *int64    `json:"max_context_tokens,omitempty"`
	IsDefault        *bool     `json:"is_default,omitempty"`
}

// aiProviderUpdateArgs are the arguments of host.ai_providers.update.
type aiProviderUpdateArgs struct {
	ProviderID       string    `json:"provider_id"`
	ExpectedRevision string    `json:"expected_revision"`
	Name             *string   `json:"name,omitempty"`
	Kind             *string   `json:"kind,omitempty"`
	BaseURL          *string   `json:"base_url,omitempty"`
	Model            *string   `json:"model,omitempty"`
	Models           *[]string `json:"models,omitempty"`
	ReasoningEffort  *string   `json:"reasoning_effort,omitempty"`
	MaxContextTokens *int64    `json:"max_context_tokens,omitempty"`
	IsDefault        *bool     `json:"is_default,omitempty"`
}

// aiProviderDeleteArgs are the arguments of host.ai_providers.delete.
type aiProviderDeleteArgs struct {
	ProviderID       string `json:"provider_id"`
	ExpectedRevision string `json:"expected_revision"`
}

// agentCoreDTO is the AgentCoreInfo schema.
type agentCoreDTO struct {
	Core      string `json:"core"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// agentCoreList is the AgentCoreList schema.
type agentCoreList struct {
	Items []agentCoreDTO `json:"items"`
}

// listAgentCores returns the cores this host can run (GAPS 缺口 2). Any
// signed-in principal may read it; a session picks a core at creation.
func (a *api) listAgentCores(w http.ResponseWriter, r *http.Request) {
	if _, err := a.caller(r); err != nil {
		a.fail(w, r, err)
		return
	}
	cores := a.d.AgentSessions.Cores()
	items := make([]agentCoreDTO, 0, len(cores))
	for _, c := range cores {
		items = append(items, agentCoreDTO{Core: string(c.Core), Available: c.Available, Reason: c.Reason})
	}
	a.writeResource(w, r, http.StatusOK, agentCoreList{Items: items}, nil)
}

// isAdmin reports whether act is an enabled human administrator. A service
// account or a disabled user is not, so the reduced provider projection is the
// fail-closed default.
func (a *api) isAdmin(ctx context.Context, act actor.Actor) bool {
	if act.Kind != actor.Human {
		return false
	}
	role, disabled, err := a.d.Identity.PrincipalRole(ctx, act.ID)
	return err == nil && !disabled && authz.Role(role) == authz.RoleAdmin
}

// listAIProviders returns every provider. Any signed-in principal may list;
// the projection depends on the caller's role.
func (a *api) listAIProviders(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	providers, err := a.d.AgentSessions.ListProviders(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	admin := a.isAdmin(r.Context(), act)
	items := make([]any, 0, len(providers))
	for i := range providers {
		items = append(items, newAIProviderDTO(&providers[i], admin))
	}
	a.writeResource(w, r, http.StatusOK, aiProviderList{Items: items}, nil)
}

// checkProviderFields validates a full create body against the domain rules,
// so a bad value is a 400 before an operation is queued.
func (a *api) checkProviderFields(name, kind, baseURL, model string, models []string, effort string, maxCtx int64) error {
	if _, err := agentsession.ValidateProviderName(name); err != nil {
		return err
	}
	if _, err := agentsession.ValidateProviderKind(kind); err != nil {
		return err
	}
	if _, err := agentsession.ValidateModelBaseURL(baseURL, "/base_url"); err != nil {
		return err
	}
	if _, err := agentsession.ValidateProviderModel(model); err != nil {
		return err
	}
	if _, err := agentsession.ValidateProviderModels(models); err != nil {
		return err
	}
	if _, err := agentsession.ValidateReasoningEffort(effort, "/reasoning_effort"); err != nil {
		return err
	}
	if _, err := agentsession.ValidateMaxContextTokens(maxCtx, "/max_context_tokens"); err != nil {
		return err
	}
	return nil
}

// checkProviderPatch validates only the members an update carries.
func (a *api) checkProviderPatch(req aiProviderUpdateRequest) error {
	if req.Name != nil {
		if _, err := agentsession.ValidateProviderName(*req.Name); err != nil {
			return err
		}
	}
	if req.Kind != nil {
		if _, err := agentsession.ValidateProviderKind(*req.Kind); err != nil {
			return err
		}
	}
	if req.BaseURL != nil {
		if _, err := agentsession.ValidateModelBaseURL(*req.BaseURL, "/base_url"); err != nil {
			return err
		}
	}
	if req.Model != nil {
		if _, err := agentsession.ValidateProviderModel(*req.Model); err != nil {
			return err
		}
	}
	if req.Models != nil {
		if _, err := agentsession.ValidateProviderModels(*req.Models); err != nil {
			return err
		}
	}
	if req.ReasoningEffort != nil {
		if _, err := agentsession.ValidateReasoningEffort(*req.ReasoningEffort, "/reasoning_effort"); err != nil {
			return err
		}
	}
	if req.MaxContextTokens != nil {
		if _, err := agentsession.ValidateMaxContextTokens(*req.MaxContextTokens, "/max_context_tokens"); err != nil {
			return err
		}
	}
	return nil
}

// createAIProvider runs host.ai_providers.create. The action is human-only, so
// there is no AI caller for an approval to stop; risk low keeps the settings
// flow to one step (create, then set the key).
func (a *api) createAIProvider(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.ai_providers:create", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req aiProviderCreateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.checkProviderFields(req.Name, req.Kind, req.BaseURL, req.Model, req.Models, req.ReasoningEffort, req.MaxContextTokens); err != nil {
		a.fail(w, r, err)
		return
	}
	args, err := json.Marshal(aiProviderCreateArgs(req))
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	idem, err := a.idempotency(r, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	resp, err := a.d.Ops.Run(r.Context(), operations.RunRequest{
		Actor:       act,
		TraceID:     traceID(r),
		RequestID:   requestID(r),
		NodeID:      a.d.NodeID,
		Action:      actionAIProviderCreate,
		Args:        args,
		Idempotency: idem,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// updateAIProvider patches a provider through host.ai_providers.update.
func (a *api) updateAIProvider(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.ai_providers:update", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	providerID := r.PathValue("provider_id")
	var req aiProviderUpdateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := parseExpectedRevision(req.ExpectedRevision); err != nil {
		a.fail(w, r, err)
		return
	}
	if req.Name == nil && req.Kind == nil && req.BaseURL == nil && req.Model == nil &&
		req.Models == nil && req.ReasoningEffort == nil && req.MaxContextTokens == nil && req.IsDefault == nil {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/", Code: "empty",
			Message: "At least one editable field is required.",
		}))
		return
	}
	if err := a.checkProviderPatch(req); err != nil {
		a.fail(w, r, err)
		return
	}
	args, err := json.Marshal(aiProviderUpdateArgs{
		ProviderID: providerID, ExpectedRevision: req.ExpectedRevision,
		Name: req.Name, Kind: req.Kind, BaseURL: req.BaseURL, Model: req.Model,
		Models: req.Models, ReasoningEffort: req.ReasoningEffort, MaxContextTokens: req.MaxContextTokens,
		IsDefault: req.IsDefault,
	})
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	idem, err := a.idempotency(r, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	resp, err := a.d.Ops.Run(r.Context(), operations.RunRequest{
		Actor:            act,
		TraceID:          traceID(r),
		RequestID:        requestID(r),
		NodeID:           a.d.NodeID,
		Action:           actionAIProviderUpdate,
		Target:           operations.Target{Subject: "ai_providers/" + providerID},
		Args:             args,
		ExpectedRevision: req.ExpectedRevision,
		Idempotency:      idem,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// deleteAIProvider removes a provider through host.ai_providers.delete.
// expected_revision is a query parameter because DELETE carries no body.
func (a *api) deleteAIProvider(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.ai_providers:delete", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	providerID := r.PathValue("provider_id")
	// The obvious refusals are answered before an approval is queued: an
	// unknown provider is NOT_FOUND, and the default provider cannot go while
	// another one exists. The executor re-checks both inside its transaction.
	cur, err := a.d.AgentSessions.GetProvider(r.Context(), providerID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if cur.IsDefault {
		all, err := a.d.AgentSessions.ListProviders(r.Context())
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if len(all) > 1 {
			a.fail(w, r, problem.New(problem.StateConflict,
				"The default AI provider cannot be deleted while other providers exist; make another one the default first."))
			return
		}
	}
	expected, err := gateway.ExpectedRevisionQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := parseExpectedRevision(expected); err != nil {
		a.fail(w, r, err)
		return
	}
	args, err := json.Marshal(aiProviderDeleteArgs{ProviderID: providerID, ExpectedRevision: expected})
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	idem, err := a.idempotency(r, args)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	resp, err := a.d.Ops.Run(r.Context(), operations.RunRequest{
		Actor:            act,
		TraceID:          traceID(r),
		RequestID:        requestID(r),
		NodeID:           a.d.NodeID,
		Action:           actionAIProviderDelete,
		Target:           operations.Target{Subject: "ai_providers/" + providerID},
		Args:             args,
		ExpectedRevision: expected,
		Idempotency:      idem,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// aiProviderKeyRequest is the AiProviderKeyRequest schema.
type aiProviderKeyRequest struct {
	APIKey string `json:"api_key"`
}

// aiProviderTestResult is the AiProviderTestResult schema: ok/latency/category
// and nothing that could map the endpoint (AGT-03).
type aiProviderTestResult struct {
	OK        bool   `json:"ok"`
	LatencyMS *int64 `json:"latency_ms,omitempty"`
	Category  string `json:"category,omitempty"`
}

// setAIProviderAPIKey stores (or replaces) a provider's API key. The route is
// catalog-exempt: the plaintext must not reach an operation record or an
// idempotent replay, so it never goes through operations. The answer is 204;
// the key is never echoed.
func (a *api) setAIProviderAPIKey(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.ai_providers:update", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req aiProviderKeyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.d.AgentSessions.SetProviderAPIKey(r.Context(), act, r.PathValue("provider_id"), req.APIKey); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clearAIProviderAPIKey removes a provider's API key.
func (a *api) clearAIProviderAPIKey(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.ai_providers:update", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.d.AgentSessions.ClearProviderAPIKey(r.Context(), act, r.PathValue("provider_id")); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// testAIProvider probes a provider's connectivity. Like the key routes it is
// catalog-exempt: a probe changes nothing, and its answer is reduced to
// ok/latency/category so it cannot be used as a network probe (AGT-03).
func (a *api) testAIProvider(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.ai_providers:update", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	probe, err := a.d.AgentSessions.TestProvider(r.Context(), r.PathValue("provider_id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := aiProviderTestResult{OK: probe.OK}
	if probe.OK {
		out.LatencyMS = &probe.LatencyMS
	} else {
		out.Category = probe.Category
	}
	a.writeResource(w, r, http.StatusOK, out, nil)
}

type aiProviderFetchModelsRequest struct {
	ProviderID string `json:"provider_id,omitempty"`
	Kind       string `json:"kind,omitempty"`
	BaseURL    string `json:"base_url,omitempty"`
	APIKey     string `json:"api_key,omitempty"`
}

type aiProviderFetchModelsResult struct {
	OK        bool     `json:"ok"`
	Models    []string `json:"models"`
	LatencyMS *int64   `json:"latency_ms,omitempty"`
	Category  string   `json:"category,omitempty"`
}

// fetchAIProviderModels implements POST /api/v1/ai/providers/fetch-models
// (admin-only, catalog-exempt because it may carry an unsaved api_key for
// model discovery before creating a provider).
func (a *api) fetchAIProviderModels(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.ai_providers:update", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req aiProviderFetchModelsRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := a.d.AgentSessions.FetchProviderModels(r.Context(), agentsession.FetchModelsInput{
		ProviderID: req.ProviderID,
		Kind:       req.Kind,
		BaseURL:    req.BaseURL,
		APIKey:     req.APIKey,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	models := res.Models
	if models == nil {
		models = []string{}
	}
	out := aiProviderFetchModelsResult{OK: res.OK, Models: models}
	if res.OK {
		out.LatencyMS = &res.LatencyMS
	} else {
		out.Category = res.Category
	}
	a.writeResource(w, r, http.StatusOK, out, nil)
}

// executeAIProviderCreate runs host.ai_providers.create inside the operation
// transaction. The result is the full provider; operations of this action can
// only originate from an administrator's session.
func (a *api) executeAIProviderCreate(ctx context.Context, tx *storage.Tx, req operations.HostRequest) (json.RawMessage, error) {
	var args aiProviderCreateArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return nil, err
	}
	if err := a.checkProviderFields(args.Name, args.Kind, args.BaseURL, args.Model, args.Models, args.ReasoningEffort, args.MaxContextTokens); err != nil {
		return nil, err
	}
	p, err := a.d.AgentSessions.CreateProvider(ctx, tx, agentsession.CreateProviderInput{
		Actor: req.Actor, Name: args.Name, Kind: args.Kind,
		BaseURL: args.BaseURL, Model: args.Model, Models: args.Models,
		ReasoningEffort: args.ReasoningEffort, MaxContextTokens: args.MaxContextTokens,
		IsDefault: args.IsDefault,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(newAIProviderDTO(p, true))
}

// executeAIProviderUpdate runs host.ai_providers.update.
func (a *api) executeAIProviderUpdate(ctx context.Context, tx *storage.Tx, req operations.HostRequest) (json.RawMessage, error) {
	var args aiProviderUpdateArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return nil, err
	}
	if args.ProviderID == "" {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/provider_id", Code: "REQUIRED", Message: "provider_id is required.",
		})
	}
	patch := aiProviderUpdateRequest{
		ExpectedRevision: args.ExpectedRevision,
		Name:             args.Name, Kind: args.Kind, BaseURL: args.BaseURL, Model: args.Model,
		Models: args.Models, ReasoningEffort: args.ReasoningEffort, MaxContextTokens: args.MaxContextTokens,
		IsDefault: args.IsDefault,
	}
	if err := a.checkProviderPatch(patch); err != nil {
		return nil, err
	}
	revision, err := parseExpectedRevision(args.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	p, err := a.d.AgentSessions.UpdateProvider(ctx, tx, agentsession.UpdateProviderInput{
		Actor: req.Actor, ProviderID: args.ProviderID, ExpectedRevision: revision,
		Name: args.Name, Kind: args.Kind, BaseURL: args.BaseURL, Model: args.Model,
		Models: args.Models, ReasoningEffort: args.ReasoningEffort, MaxContextTokens: args.MaxContextTokens,
		IsDefault: args.IsDefault,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(newAIProviderDTO(p, true))
}

// executeAIProviderDelete runs host.ai_providers.delete.
func (a *api) executeAIProviderDelete(ctx context.Context, tx *storage.Tx, req operations.HostRequest) (json.RawMessage, error) {
	var args aiProviderDeleteArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return nil, err
	}
	if args.ProviderID == "" {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/provider_id", Code: "REQUIRED", Message: "provider_id is required.",
		})
	}
	revision, err := parseExpectedRevision(args.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	if err := a.d.AgentSessions.DeleteProvider(ctx, tx, agentsession.DeleteProviderInput{
		Actor: req.Actor, ProviderID: args.ProviderID, ExpectedRevision: revision,
	}); err != nil {
		return nil, err
	}
	return nil, nil
}

// planAIProviderCreate previews host.ai_providers.create.
func (a *api) planAIProviderCreate(_ context.Context, _ *sql.Tx, req operations.HostRequest) (operations.Preview, error) {
	var args aiProviderCreateArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return operations.Preview{}, err
	}
	if err := a.checkProviderFields(args.Name, args.Kind, args.BaseURL, args.Model, args.Models, args.ReasoningEffort, args.MaxContextTokens); err != nil {
		return operations.Preview{}, err
	}
	after, err := json.Marshal(map[string]any{
		"name": args.Name, "kind": args.Kind, "base_url": args.BaseURL,
		"model": args.Model, "is_default": args.IsDefault,
	})
	if err != nil {
		return operations.Preview{}, problem.Wrap(err)
	}
	return operations.Preview{
		Changes: []operations.PlannedChange{{
			Kind: "create", Subject: "ai_providers", After: after, Reversible: true,
		}},
	}, nil
}

// planAIProviderUpdate previews host.ai_providers.update.
func (a *api) planAIProviderUpdate(_ context.Context, _ *sql.Tx, req operations.HostRequest) (operations.Preview, error) {
	var args aiProviderUpdateArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return operations.Preview{}, err
	}
	if args.ProviderID == "" {
		return operations.Preview{}, problem.Validation(problem.Violation{
			Pointer: "/provider_id", Code: "REQUIRED", Message: "provider_id is required.",
		})
	}
	if _, err := parseExpectedRevision(args.ExpectedRevision); err != nil {
		return operations.Preview{}, err
	}
	after := map[string]any{}
	if args.Name != nil {
		after["name"] = *args.Name
	}
	if args.BaseURL != nil {
		after["base_url"] = *args.BaseURL
	}
	if args.Model != nil {
		after["model"] = *args.Model
	}
	if args.IsDefault != nil {
		after["is_default"] = *args.IsDefault
	}
	raw, err := json.Marshal(after)
	if err != nil {
		return operations.Preview{}, problem.Wrap(err)
	}
	return operations.Preview{
		Changes: []operations.PlannedChange{{
			Kind: "update", Subject: "ai_providers/" + args.ProviderID, After: raw, Reversible: true,
		}},
	}, nil
}

// planAIProviderDelete previews host.ai_providers.delete.
func (a *api) planAIProviderDelete(_ context.Context, _ *sql.Tx, req operations.HostRequest) (operations.Preview, error) {
	var args aiProviderDeleteArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return operations.Preview{}, err
	}
	if args.ProviderID == "" {
		return operations.Preview{}, problem.Validation(problem.Violation{
			Pointer: "/provider_id", Code: "REQUIRED", Message: "provider_id is required.",
		})
	}
	if _, err := parseExpectedRevision(args.ExpectedRevision); err != nil {
		return operations.Preview{}, err
	}
	return operations.Preview{
		Changes: []operations.PlannedChange{{
			Kind: "delete", Subject: "ai_providers/" + args.ProviderID, Reversible: false,
		}},
	}, nil
}
