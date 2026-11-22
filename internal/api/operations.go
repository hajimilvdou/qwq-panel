// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// listOperations returns a page of operations, newest first. The operation
// manager already restricts service accounts to their own operations; results
// are redacted per item (resultRedactor).
func (a *api) listOperations(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.operations:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	q, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	values := r.URL.Query()
	statuses, err := parseOperationStatuses(values.Get("status"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	kind, err := parseActorKind(values.Get("actor_kind"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	page, err := a.d.Ops.List(r.Context(), act, operations.ListFilter{
		Statuses:      statuses,
		ActorKind:     kind,
		NodeID:        values.Get("node_id"),
		PluginID:      values.Get("plugin_id"),
		SinceRevision: q.SinceRevision,
		Cursor:        q.Cursor,
		Limit:         q.Limit,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := make([]any, 0, len(page.Items))
	redact := a.resultRedactor(r.Context(), act)
	for i := range page.Items {
		redact(&page.Items[i])
		items = append(items, page.Items[i])
	}
	a.writeList(w, r, listResponse{
		Items:      items,
		NextCursor: page.NextCursor,
		Revision:   page.Revision,
		Delta:      page.Delta,
		DeletedIDs: page.DeletedIDs,
	}, q.Fields)
}

// getOperation returns one operation the caller may read; its result is
// redacted like the list's (resultRedactor).
func (a *api) getOperation(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.operations:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	op, err := a.d.Ops.Get(r.Context(), act, r.PathValue("operation_id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.resultRedactor(r.Context(), act)(op)
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, op, fields)
}

// resultRedactor returns the function that clears the result of an operation
// the caller may read but not see the result of. Every person reads every
// operation (follow mode, ADR-0004 D9), yet a result can be as sensitive as the
// action that produced it: it goes only to the actor that started the operation
// and to callers that hold the action's permission. Decisions are cached per
// permission and node for the request, so a page costs one authorization per
// distinct action; an authorization error hides the result (fail closed).
func (a *api) resultRedactor(ctx context.Context, act actor.Actor) func(*operations.Operation) {
	return a.d.Ops.ResultRedactor(ctx, act)
}

// cancelRequest is the CancelRequest schema; the body is optional.
type cancelRequest struct {
	Reason string `json:"reason"`
}

// cancelOperation cancels an operation. The 200/202 split is the operation
// manager's: a running operation only records the request.
func (a *api) cancelOperation(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.operations:cancel", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req cancelRequest
	if err := a.decodeOptionalJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	idem, err := a.idempotency(r, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	resp, err := a.d.Ops.Cancel(r.Context(), operations.CancelRequest{
		Actor:       act,
		OperationID: r.PathValue("operation_id"),
		Reason:      req.Reason,
		Idempotency: idem,
		TraceID:     traceID(r),
		RequestID:   requestID(r),
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// parseOperationStatuses parses the comma-separated `status` filter.
func parseOperationStatuses(raw string) ([]operations.Status, error) {
	if raw == "" {
		return nil, nil
	}
	seen := make(map[operations.Status]bool)
	var out []operations.Status
	for _, part := range strings.Split(raw, ",") {
		s := operations.Status(strings.TrimSpace(part))
		if s == "" {
			continue
		}
		if !s.Valid() {
			return nil, problem.Validation(problem.Violation{
				In: "query", Pointer: "/status", Code: "INVALID",
				Message: "Each status must be a known OperationStatus.",
			})
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) > 9 {
		return nil, problem.Validation(problem.Violation{
			In: "query", Pointer: "/status", Code: "TOO_MANY",
			Message: "At most 9 statuses can be listed.",
		})
	}
	return out, nil
}

// parseActorKind parses the `actor_kind` filter.
func parseActorKind(raw string) (actor.Kind, error) {
	if raw == "" {
		return "", nil
	}
	k := actor.Kind(raw)
	switch k {
	case actor.Human, actor.AIAgent, actor.Service, actor.System:
		return k, nil
	}
	return "", problem.Validation(problem.Violation{
		In: "query", Pointer: "/actor_kind", Code: "INVALID",
		Message: "actor_kind must be human, ai_agent, service or system.",
	})
}
