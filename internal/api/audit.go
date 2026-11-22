// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
)

// The audit log query (GAPS gap 7). Reading it is an administrator's job: it
// names every person and every change on the installation. The route therefore
// takes a human browser session only (the gateway refuses service and delegation
// tokens) and additionally requires the administrator role, so an operator's
// read-class grant is not enough.

// auditPageResponse is the AuditPage schema. The pagination members live under
// `meta`: audit rows carry no revision, so this is not a revisioned collection
// and `since_revision` does not apply.
type auditPageResponse struct {
	Items []operations.AuditEntry `json:"items"`
	Meta  auditMeta               `json:"meta"`
}

// auditMeta is the pagination half of AuditPage.
type auditMeta struct {
	NextCursor string `json:"next_cursor,omitempty"`
}

// listAudit implements GET /api/v1/audit.
func (a *api) listAudit(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.audit:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	f, err := a.auditFilter(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	page, err := a.d.Ops.ListAudit(r.Context(), f)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, auditPageResponse{
		Items: page.Items,
		Meta:  auditMeta{NextCursor: page.NextCursor},
	}, nil)
}

// auditFilter parses the query parameters of the audit list.
func (a *api) auditFilter(r *http.Request) (operations.AuditFilter, error) {
	q := r.URL.Query()
	var f operations.AuditFilter
	for _, field := range []struct {
		name string
		max  int
		dst  *string
	}{
		{"actor", 64, &f.ActorID},
		{"action", 128, &f.Action},
		{"subject", 512, &f.Subject},
		{"operation_id", 64, &f.OperationID},
	} {
		v := q.Get(field.name)
		if len(v) > field.max {
			return f, queryViolation("/"+field.name, "INVALID", "The filter value is too long.")
		}
		*field.dst = v
	}
	f.Outcome = q.Get("outcome")
	switch f.Outcome {
	case "", operations.AuditSuccess, operations.AuditFailure, operations.AuditDenied:
	default:
		return f, queryViolation("/outcome", "INVALID", "The outcome must be success, failure or denied.")
	}
	for _, bound := range []struct {
		name string
		dst  *time.Time
	}{
		{"from", &f.From},
		{"to", &f.To},
	} {
		v := q.Get(bound.name)
		if v == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, queryViolation("/"+bound.name, "INVALID", "The bound must be an RFC 3339 timestamp.")
		}
		*bound.dst = at
	}
	list, err := a.g.ListQuery(r)
	if err != nil {
		return f, err
	}
	f.Cursor, f.Limit = list.Cursor, list.Limit
	return f, nil
}
