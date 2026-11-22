// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"net/http"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/operations"
)

// maxCancelReasonRunes is CancelRequest.reason.maxLength.
const maxCancelReasonRunes = 500

// cancelRequest is the AgentCancelRequest schema.
type cancelRequest struct {
	OperationID string `json:"operation_id"`
	Reason      string `json:"reason,omitempty"`
}

// check validates the request against the schema.
func (req *cancelRequest) check() error {
	if err := checkResourceID("/operation_id", req.OperationID); err != nil {
		return err
	}
	if utf8.RuneCountInString(req.Reason) > maxCancelReasonRunes {
		return wrongFormat("/reason", "The reason is longer than 500 characters.")
	}
	return nil
}

// cancel implements POST /api/v1/agent/cancel: the same semantics as
// POST /api/v1/operations/{operation_id}/cancel, always 200 with the outcome. A
// delegation can cancel only operations it created; anything else answers 404,
// like an unknown ID.
func (h *handlers) cancel(w http.ResponseWriter, r *http.Request) {
	c, err := h.begin(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var req cancelRequest
	if err := h.decode(r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := req.check(); err != nil {
		h.fail(w, r, err)
		return
	}
	key, err := h.toolKey(r, "cancel")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	resp, err := h.ops.Cancel(r.Context(), operations.CancelRequest{
		Actor:       c.actor,
		OperationID: req.OperationID,
		Reason:      req.Reason,
		Idempotency: operations.Idempotency{
			Key:    key,
			Method: http.MethodPost,
			Route:  "/api/v1/agent/cancel",
		},
		TraceID:   c.traceID,
		RequestID: c.request,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out, err := outcomeOf(resp)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body, err := outcomeBody(out)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.write(w, r, body)
}
