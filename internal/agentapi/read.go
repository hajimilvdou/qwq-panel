// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// readRequest is the ReadRequest schema.
type readRequest struct {
	Subject       string   `json:"subject"`
	Fields        []string `json:"fields,omitempty"`
	SinceRevision string   `json:"since_revision,omitempty"`
	Cursor        string   `json:"cursor,omitempty"`
	Limit         int      `json:"limit,omitempty"`
}

// readTruncated is ReadResponse.truncated: which cap was hit and how to
// continue.
type readTruncated struct {
	Reason   string `json:"reason"`
	Returned int    `json:"returned,omitempty"`
	Hint     string `json:"hint,omitempty"`
}

// readResponse is the ReadResponse schema. Exactly one of Values (a single
// resource, a flat map from JSON Pointer to value) and Items (a collection) is
// present, unless Unchanged is set. Both are pointers so an empty collection
// is written as `[]` instead of disappearing.
type readResponse struct {
	Subject    string            `json:"subject"`
	Revision   string            `json:"revision"`
	Unchanged  bool              `json:"unchanged,omitempty"`
	Values     *map[string]any   `json:"values,omitempty"`
	Missing    []string          `json:"missing,omitempty"`
	Items      *[]map[string]any `json:"items,omitempty"`
	Delta      bool              `json:"delta,omitempty"`
	DeletedIDs []string          `json:"deleted_ids,omitempty"`
	NextCursor string            `json:"next_cursor,omitempty"`
	Truncated  *readTruncated    `json:"truncated,omitempty"`
}

// check validates the request against the schema. The subject is parsed again
// by the handler; this only reports field problems.
func (req *readRequest) check() error {
	if _, _, err := checkSubject(req.Subject); err != nil {
		return err
	}
	if req.SinceRevision != "" {
		if err := checkRevisionField("/since_revision", req.SinceRevision); err != nil {
			return err
		}
	}
	if len(req.Cursor) > 512 {
		return wrongFormat("/cursor", "A cursor is at most 512 characters.")
	}
	if req.Limit != 0 && (req.Limit < 1 || req.Limit > ReadItemsMax) {
		return outOfRange("/limit", "The limit must be between 1 and 100.")
	}
	return nil
}

// read implements POST /api/v1/agent/read: it reads host-owned subjects on
// behalf of the delegation, with field projection, cursor pagination and a
// bounded response size.
func (h *handlers) read(w http.ResponseWriter, r *http.Request) {
	c, err := h.begin(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var req readRequest
	if err := h.decode(r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := req.check(); err != nil {
		h.fail(w, r, err)
		return
	}
	head, id, _ := checkSubject(req.Subject)
	fields, err := checkFields(req.Fields)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	resp, err := h.readSubject(r.Context(), c, &req, head, id, fields)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.write(w, r, resp)
}

// readSubject dispatches on the subject head. Host-owned subjects of P1 are
// users, operations, approvals, plans and delegations; nodes and plugins have
// no host-side store yet, and plugin-owned subjects need the plugin read
// contract (openapi.yaml ReadRequest description), so both answer NOT_FOUND.
func (h *handlers) readSubject(ctx context.Context, c *call, req *readRequest,
	head, id string, fields []string) (*readResponse, error) {
	resp := &readResponse{Subject: req.Subject}
	switch head {
	case "users":
		if !c.view.allowsRead("host.users") {
			return nil, notFoundSubject()
		}
		if id == "" {
			return h.readUsers(ctx, req, resp, fields)
		}
		return h.readUser(ctx, req, resp, id, fields)
	case "operations":
		if !c.view.allowsRead("host.operations") {
			return nil, notFoundSubject()
		}
		if id == "" {
			return h.readOperations(ctx, c, req, resp, fields)
		}
		return h.readOperation(ctx, c, req, resp, id, fields)
	case "approvals":
		if !c.view.allowsRead("host.approvals") {
			return nil, notFoundSubject()
		}
		if id == "" {
			return h.readApprovals(ctx, c, req, resp, fields)
		}
		return h.readApproval(ctx, c, req, resp, id, fields)
	case "plans":
		if !c.view.allowsRead("host.plans") {
			return nil, notFoundSubject()
		}
		if id == "" {
			// operations exposes plans by ID only (a plan is short-lived and
			// created for one execution).
			return nil, notFoundSubject()
		}
		return h.readPlan(ctx, c, req, resp, id, fields)
	case "delegations":
		if id == "" {
			return nil, notFoundSubject()
		}
		return h.readDelegation(ctx, c, req, resp, id)
	default:
		return nil, notFoundSubject()
	}
}

// ---- users ----------------------------------------------------------------

// readUser reads one panel user. The public User schema is built by hand
// because identity.User is a storage shape without JSON tags.
func (h *handlers) readUser(ctx context.Context, req *readRequest, resp *readResponse,
	id string, fields []string) (*readResponse, error) {
	u, err := h.identity.User(ctx, id)
	if err != nil {
		return nil, notFoundOr(err)
	}
	rev := strconv.FormatInt(u.Revision, 10)
	resp.Revision = rev
	if req.SinceRevision != "" && req.SinceRevision == rev {
		resp.Unchanged = true
		return resp, nil
	}
	values, missing := buildValues(userDoc(u), fields)
	resp.Values, resp.Missing = &values, missing
	h.fitValues(resp)
	return resp, nil
}

// readUsers reads a page of users. identity lists users by ID; the cursor is
// the opaque base64url form of the last returned user ID.
func (h *handlers) readUsers(ctx context.Context, req *readRequest, resp *readResponse,
	fields []string) (*readResponse, error) {
	limit := effectiveLimit(req.Limit)
	after := ""
	if req.Cursor != "" {
		decoded, err := decodeCursor(req.Cursor)
		if err != nil {
			return nil, wrongFormat("/cursor", "The cursor is not one this host issued.")
		}
		after = decoded
	}
	// One extra row tells whether another page exists without a second query.
	users, err := h.identity.ListUsers(ctx, identity.ListUsersInput{After: after, Limit: limit + 1})
	if err != nil {
		return nil, problem.From(err)
	}
	next := ""
	if len(users) > limit {
		users = users[:limit]
		next = encodeCursor(users[len(users)-1].ID)
	}
	items := make([]map[string]any, 0, len(users))
	for _, u := range users {
		items = append(items, projectItem(userDoc(u), fields))
	}
	resp.Items = &items
	resp.NextCursor = next
	// A user has no event history the host keeps for deltas, so this is a full
	// snapshot and `delta` is false even when since_revision was given.
	resp.Delta = false
	resp.Revision = storage.Revision(h.db.HeadSeq())
	h.capItems(resp, ReadItemsMax)
	h.fitItems(resp)
	return resp, nil
}

// userDoc renders the public User schema.
func userDoc(u identity.User) map[string]any {
	doc := map[string]any{
		"user_id":      u.ID,
		"username":     u.Username,
		"display_name": u.DisplayName,
		"role":         string(u.Role),
		"mfa_enabled":  u.MFAEnabled,
		"disabled":     u.Disabled,
		"created_at":   timestamp(u.CreatedAt),
		"updated_at":   timestamp(u.UpdatedAt),
		"revision":     strconv.FormatInt(u.Revision, 10),
	}
	return doc
}

// ---- operations -----------------------------------------------------------

func (h *handlers) readOperation(ctx context.Context, c *call, req *readRequest,
	resp *readResponse, id string, fields []string) (*readResponse, error) {
	op, err := h.ops.Get(ctx, c.actor, id)
	if err != nil {
		return nil, notFoundOr(err)
	}
	resp.Revision = op.Revision
	if req.SinceRevision != "" && req.SinceRevision == op.Revision {
		resp.Unchanged = true
		return resp, nil
	}
	doc, err := jsonObject(op)
	if err != nil {
		return nil, err
	}
	values, missing := buildValues(doc, fields)
	resp.Values, resp.Missing = &values, missing
	h.fitValues(resp)
	return resp, nil
}

func (h *handlers) readOperations(ctx context.Context, c *call, req *readRequest,
	resp *readResponse, fields []string) (*readResponse, error) {
	page, err := h.ops.List(ctx, c.actor, operations.ListFilter{
		Limit:         effectiveLimit(req.Limit),
		Cursor:        req.Cursor,
		SinceRevision: req.SinceRevision,
	})
	if err != nil {
		return nil, problem.From(err)
	}
	items := make([]map[string]any, 0, len(page.Items))
	for i := range page.Items {
		doc, err := jsonObject(&page.Items[i])
		if err != nil {
			return nil, err
		}
		items = append(items, projectItem(doc, fields))
	}
	resp.Items = &items
	resp.Revision = page.Revision
	resp.Delta = page.Delta
	resp.DeletedIDs = page.DeletedIDs
	resp.NextCursor = page.NextCursor
	h.capItems(resp, ReadItemsMax)
	h.fitItems(resp)
	return resp, nil
}

// ---- approvals ------------------------------------------------------------

func (h *handlers) readApproval(ctx context.Context, c *call, req *readRequest,
	resp *readResponse, id string, fields []string) (*readResponse, error) {
	approval, err := h.ops.GetApproval(ctx, c.actor, id)
	if err != nil {
		return nil, notFoundOr(err)
	}
	resp.Revision = approval.Revision
	if req.SinceRevision != "" && req.SinceRevision == approval.Revision {
		resp.Unchanged = true
		return resp, nil
	}
	doc, err := jsonObject(approval)
	if err != nil {
		return nil, err
	}
	values, missing := buildValues(doc, fields)
	resp.Values, resp.Missing = &values, missing
	h.fitValues(resp)
	return resp, nil
}

func (h *handlers) readApprovals(ctx context.Context, c *call, req *readRequest,
	resp *readResponse, fields []string) (*readResponse, error) {
	// The approvals collection uses the default of the REST list, which is
	// PENDING: a decision that is still waiting for a human.
	page, err := h.ops.ListApprovals(ctx, c.actor, operations.ApprovalFilter{
		Limit:         effectiveLimit(req.Limit),
		Cursor:        req.Cursor,
		SinceRevision: req.SinceRevision,
	})
	if err != nil {
		return nil, problem.From(err)
	}
	items := make([]map[string]any, 0, len(page.Items))
	for i := range page.Items {
		doc, err := jsonObject(&page.Items[i])
		if err != nil {
			return nil, err
		}
		items = append(items, projectItem(doc, fields))
	}
	resp.Items = &items
	resp.Revision = page.Revision
	resp.Delta = page.Delta
	resp.DeletedIDs = page.DeletedIDs
	resp.NextCursor = page.NextCursor
	h.capItems(resp, ReadItemsMax)
	h.fitItems(resp)
	return resp, nil
}

// ---- plans and delegations ------------------------------------------------

func (h *handlers) readPlan(ctx context.Context, c *call, req *readRequest,
	resp *readResponse, id string, fields []string) (*readResponse, error) {
	plan, err := h.ops.GetPlan(ctx, c.actor, id)
	if err != nil {
		return nil, notFoundOr(err)
	}
	resp.Revision = plan.Revision
	if req.SinceRevision != "" && req.SinceRevision == plan.Revision {
		resp.Unchanged = true
		return resp, nil
	}
	doc, err := planBody(plan)
	if err != nil {
		return nil, err
	}
	values, missing := buildValues(doc, fields)
	resp.Values, resp.Missing = &values, missing
	h.fitValues(resp)
	return resp, nil
}

// readDelegation reads a delegation record. A token may always read its own
// record; reading another one requires an administrator owner, because the
// record names its owner and token prefix and the read tool must not become a
// directory of other users' AI credentials.
func (h *handlers) readDelegation(ctx context.Context, c *call, req *readRequest,
	resp *readResponse, id string) (*readResponse, error) {
	if id != c.actor.ID && c.view.role != authz.RoleAdmin {
		return nil, notFoundSubject()
	}
	d, err := h.authz.Delegation(ctx, id)
	if err != nil {
		return nil, notFoundOr(err)
	}
	resp.Revision = strconv.FormatInt(d.Revision, 10)
	if req.SinceRevision != "" && req.SinceRevision == resp.Revision {
		resp.Unchanged = true
		return resp, nil
	}
	doc, err := delegationDoc(d, h.clock.Now().UTC())
	if err != nil {
		return nil, err
	}
	values, missing := buildValues(doc, nil)
	resp.Values, resp.Missing = &values, missing
	h.fitValues(resp)
	return resp, nil
}

// delegationDoc renders the public Delegation schema.
func delegationDoc(d authz.Delegation, now time.Time) (map[string]any, error) {
	policy, err := jsonObject(d.Policy)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{
		"delegation_id": d.ID,
		"label":         d.Label,
		"owner_id":      d.OwnerID,
		"policy":        policy,
		"status":        string(d.StatusAt(now)),
		"token_prefix":  d.TokenPrefix,
		"created_at":    timestamp(d.CreatedAt),
		"expires_at":    timestamp(d.ExpiresAt),
		"revision":      strconv.FormatInt(d.Revision, 10),
	}
	if !d.LastUsedAt.IsZero() {
		doc["last_used_at"] = timestamp(d.LastUsedAt)
	}
	return doc, nil
}

// ---- small helpers --------------------------------------------------------

// buildValues projects a single resource into the flat pointer map of
// ReadResponse.values, and lists the requested pointers that do not exist.
func buildValues(doc map[string]any, fields []string) (map[string]any, []string) {
	values := make(map[string]any, len(fields)+1)
	var missing []string
	if len(fields) == 0 {
		values[""] = doc
		return values, nil
	}
	for _, pointer := range fields {
		if pointer == "" {
			values[""] = doc
			continue
		}
		value, ok := lookupPointer(doc, pointer)
		if !ok {
			missing = append(missing, pointer)
			continue
		}
		values[pointer] = value
	}
	return values, missing
}

// effectiveLimit applies agent_read_items_default.
func effectiveLimit(n int) int {
	if n <= 0 {
		return ReadItemsDefault
	}
	return n
}

// timestamp renders a time the way the host's other JSON surfaces do: RFC 3339
// in UTC with milliseconds.
func timestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// encodeCursor makes a user ID an opaque cursor.
func encodeCursor(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// decodeCursor reverses encodeCursor.
func decodeCursor(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("agentapi: empty cursor")
	}
	return string(b), nil
}

// notFoundSubject is the single answer for an unknown, unreadable or
// plugin-owned subject: the caller cannot tell the cases apart.
func notFoundSubject() error {
	return problem.New(problem.NotFound, "No readable resource matches this subject.")
}

// notFoundOr keeps NOT_FOUND answers identical (no existence leak) and passes
// every other problem through.
func notFoundOr(err error) error {
	if problem.HasCode(err, problem.NotFound) {
		return notFoundSubject()
	}
	return problem.From(err)
}
