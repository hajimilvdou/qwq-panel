// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Action IDs of the user host actions (x-qwq-action of the OpenAPI document).
const (
	actionUserCreate = "host.users.create"
	actionUserUpdate = "host.users.update"
	actionUserDelete = "host.users.delete"
)

// userCreateRequest is the UserCreateRequest schema.
type userCreateRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

// userUpdateRequest is the UserUpdateRequest schema.
type userUpdateRequest struct {
	ExpectedRevision string  `json:"expected_revision"`
	DisplayName      *string `json:"display_name,omitempty"`
	Role             *string `json:"role,omitempty"`
	Disabled         *bool   `json:"disabled,omitempty"`
}

// The arguments of the host actions: the route's path parameters and body
// members flattened into one object (OpenAPI PlanRequest).
type userCreateArgs struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
}

type userUpdateArgs struct {
	UserID           string  `json:"user_id"`
	ExpectedRevision string  `json:"expected_revision"`
	DisplayName      *string `json:"display_name,omitempty"`
	Role             *string `json:"role,omitempty"`
	Disabled         *bool   `json:"disabled,omitempty"`
}

type userDeleteArgs struct {
	UserID           string `json:"user_id"`
	ExpectedRevision string `json:"expected_revision"`
}

// listUsers returns a page of users. `since_revision` is accepted but the list
// is always a full snapshot with delta=false: identity has no incremental query
// and a delta built here would have to read SQL, which this package must not do.
func (a *api) listUsers(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.users:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	q, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	users, err := a.d.Identity.ListUsers(r.Context(), identity.ListUsersInput{
		After: q.Cursor,
		Limit: pageLimit(q.Limit),
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	users, next := nextCursor(users, q.Limit, func(u identity.User) string { return u.ID })
	items := make([]any, 0, len(users))
	for _, u := range users {
		items = append(items, newUserDTO(u))
	}
	a.writeList(w, r, listResponse{Items: items, NextCursor: next, Revision: a.watermark()}, q.Fields)
}

// getUser returns one user.
func (a *api) getUser(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.users:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	u, err := a.d.Identity.User(r.Context(), r.PathValue("user_id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, newUserDTO(u), fields)
}

// createUser creates an operation for host.users.create. The action is risk
// high, so a normal administrator gets 202 and an approval to decide.
func (a *api) createUser(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.users:create", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req userCreateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := requireFields(map[string]string{"/username": req.Username, "/role": req.Role}); err != nil {
		a.fail(w, r, err)
		return
	}
	// Validate what the catalog's args schema declares before an operation is
	// queued: a typo must be a 400 now, not a failed operation after approval.
	if _, err := identity.NormalizeUsername(req.Username); err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := identity.ParseRole(req.Role); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := validateDisplayName(req.DisplayName); err != nil {
		a.fail(w, r, err)
		return
	}
	args, err := json.Marshal(userCreateArgs(req))
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
		Action:      actionUserCreate,
		Args:        args,
		Idempotency: idem,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeOperationResponse(w, resp)
}

// updateUser patches a user through host.users.update.
func (a *api) updateUser(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.users:update", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	userID := r.PathValue("user_id")
	var req userUpdateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := parseExpectedRevision(req.ExpectedRevision); err != nil {
		a.fail(w, r, err)
		return
	}
	if req.DisplayName == nil && req.Role == nil && req.Disabled == nil {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/", Code: "empty",
			Message: "At least one of display_name, role or disabled is required.",
		}))
		return
	}
	if req.Role != nil {
		if _, err := identity.ParseRole(*req.Role); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	if req.DisplayName != nil {
		if err := validateDisplayName(*req.DisplayName); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	args, err := json.Marshal(userUpdateArgs{
		UserID: userID, ExpectedRevision: req.ExpectedRevision,
		DisplayName: req.DisplayName, Role: req.Role, Disabled: req.Disabled,
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
		Action:           actionUserUpdate,
		Target:           operations.Target{Subject: "users/" + userID},
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

// deleteUser removes a user through host.users.delete. expected_revision is a
// query parameter because DELETE carries no body (ADR-0006 D5).
func (a *api) deleteUser(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.users:delete", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	userID := r.PathValue("user_id")
	expected, err := gateway.ExpectedRevisionQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := parseExpectedRevision(expected); err != nil {
		a.fail(w, r, err)
		return
	}
	args, err := json.Marshal(userDeleteArgs{UserID: userID, ExpectedRevision: expected})
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
		Action:           actionUserDelete,
		Target:           operations.Target{Subject: "users/" + userID},
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

// registerHostActions installs the executors and previews of the user,
// account and AI provider host actions on the operation manager.
func (a *api) registerHostActions() {
	a.d.Ops.RegisterHostAction(actionUserCreate, a.executeUserCreate, a.planUserCreate)
	a.d.Ops.RegisterHostAction(actionUserUpdate, a.executeUserUpdate, a.planUserUpdate)
	a.d.Ops.RegisterHostAction(actionUserDelete, a.executeUserDelete, a.planUserDelete)
	a.d.Ops.RegisterHostAction(actionAccountUpdate, a.executeAccountUpdate, a.planAccountUpdate)
	a.d.Ops.RegisterHostAction(actionAIProviderCreate, a.executeAIProviderCreate, a.planAIProviderCreate)
	a.d.Ops.RegisterHostAction(actionAIProviderUpdate, a.executeAIProviderUpdate, a.planAIProviderUpdate)
	a.d.Ops.RegisterHostAction(actionAIProviderDelete, a.executeAIProviderDelete, a.planAIProviderDelete)
	a.d.Ops.RegisterHostJob(actionPluginUninstall, a.executePluginUninstall)
	a.d.Ops.RegisterHostJob(actionPluginEnable, a.executePluginEnable)
	a.d.Ops.RegisterHostJob(actionPluginDisable, a.executePluginDisable)
}

// executeUserCreate runs host.users.create inside the operation transaction.
// The caller never chooses the initial password: the new user enrolls with a
// one-time link, and the result only reports that one is pending. The link is
// issued by POST /api/v1/users/{user_id}/enrollment-token, never here, because
// an operation result is stored for good and every reader of the operation
// sees it (AUTH-06).
func (a *api) executeUserCreate(ctx context.Context, tx *storage.Tx, req operations.HostRequest) (json.RawMessage, error) {
	var args userCreateArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return nil, err
	}
	res, err := a.d.Identity.CreateUser(ctx, tx, identity.CreateUserInput{
		Username:    args.Username,
		DisplayName: args.DisplayName,
		Role:        identity.Role(args.Role),
		Actor:       req.Actor,
	})
	if err != nil {
		return nil, err
	}
	out := struct {
		User                userDTO `json:"user"`
		EnrollmentPending   bool    `json:"enrollment_pending"`
		EnrollmentExpiresAt string  `json:"enrollment_expires_at,omitempty"`
	}{
		User:                newUserDTO(res.User),
		EnrollmentPending:   !res.EnrollmentUntil.IsZero(),
		EnrollmentExpiresAt: ts(res.EnrollmentUntil),
	}
	return json.Marshal(out)
}

// executeUserUpdate runs host.users.update inside the operation transaction.
func (a *api) executeUserUpdate(ctx context.Context, tx *storage.Tx, req operations.HostRequest) (json.RawMessage, error) {
	var args userUpdateArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return nil, err
	}
	revision, err := parseExpectedRevision(args.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	var role *identity.Role
	if args.Role != nil {
		r := identity.Role(*args.Role)
		role = &r
	}
	u, err := a.d.Identity.UpdateUser(ctx, tx, identity.UpdateUserInput{
		UserID:           args.UserID,
		ExpectedRevision: revision,
		DisplayName:      args.DisplayName,
		Role:             role,
		Disabled:         args.Disabled,
		Actor:            req.Actor,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(newUserDTO(u))
}

// executeUserDelete runs host.users.delete inside the operation transaction.
func (a *api) executeUserDelete(ctx context.Context, tx *storage.Tx, req operations.HostRequest) (json.RawMessage, error) {
	var args userDeleteArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return nil, err
	}
	revision, err := parseExpectedRevision(args.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	if err := a.d.Identity.DeleteUser(ctx, tx, identity.DeleteUserInput{
		UserID:           args.UserID,
		ExpectedRevision: revision,
		Actor:            req.Actor,
	}); err != nil {
		return nil, err
	}
	return nil, nil
}

// planUserCreate previews host.users.create. The change targets the users
// collection: the new ID is assigned inside the operation.
func (a *api) planUserCreate(_ context.Context, _ *sql.Tx, req operations.HostRequest) (operations.Preview, error) {
	var args userCreateArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return operations.Preview{}, err
	}
	if _, err := identity.NormalizeUsername(args.Username); err != nil {
		return operations.Preview{}, err
	}
	if _, err := identity.ParseRole(args.Role); err != nil {
		return operations.Preview{}, err
	}
	after, err := json.Marshal(map[string]string{"username": args.Username, "role": args.Role, "display_name": args.DisplayName})
	if err != nil {
		return operations.Preview{}, problem.Wrap(err)
	}
	return operations.Preview{
		Changes: []operations.PlannedChange{{
			Kind: "create", Subject: "users", After: after, Reversible: true,
		}},
	}, nil
}

// planUserUpdate previews host.users.update.
func (a *api) planUserUpdate(_ context.Context, _ *sql.Tx, req operations.HostRequest) (operations.Preview, error) {
	var args userUpdateArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return operations.Preview{}, err
	}
	if args.UserID == "" {
		return operations.Preview{}, problem.Validation(problem.Violation{
			Pointer: "/user_id", Code: "REQUIRED", Message: "user_id is required.",
		})
	}
	if _, err := parseExpectedRevision(args.ExpectedRevision); err != nil {
		return operations.Preview{}, err
	}
	if args.DisplayName == nil && args.Role == nil && args.Disabled == nil {
		return operations.Preview{}, problem.Validation(problem.Violation{
			Pointer: "/", Code: "empty", Message: "At least one member is required.",
		})
	}
	if args.Role != nil {
		if _, err := identity.ParseRole(*args.Role); err != nil {
			return operations.Preview{}, err
		}
	}
	after := map[string]any{}
	if args.DisplayName != nil {
		after["display_name"] = *args.DisplayName
	}
	if args.Role != nil {
		after["role"] = *args.Role
	}
	if args.Disabled != nil {
		after["disabled"] = *args.Disabled
	}
	raw, err := json.Marshal(after)
	if err != nil {
		return operations.Preview{}, problem.Wrap(err)
	}
	return operations.Preview{
		Changes: []operations.PlannedChange{{
			Kind: "update", Subject: "users/" + args.UserID, After: raw, Reversible: true,
		}},
	}, nil
}

// planUserDelete previews host.users.delete.
func (a *api) planUserDelete(_ context.Context, _ *sql.Tx, req operations.HostRequest) (operations.Preview, error) {
	var args userDeleteArgs
	if err := decodeArgs(req.Args, &args); err != nil {
		return operations.Preview{}, err
	}
	if args.UserID == "" {
		return operations.Preview{}, problem.Validation(problem.Violation{
			Pointer: "/user_id", Code: "REQUIRED", Message: "user_id is required.",
		})
	}
	if _, err := parseExpectedRevision(args.ExpectedRevision); err != nil {
		return operations.Preview{}, err
	}
	return operations.Preview{
		Changes: []operations.PlannedChange{{
			Kind: "delete", Subject: "users/" + args.UserID, Reversible: false,
		}},
	}, nil
}

// decodeArgs decodes the arguments of a host action strictly. The arguments come
// from the operation record, which the HTTP handler wrote, but a plan is
// replayed through the same path, so they are validated again.
func decodeArgs(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return problem.Validation(problem.Violation{
			Pointer: "/args", Code: "REQUIRED", Message: "The action needs arguments.",
		})
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return problem.Validation(problem.Violation{
			Pointer: "/args", Code: "INVALID", Message: "The action arguments do not match the action.",
		})
	}
	return nil
}

// parseExpectedRevision converts the opaque revision of a request into the row
// revision the identity domain compares. Revisions are decimal journal
// sequences; a client never parses them, but the host does.
func parseExpectedRevision(raw string) (int64, error) {
	if raw == "" {
		return 0, problem.Validation(problem.Violation{
			Pointer: "/expected_revision", Code: "REQUIRED", Message: "expected_revision is required.",
		})
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0, problem.Validation(problem.Violation{
			Pointer: "/expected_revision", Code: "INVALID",
			Message: "expected_revision is not a revision this host issued.",
		})
	}
	return n, nil
}

// validateDisplayName mirrors the identity rule for a display name, so a bad
// value is rejected before an operation is queued.
func validateDisplayName(s string) error {
	d := strings.TrimSpace(s)
	if utf8.RuneCountInString(d) > identity.MaxDisplayNameLen {
		return problem.Validation(problem.Violation{
			Pointer: "/display_name", Code: "too_long",
			Message: "The display name must be at most 64 characters.",
		})
	}
	for _, r := range d {
		if unicode.IsControl(r) {
			return problem.Validation(problem.Violation{
				Pointer: "/display_name", Code: "invalid",
				Message: "The display name must not contain control characters.",
			})
		}
	}
	return nil
}

// requireFields reports every empty required member as one VALIDATION_FAILED.
func requireFields(fields map[string]string) error {
	var vs []problem.Violation
	for pointer, value := range fields {
		if value == "" {
			vs = append(vs, problem.Violation{
				Pointer: pointer, Code: "REQUIRED", Message: "The field is required.",
			})
		}
	}
	if len(vs) == 0 {
		return nil
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].Pointer < vs[j].Pointer })
	return problem.Validation(vs...)
}
