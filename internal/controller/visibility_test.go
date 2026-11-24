// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"encoding/json"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ============================================================================
//  事件可见性与 REST 读权限对齐（GW-04）
// ============================================================================

func newVisibilityController(t *testing.T) (*Controller, *visibility) {
	t.Helper()
	c, err := New(t.Context(), testOptions(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, newVisibility(c.id, c.auth, c.clk)
}

func createVisibilityUser(t *testing.T, c *Controller, name string, role identity.Role) actor.Actor {
	t.Helper()
	system := actor.SystemActor("test")
	var u identity.User
	if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: system})
		res, err := c.Identity().CreateUser(t.Context(), tx, identity.CreateUserInput{
			Username: name, DisplayName: name, Role: role, Actor: system,
		})
		u = res.User
		return err
	}); err != nil {
		t.Fatalf("CreateUser %s: %v", name, err)
	}
	return actor.Actor{Kind: actor.Human, ID: u.ID, SessionID: "ses_" + name}
}

func operationEvent(t *testing.T, opID string, by actor.Actor) events.Event {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"operation_id": opID, "actor": by})
	if err != nil {
		t.Fatal(err)
	}
	return events.Event{Type: "operation.updated", Subject: "operations/" + opID, Payload: payload}
}

func TestVisibilityServiceAccountSeesOnlyOwnOperations(t *testing.T) {
	c, v := newVisibilityController(t)
	admin := createVisibilityUser(t, c, "admin", identity.RoleAdmin)

	mint := func(name string) actor.Actor {
		var sa authz.CreatedServiceAccount
		if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
			tx.SetOrigin(storage.Origin{Actor: admin})
			var err error
			sa, err = c.Authorizer().CreateServiceAccount(t.Context(), tx, authz.CreateServiceAccountInput{
				Actor: admin, Name: name, Role: authz.RoleAdmin,
			})
			return err
		}); err != nil {
			t.Fatalf("CreateServiceAccount: %v", err)
		}
		return actor.Actor{Kind: actor.Service, ID: sa.ID}
	}
	self, other := mint("self"), mint("other")

	if !v.Allowed(self, operationEvent(t, "op_1", self)) {
		t.Fatal("service account must see its own operation")
	}
	if v.Allowed(self, operationEvent(t, "op_2", other)) {
		t.Fatal("service account must not see another principal's operation")
	}
	if v.Allowed(self, operationEvent(t, "op_3", admin)) {
		t.Fatal("service account must not see a human's operation")
	}
	// resource.changed 不带发起人：非人类主体一律不推。
	changed := events.Event{Type: "resource.changed", Subject: "operations/op_1", Payload: json.RawMessage(`{}`)}
	if v.Allowed(self, changed) {
		t.Fatal("service account must not see operation resource.changed")
	}
	// 人类保持原样：能看全部。
	if !v.Allowed(admin, operationEvent(t, "op_2", other)) || !v.Allowed(admin, changed) {
		t.Fatal("admin must see every operation event")
	}
}

func TestVisibilityViewerCannotSeeForeignDelegations(t *testing.T) {
	c, v := newVisibilityController(t)
	owner := createVisibilityUser(t, c, "owner", identity.RoleOperator)
	otherOp := createVisibilityUser(t, c, "otherop", identity.RoleOperator)
	viewer := createVisibilityUser(t, c, "viewer", identity.RoleViewer)
	admin := createVisibilityUser(t, c, "admin", identity.RoleAdmin)

	var d authz.Created
	if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: owner})
		var err error
		d, err = c.Authorizer().CreateDelegation(t.Context(), tx, authz.CreateDelegationInput{
			Actor: owner, Label: "bot",
			Policy: authz.Policy{AutoApproveMaxRisk: "none", OnApprovalRequired: "queue"},
		})
		return err
	}); err != nil {
		t.Fatalf("CreateDelegation: %v", err)
	}
	e := events.Event{Type: "resource.changed", Subject: d.Subject(), Payload: json.RawMessage(`{}`)}

	if v.Allowed(viewer, e) {
		t.Fatal("viewer must not see a foreign delegation")
	}
	if v.Allowed(otherOp, e) {
		t.Fatal("another operator must not see a foreign delegation")
	}
	if !v.Allowed(owner, e) {
		t.Fatal("owner operator must see their delegation")
	}
	if !v.Allowed(admin, e) {
		t.Fatal("admin must see every delegation")
	}
	// 已删除且未缓存的委托：只认事件发起人（且发起人角色需允许读取委托）。
	gone := events.Event{Type: "resource.changed", Subject: "delegations/dlg_gone", Payload: json.RawMessage(`{}`),
		Actor: events.Actor{Kind: string(actor.Human), ID: owner.ID}}
	if !v.Allowed(owner, gone) || v.Allowed(otherOp, gone) || v.Allowed(viewer, gone) {
		t.Fatal("deleted delegation must be visible to its actor only")
	}
	// 已知资源已由真实查询确认所有者后，不能借缓存向其他角色泄漏。
	viewerOwn := events.Event{Type: "resource.changed", Subject: "delegations/dlg_viewer_gone",
		Payload: json.RawMessage(`{"kind":"delete"}`),
		Actor:   events.Actor{Kind: string(actor.Human), ID: viewer.ID}}
	if !v.Allowed(viewer, viewerOwn) || v.Allowed(owner, viewerOwn) || v.Allowed(otherOp, viewerOwn) {
		t.Fatal("a viewer may see its own delegation removal, never another owner's")
	}
}

func TestVisibilityUsersServiceAccountsAuditAdminOnly(t *testing.T) {
	c, v := newVisibilityController(t)
	admin := createVisibilityUser(t, c, "admin", identity.RoleAdmin)
	operator := createVisibilityUser(t, c, "operator", identity.RoleOperator)
	viewer := createVisibilityUser(t, c, "viewer", identity.RoleViewer)

	var sa authz.CreatedServiceAccount
	if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: admin})
		var err error
		sa, err = c.Authorizer().CreateServiceAccount(t.Context(), tx, authz.CreateServiceAccountInput{
			Actor: admin, Name: "svc-admin", Role: authz.RoleAdmin,
		})
		return err
	}); err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	svcAdmin := actor.Actor{Kind: actor.Service, ID: sa.ID}

	for _, subj := range []string{"users", "service_accounts", "audit", "users/usr_1", "service_accounts/svc_1", "audit/aud_1"} {
		ev := events.Event{Type: "resource.changed", Subject: subj, Payload: json.RawMessage(`{}`)}
		if !v.Allowed(admin, ev) {
			t.Fatalf("admin must see %s", subj)
		}
		if v.Allowed(operator, ev) {
			t.Fatalf("operator must not see %s", subj)
		}
		if v.Allowed(viewer, ev) {
			t.Fatalf("viewer must not see %s", subj)
		}
		if v.Allowed(svcAdmin, ev) {
			t.Fatalf("non-human service account must not see %s", subj)
		}
	}
}

// TestVisibilityAgentSessionsOnlyOwner covers gap 6: agent_sessions events go
// to the owner alone — an administrator is no exception — a session whose row
// is gone keeps its cached owner within the TTL, a delete event names its
// owner through its actor, and any other unknown subject is dropped.
func TestVisibilityAgentSessionsOnlyOwner(t *testing.T) {
	c, v := newVisibilityController(t)
	owner := createVisibilityUser(t, c, "owner", identity.RoleOperator)
	admin := createVisibilityUser(t, c, "admin", identity.RoleAdmin)
	other := createVisibilityUser(t, c, "other", identity.RoleViewer)

	svc, err := c.NewAgentSessions(t.Context())
	if err != nil {
		t.Fatalf("NewAgentSessions: %v", err)
	}
	v.setSessionOwner(svc.OwnerOf)

	rec, err := svc.Create(t.Context(), owner, agentsession.CreateRequest{Title: "T"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	subject := "agent_sessions/" + rec.ID
	update := events.Event{Type: "agent.session.updated", Subject: subject, Payload: json.RawMessage(`{}`)}

	if !v.Allowed(owner, update) {
		t.Fatal("owner must see their own session event")
	}
	if v.Allowed(admin, update) {
		t.Fatal("admin must not see another user's session event")
	}
	if v.Allowed(other, update) {
		t.Fatal("another user must not see the session event")
	}
	if !v.Allowed(actor.SystemActor("test"), update) {
		t.Fatal("the system actor sees everything")
	}

	// The cache keeps the owner while the row is gone (the delete event is
	// dispatched after the commit that removed it).
	if err := svc.Delete(t.Context(), owner, rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	gone := events.Event{Type: "agent.session.updated", Subject: subject, Payload: json.RawMessage(`{}`)}
	if !v.Allowed(owner, gone) {
		t.Fatal("the cached owner must survive the row within the TTL")
	}

	// A session that was never seen: only a delete event names its owner (the
	// event actor); any other event of an unknown subject is dropped.
	del := events.Event{Type: "resource.changed", Subject: "agent_sessions/sess_gone",
		Payload: json.RawMessage(`{"kind":"delete"}`),
		Actor:   events.Actor{Kind: string(actor.Human), ID: owner.ID}}
	if !v.Allowed(owner, del) {
		t.Fatal("a delete event must be visible to the actor it names")
	}
	if v.Allowed(admin, del) || v.Allowed(other, del) {
		t.Fatal("a delete event must not reach anyone else")
	}
	unknown := events.Event{Type: "resource.changed", Subject: "agent_sessions/sess_unknown",
		Payload: json.RawMessage(`{"kind":"update"}`),
		Actor:   events.Actor{Kind: string(actor.Human), ID: owner.ID}}
	if v.Allowed(owner, unknown) {
		t.Fatal("an update event of an unknown session must be dropped")
	}

	// A service account's session is the service account's alone.
	var sa authz.CreatedServiceAccount
	if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: owner})
		var err error
		sa, err = c.Authorizer().CreateServiceAccount(t.Context(), tx, authz.CreateServiceAccountInput{
			Actor: owner, Name: "ci", Role: authz.RoleAdmin,
		})
		return err
	}); err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	svcOwner := actor.Actor{Kind: actor.Service, ID: sa.ID}
	rec2, err := svc.Create(t.Context(), svcOwner, agentsession.CreateRequest{Title: "CI"})
	if err != nil {
		t.Fatalf("Create as service: %v", err)
	}
	e2 := events.Event{Type: "agent.session.updated", Subject: "agent_sessions/" + rec2.ID, Payload: json.RawMessage(`{}`)}
	if !v.Allowed(svcOwner, e2) {
		t.Fatal("a service account must see its own session event")
	}
	if v.Allowed(admin, e2) || v.Allowed(owner, e2) {
		t.Fatal("no human may see a service account's session event")
	}
}

// TestVisibilitySessionOwnerWired covers the controller wiring: the gateway's
// visibility resolves agent session owners once the backend exists, and denies
// the subject family before that.
func TestVisibilitySessionOwnerWired(t *testing.T) {
	c, err := New(t.Context(), testOptions(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	owner := createVisibilityUser(t, c, "owner", identity.RoleOperator)

	e := events.Event{Type: "agent.session.updated", Subject: "agent_sessions/sess_wired", Payload: json.RawMessage(`{}`)}
	if c.vis.Allowed(owner, e) {
		t.Fatal("without a session backend the subject family must be denied")
	}
	svc, err := c.NewAgentSessions(t.Context())
	if err != nil {
		t.Fatalf("NewAgentSessions: %v", err)
	}
	rec, err := svc.Create(t.Context(), owner, agentsession.CreateRequest{Title: "T"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	e2 := events.Event{Type: "agent.session.updated", Subject: "agent_sessions/" + rec.ID, Payload: json.RawMessage(`{}`)}
	if !c.vis.Allowed(owner, e2) {
		t.Fatal("the gateway visibility must resolve session owners once the backend is built")
	}
}
