// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 角色撤权必须先于会话写入和模型调用 ========================

func TestAgentSessionViewerWriteRoutesAreDenied(t *testing.T) {
	model := newFakeModel(t, 0, func(int) string { return textReply("status") })
	e := newAgentEnv(t, func(o *agentsession.Options) { o.HTTPClient = model.srv.Client() })
	e.setupAdmin(adminUser)
	userID := e.insertUser("limited", identity.RoleOperator, adminPass)
	user := e.login("limited", adminPass)
	session := createSession(t, e, user, map[string]any{"config": configFor(model.srv.URL)})
	id := mustString(t, session, "session_id")
	revision := mustString(t, session, "revision")
	cur, err := e.c.Identity().User(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	role := identity.RoleViewer
	if err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		_, err := e.c.Identity().UpdateUser(t.Context(), tx, identity.UpdateUserInput{UserID: userID, ExpectedRevision: cur.Revision, Role: &role})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/agent-sessions", `{}`},
		{http.MethodPost, "/api/v1/agent-sessions/" + id + "/messages", `{"content":"status"}`},
		{http.MethodPatch, "/api/v1/agent-sessions/" + id, `{"title":"changed","expected_revision":"` + revision + `"}`},
		{http.MethodDelete, "/api/v1/agent-sessions/" + id, ""},
		{http.MethodPut, "/api/v1/agent-sessions/" + id + "/api-key", `{"api_key":"TEST-ONLY-session-key"}`},
		{http.MethodDelete, "/api/v1/agent-sessions/" + id + "/api-key", ""},
		{http.MethodPost, "/api/v1/agent-sessions/" + id + "/cancel", `{}`},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			e.do(user.sign(route.method, route.path, route.body)).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
		})
	}
	// 查看本人会话仍按只读权限开放，拒绝的写入不能改变记录或启动模型。
	e.do(user.sign(http.MethodGet, "/api/v1/agent-sessions", "")).expect(t, http.StatusOK)
	detail := getSession(t, e, user, id)
	if mustString(t, detail, "revision") != revision {
		t.Fatal("denied viewer route changed the session")
	}
	if len(model.authorizations()) != 0 {
		t.Fatal("denied viewer message reached the model")
	}
}

// ======================== 续期范围不能当作全局模型授权 ========================

func TestAgentSessionScopedServiceRoutesAreDenied(t *testing.T) {
	e := newAgentEnv(t, nil)
	admin := e.setupAdmin(adminUser)
	by, _, err := e.c.Identity().AuthenticateSession(t.Context(), admin.raw.Value)
	if err != nil {
		t.Fatal(err)
	}
	var account authz.CreatedServiceAccount
	if err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		var err error
		account, err = e.c.Authorizer().CreateServiceAccount(t.Context(), tx, authz.CreateServiceAccountInput{
			Actor: by, Name: "renewal-only", Role: authz.RoleOperator,
			Scope: &authz.ServiceScope{Actions: []string{"tls.certificates/renew_existing"}, NodeIDs: []string{"local"},
				Subjects: []string{"plugins/tls.certificates/resources/certificates/test-cert"}, ExpiresAt: time.Now().Add(time.Hour)},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/agent-sessions", `{}`},
		{http.MethodGet, "/api/v1/agent-sessions", ""},
		{http.MethodGet, "/api/v1/agent-sessions/not-owned", ""},
		{http.MethodPatch, "/api/v1/agent-sessions/not-owned", `{}`},
		{http.MethodDelete, "/api/v1/agent-sessions/not-owned", ""},
		{http.MethodPut, "/api/v1/agent-sessions/not-owned/api-key", `{}`},
		{http.MethodDelete, "/api/v1/agent-sessions/not-owned/api-key", ""},
		{http.MethodPost, "/api/v1/agent-sessions/not-owned/messages", `{"content":"status"}`},
		{http.MethodGet, "/api/v1/agent-sessions/not-owned/messages", ""},
		{http.MethodPost, "/api/v1/agent-sessions/not-owned/cancel", `{}`},
		{http.MethodGet, "/api/v1/agent-sessions/not-owned/events", ""},
		{http.MethodGet, "/api/v1/agent-sessions/not-owned/approvals", ""},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			e.do(bearer(route.method, route.path, route.body, account.Token)).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
		})
	}
}

func TestAgentSessionAuthorizedServiceStillCreatesOwnChat(t *testing.T) {
	e := newAgentEnv(t, nil)
	admin := e.setupAdmin(adminUser)
	token := e.serviceToken(admin)
	e.do(bearer(http.MethodPost, "/api/v1/agent-sessions", `{}`, token)).expect(t, http.StatusCreated)
}
