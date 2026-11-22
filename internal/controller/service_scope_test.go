// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 实际 controller 适配器与 SQLite 授权链 ========================

func TestAuthorizerAdapterServiceScopeUsesActualSubject(t *testing.T) {
	c, visible := newVisibilityController(t)
	admin := createVisibilityUser(t, c, "scope-admin", identity.RoleAdmin)
	const actionID = "tls.certificates/renew_existing"
	const subject = "plugins/tls.certificates/resources/certificates/cert-one"
	var created authz.CreatedServiceAccount
	if err := c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		var err error
		created, err = c.Authorizer().CreateServiceAccount(t.Context(), tx, authz.CreateServiceAccountInput{
			Actor: admin, Name: "scope-renewal", Role: authz.RoleOperator,
			Scope: &authz.ServiceScope{Actions: []string{actionID}, NodeIDs: []string{"local"},
				Subjects: []string{subject}, ExpiresAt: c.clk.Now().Add(time.Hour)},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	who, err := c.Authorizer().AuthenticateBearer(t.Context(), created.Token)
	if err != nil {
		t.Fatal(err)
	}
	adapter := authorizerAdapter{authz: c.Authorizer()}
	action := operations.Action{ID: actionID, PluginID: "tls.certificates", Effect: "write", Permission: "system.certificates:manage"}
	target := operations.Target{NodeID: "local", Subject: subject}
	if err := adapter.Authorize(t.Context(), who, action, target); err != nil {
		t.Fatal("适配器没有传递完整真实目标: ", err)
	}
	target.Subject += "-other"
	if err := adapter.Authorize(t.Context(), who, action, target); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("controller 适配器扩大了服务资源范围: %v", err)
	}
	if visible.Allowed(who, operationEvent(t, "op_scope", who)) {
		t.Fatal("事件可见性按角色绕过了精确服务作用域")
	}
}
