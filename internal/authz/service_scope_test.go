// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实 SQLite 账号与精确资源 ========================

func scopedServiceFixture(t *testing.T) (*fixture, string, CreatedServiceAccount, *ServiceScope) {
	t.Helper()
	f := newFixture(t)
	owner := f.user("scope-admin", "admin", false)
	scope := &ServiceScope{
		Actions:   []string{"tls.certificates/renew_existing"},
		NodeIDs:   []string{"local"},
		Subjects:  []string{"plugins/tls.certificates/resources/certificates/cert-one"},
		ExpiresAt: f.clk.Now().Add(24 * time.Hour),
	}
	var created CreatedServiceAccount
	f.update(func(tx *storage.Tx) error {
		var err error
		created, err = f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
			Actor: f.human(owner), Name: "scoped-renewal", Role: RoleOperator, Scope: scope,
		})
		return err
	})
	return f, owner, created, scope
}

func TestServiceScopeExactTargetAndSessionOwner(t *testing.T) {
	f, _, created, scope := scopedServiceFixture(t)
	who := f.agent(created.Token)
	exact := Resource{Name: "system.certificates", NodeID: "local",
		Action: "tls.certificates/renew_existing", Subject: scope.Subjects[0]}
	if err := f.z.Authorize(f.ctx, who, "system.certificates:manage", exact); err != nil {
		t.Fatal(err)
	}
	if err := f.z.AuthorizeSession(f.ctx, created.ID, "system.certificates:manage", exact); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name  string
		apply func(*Resource)
	}{
		{"other-action", func(r *Resource) { r.Action = "tls.certificates/issue" }},
		{"missing-action", func(r *Resource) { r.Action = "" }},
		{"other-node", func(r *Resource) { r.NodeID = "other" }},
		{"missing-node", func(r *Resource) { r.NodeID = "" }},
		{"other-subject", func(r *Resource) { r.Subject += "-other" }},
		{"missing-subject", func(r *Resource) { r.Subject = "" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			target := exact
			change.apply(&target)
			if err := f.z.Authorize(f.ctx, who, "system.certificates:manage", target); !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatalf("服务账号越界未拒绝: %v", err)
			}
			if err := f.z.AuthorizeSession(f.ctx, created.ID, "system.certificates:manage", target); !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatalf("服务账号所属会话扩大权限: %v", err)
			}
		})
	}
}

func TestServiceScopePersistenceAndInputIsolation(t *testing.T) {
	f, _, created, input := scopedServiceFixture(t)
	original := slices.Clone(input.Subjects)
	input.Subjects[0] = "mutated"
	reloaded, err := f.z.ServiceAccount(f.ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Scope == nil || !slices.Equal(reloaded.Scope.Subjects, original) {
		t.Fatal("作用域丢失或复用了调用方切片")
	}
	reloaded.Scope.Actions[0] = "mutated"
	again, err := f.z.ServiceAccount(f.ctx, created.ID)
	if err != nil || again.Scope == nil || again.Scope.Actions[0] != "tls.certificates/renew_existing" {
		t.Fatal("读取副本改变了持久权限")
	}
}

func TestServiceScopeExpiryAndCreatorRevocation(t *testing.T) {
	f, owner, created, scope := scopedServiceFixture(t)
	who := f.agent(created.Token)
	target := Resource{Name: "system.certificates", NodeID: "local", Action: scope.Actions[0], Subject: scope.Subjects[0]}
	f.setRole(owner, "viewer")
	if err := f.z.Authorize(f.ctx, who, "system.certificates:manage", target); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("创建者撤权未收紧服务账号: %v", err)
	}
	f.setRole(owner, "admin")
	f.disable(owner)
	if _, err := f.z.AuthenticateBearer(f.ctx, created.Token); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("创建者禁用后仍能认证: %v", err)
	}
	f2, _, second, _ := scopedServiceFixture(t)
	f2.clk.Advance(24 * time.Hour)
	if _, err := f2.z.AuthenticateBearer(f2.ctx, second.Token); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("到期作用域仍能认证: %v", err)
	}
}

func TestServiceScopeStrictStoredDocument(t *testing.T) {
	for _, raw := range []string{"null", "{}", `{"unknown":true}`, `{"actions":[],"actions":[]}`, `{"actions":true}`, `{} {}`} {
		if _, err := decodeServiceScope(raw); err == nil {
			t.Fatalf("畸形作用域未拒绝: %s", raw)
		}
	}
	f, _, created, _ := scopedServiceFixture(t)
	valid, err := json.Marshal(created.Scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{`,"unknown":true}`, `,"actions":["tls.certificates/renew_existing"]}`, `,"\u0061ctions":["tls.certificates/renew_existing"]}`} {
		raw := strings.TrimSuffix(string(valid), "}") + suffix
		if _, err := decodeServiceScope(raw); err == nil {
			t.Fatal("完整有效权限上的未知/重复字段未拒绝")
		}
	}
	for _, raw := range []string{"null", "{}", `{"unknown":true}`, `{"actions":[],"actions":[]}`} {
		f.update(func(tx *storage.Tx) error {
			_, err := tx.ExecContext(f.ctx, `UPDATE service_accounts SET scope_json = ? WHERE service_id = ?`, raw, created.ID)
			return err
		})
		if _, err := f.z.AuthenticateBearer(f.ctx, created.Token); err == nil {
			t.Fatal("非空坏作用域降级为旧版角色账号")
		}
	}
}

// ======================== 形状有界与创建前到期验证 ========================

func TestServiceScopeValidationMatrix(t *testing.T) {
	f, owner, _, valid := scopedServiceFixture(t)
	for _, invalid := range []struct {
		name  string
		apply func(*ServiceScope)
	}{
		{"missing-actions", func(s *ServiceScope) { s.Actions = nil }},
		{"wildcard-action", func(s *ServiceScope) { s.Actions = []string{"tls.certificates/*"} }},
		{"duplicate-action", func(s *ServiceScope) { s.Actions = append(s.Actions, s.Actions[0]) }},
		{"missing-nodes", func(s *ServiceScope) { s.NodeIDs = nil }},
		{"wildcard-node", func(s *ServiceScope) { s.NodeIDs = []string{"*"} }},
		{"duplicate-node", func(s *ServiceScope) { s.NodeIDs = append(s.NodeIDs, s.NodeIDs[0]) }},
		{"missing-subjects", func(s *ServiceScope) { s.Subjects = nil }},
		{"absolute-subject", func(s *ServiceScope) { s.Subjects = []string{"/certificates/one"} }},
		{"traversal-subject", func(s *ServiceScope) { s.Subjects = []string{"certificates/../one"} }},
		{"empty-path-segment", func(s *ServiceScope) { s.Subjects = []string{"certificates//one"} }},
		{"missing-expiry", func(s *ServiceScope) { s.ExpiresAt = time.Time{} }},
		{"expired-before-create", func(s *ServiceScope) { s.ExpiresAt = f.clk.Now() }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			scope := *valid
			scope.Actions, scope.NodeIDs, scope.Subjects = slices.Clone(valid.Actions), slices.Clone(valid.NodeIDs), slices.Clone(valid.Subjects)
			invalid.apply(&scope)
			f.try(func(tx *storage.Tx) error {
				_, err := f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
					Actor: f.human(owner), Name: "invalid-scope", Role: RoleOperator, Scope: &scope,
				})
				return err
			}, problem.ValidationFailed)
		})
	}
}
