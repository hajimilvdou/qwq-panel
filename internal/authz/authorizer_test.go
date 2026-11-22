// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestAuthorizeHuman(t *testing.T) {
	f := newFixture(t)
	admin := f.human(f.user("admin", "admin", false))
	op := f.human(f.user("op", "operator", false))
	viewer := f.human(f.user("viewer", "viewer", false))
	disabled := f.human(f.user("gone", "admin", true))
	unknown := f.human(f.gen.New("usr"))

	cases := []struct {
		name string
		a    actor.Actor
		perm string
		code problem.Code // empty means allowed
	}{
		{"admin create user", admin, "host.users:create", ""},
		{"admin install plugin", admin, "host.plugins:install", ""},
		{"operator installs plugin", op, "host.plugins:install", ""},
		{"operator reads users", op, "host.users:read", problem.PermissionDenied},
		{"operator reads audit", op, "host.audit:read", problem.PermissionDenied},
		{"operator creates delegation", op, "host.delegations:create", ""},
		{"operator manages service accounts", op, "host.service_accounts:create", problem.PermissionDenied},
		{"viewer reads", viewer, "host.nodes:read", ""},
		{"viewer denied users read", viewer, "host.users:read", problem.PermissionDenied},
		{"viewer denied service accounts read", viewer, "host.service_accounts:read", problem.PermissionDenied},
		{"viewer reads own delegations", viewer, "host.delegations:read", ""},
		{"viewer denied audit read", viewer, "host.audit:read", problem.PermissionDenied},
		{"viewer performs read-only export", viewer, "core.xray:export", ""},
		{"viewer writes", viewer, "host.plugins:install", problem.PermissionDenied},
		{"disabled user", disabled, "host.nodes:read", problem.PermissionDenied},
		{"unknown user", unknown, "host.nodes:read", problem.PermissionDenied},
	}
	for _, c := range cases {
		err := f.z.Authorize(f.ctx, c.a, c.perm, Resource{Name: permResource(c.perm)})
		if c.code == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if !problem.HasCode(err, c.code) {
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
		}
	}
	// A system actor is trusted.
	if err := f.z.Authorize(f.ctx, actor.SystemActor("reconciler"), "host.users:delete", Resource{}); err != nil {
		t.Fatalf("system actor denied: %v", err)
	}
	// Malformed permission strings are a caller bug, not a denial.
	if err := f.z.Authorize(f.ctx, admin, "not-a-permission", Resource{}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("malformed permission: %v", err)
	}
	// A resource that does not match the permission is rejected.
	if err := f.z.Authorize(f.ctx, admin, "host.users:read", Resource{Name: "host.nodes"}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("mismatched resource: %v", err)
	}
	// An unknown actor kind fails closed.
	if err := f.z.Authorize(f.ctx, actor.Actor{Kind: "gremlin", ID: "x"}, "host.nodes:read", Resource{}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("unknown actor kind: %v", err)
	}
}

func permResource(perm string) string {
	p, err := ParsePermission(perm)
	if err != nil {
		return ""
	}
	return p.Resource()
}

func TestCreateDelegationRequiresHumanSession(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	// A human actor without a session cannot create a delegation.
	f.try(func(tx *storage.Tx) error {
		_, err := f.z.CreateDelegation(f.ctx, tx, CreateDelegationInput{
			Actor: actor.Actor{Kind: actor.Human, ID: ownerID}, Label: "x",
		})
		return err
	}, problem.PermissionDenied)
	// An ai_agent or service actor cannot either, even with a valid session field.
	f.try(func(tx *storage.Tx) error {
		_, err := f.z.CreateDelegation(f.ctx, tx, CreateDelegationInput{
			Actor: actor.Actor{Kind: actor.AIAgent, ID: "dlg_x", OnBehalfOf: ownerID}, Label: "x",
		})
		return err
	}, problem.PermissionDenied)
	// Neither can approve.
	if f.z.CanApprove(actor.Actor{Kind: actor.AIAgent, ID: "dlg_x", OnBehalfOf: ownerID}) {
		t.Fatal("AI actor may approve")
	}
	if f.z.CanApprove(actor.Actor{Kind: actor.Service, ID: "svc_x"}) {
		t.Fatal("service actor may approve")
	}
	if !f.z.CanApprove(f.human(ownerID)) {
		t.Fatal("human session may not approve")
	}
}

func TestDelegationEffectivePermission(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	created := f.createDelegation(f.human(ownerID), Policy{}, time.Hour)
	a := f.agent(created.Token)
	if a.Kind != actor.AIAgent || a.ID != created.ID || a.OnBehalfOf != ownerID {
		t.Fatalf("delegation actor = %+v", a)
	}
	if a.IsHumanSession() {
		t.Fatal("delegation actor claims to be a human session")
	}
	// Within the owner's role: allowed.
	if err := f.z.Authorize(f.ctx, a, "host.plugins:install", Resource{Name: "host.plugins"}); err != nil {
		t.Fatalf("operator delegation denied plugin install: %v", err)
	}
	// Outside the owner's role: denied.
	if err := f.z.Authorize(f.ctx, a, "host.users:create", Resource{Name: "host.users"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("delegation exceeded the owner: %v", err)
	}
	// Hard rule: never approve, never manage delegations.
	if f.z.CanApprove(a) {
		t.Fatal("delegation may approve")
	}
	if err := f.z.Authorize(f.ctx, a, "host.approvals:approve", Resource{Name: "host.approvals"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("delegation approved: %v", err)
	}
	if err := f.z.Authorize(f.ctx, a, "host.delegations:create", Resource{Name: "host.delegations"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("delegation managed delegations: %v", err)
	}
	if err := f.z.Authorize(f.ctx, a, "host.users:read", Resource{Name: "host.users"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("delegation read users: %v", err)
	}
}

// TestAcceptanceDelegationCannotExceedOwner is ADR-0004 acceptance 3: a
// delegation token is refused for resources outside the owner's RBAC, refused
// for approvals, and shrinks when the owner is demoted.
func TestAcceptanceDelegationCannotExceedOwner(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	created := f.createDelegation(f.human(ownerID), Policy{}, time.Hour)
	a := f.agent(created.Token)

	if err := f.z.Authorize(f.ctx, a, "host.plugins:install", Resource{Name: "host.plugins"}); err != nil {
		t.Fatalf("operator delegation should install plugins: %v", err)
	}
	// Demote the owner: the same token loses the permission on the next call.
	f.setRole(ownerID, "viewer")
	if err := f.z.Authorize(f.ctx, a, "host.plugins:install", Resource{Name: "host.plugins"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("demotion did not shrink the delegation: %v", err)
	}
	// Reads still work for the viewer owner.
	if err := f.z.Authorize(f.ctx, a, "host.nodes:read", Resource{Name: "host.nodes"}); err != nil {
		t.Fatalf("viewer delegation cannot read: %v", err)
	}
	// Disabling the owner invalidates the token entirely.
	f.disable(ownerID)
	if _, err := f.z.AuthenticateBearer(f.ctx, created.Token); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("disabled owner's delegation authenticated: %v", err)
	}
	if err := f.z.Authorize(f.ctx, a, "host.nodes:read", Resource{Name: "host.nodes"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("disabled owner's delegation authorized: %v", err)
	}
}

func TestDelegationSuspension(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	created := f.createDelegation(f.human(ownerID), Policy{}, time.Hour)
	a := f.agent(created.Token)

	suspended := StatusSuspended
	var updated Delegation
	f.update(func(tx *storage.Tx) error {
		var err error
		updated, err = f.z.UpdateDelegation(f.ctx, tx, UpdateDelegationInput{
			Actor: f.human(ownerID), DelegationID: created.ID,
			ExpectedRevision: created.Revision, Status: &suspended,
		})
		return err
	})
	if updated.Status != StatusSuspended {
		t.Fatalf("status = %s", updated.Status)
	}
	if _, err := f.z.AuthenticateBearer(f.ctx, created.Token); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("suspended delegation authenticated: %v", err)
	}
	if err := f.z.Authorize(f.ctx, a, "host.nodes:read", Resource{Name: "host.nodes"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("suspended delegation authorized: %v", err)
	}
	// Resume restores the token.
	active := StatusActive
	f.update(func(tx *storage.Tx) error {
		_, err := f.z.UpdateDelegation(f.ctx, tx, UpdateDelegationInput{
			Actor: f.human(ownerID), DelegationID: created.ID,
			ExpectedRevision: updated.Revision, Status: &active,
		})
		return err
	})
	if _, err := f.z.AuthenticateBearer(f.ctx, created.Token); err != nil {
		t.Fatalf("resumed delegation rejected: %v", err)
	}
	// A stale expected_revision is a conflict.
	f.try(func(tx *storage.Tx) error {
		_, err := f.z.UpdateDelegation(f.ctx, tx, UpdateDelegationInput{
			Actor: f.human(ownerID), DelegationID: created.ID,
			ExpectedRevision: created.Revision, Status: &suspended,
		})
		return err
	}, problem.RevisionConflict)
}

func TestDelegationExpiry(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	created := f.createDelegation(f.human(ownerID), Policy{}, 5*time.Minute)
	a := f.agent(created.Token)
	f.clk.Advance(6 * time.Minute)
	if _, err := f.z.AuthenticateBearer(f.ctx, created.Token); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("expired delegation authenticated: %v", err)
	}
	if err := f.z.Authorize(f.ctx, a, "host.nodes:read", Resource{Name: "host.nodes"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("expired delegation authorized: %v", err)
	}
	if st := created.StatusAt(f.clk.Now()); st != StatusExpired {
		t.Fatalf("StatusAt = %s", st)
	}
}

func TestDelegationNodeScope(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	policy := Policy{NodeIDs: []string{"local"}}
	created := f.createDelegation(f.human(ownerID), policy, time.Hour)
	a := f.agent(created.Token)
	if err := f.z.Authorize(f.ctx, a, "host.plugins:install", Resource{Name: "host.plugins", NodeID: "local"}); err != nil {
		t.Fatalf("allowed node denied: %v", err)
	}
	if err := f.z.Authorize(f.ctx, a, "host.plugins:install", Resource{Name: "host.plugins", NodeID: "other"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("node outside the policy allowed: %v", err)
	}
	// Host-wide resources (no node) are always in scope.
	if err := f.z.Authorize(f.ctx, a, "host.nodes:read", Resource{Name: "host.nodes"}); err != nil {
		t.Fatalf("host-wide read denied: %v", err)
	}
}

// TestDelegationActionAllowList checks that Authorize enforces the policy's
// action allowlist itself (ADR-0004 D6): with the permission held constant, the
// action ID alone decides, and a call that does not name its action fails
// closed instead of skipping the check.
func TestDelegationActionAllowList(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	created := f.createDelegation(f.human(ownerID), Policy{Actions: []string{"a/*"}}, time.Hour)
	a := f.agent(created.Token)

	cases := []struct {
		name   string
		action string
		code   problem.Code // empty means allowed
	}{
		{"outside the allowlist", "b/x", problem.PermissionDenied},
		{"no action ID", "", problem.PermissionDenied},
		{"inside the allowlist", "a/x", ""},
	}
	for _, c := range cases {
		err := f.z.Authorize(f.ctx, a, "host.plugins:install", Resource{Name: "host.plugins", Action: c.action})
		if c.code == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if !problem.HasCode(err, c.code) {
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
		}
	}
}

func TestDelegationRateLimit(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	created := f.createDelegation(f.human(ownerID), Policy{RequestsPerMinute: 1}, time.Hour)
	a := f.agent(created.Token)
	if err := f.z.Authorize(f.ctx, a, "host.nodes:read", Resource{Name: "host.nodes"}); err != nil {
		t.Fatalf("first request: %v", err)
	}
	err := f.z.Authorize(f.ctx, a, "host.nodes:read", Resource{Name: "host.nodes"})
	if !problem.HasCode(err, problem.RateLimited) {
		t.Fatalf("second request in the same minute: %v, want RATE_LIMITED", err)
	}
	var pe *problem.Error
	if !asProblem(err, &pe) || pe.RetryAfterSec < 1 {
		t.Fatalf("rate limit without retry_after: %v", err)
	}
	f.clk.Advance(61 * time.Second)
	if err := f.z.Authorize(f.ctx, a, "host.nodes:read", Resource{Name: "host.nodes"}); err != nil {
		t.Fatalf("request after the window: %v", err)
	}
}

func TestDelegationPolicyNarrowing(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	base := Policy{
		Actions:           []string{"com.example.monitor/*"},
		NodeIDs:           []string{"local"},
		RequestsPerMinute: 60,
	}
	created := f.createDelegation(f.human(ownerID), base, time.Hour)
	wider := Policy{Actions: []string{"host.users.create"}}
	f.try(func(tx *storage.Tx) error {
		_, err := f.z.UpdateDelegation(f.ctx, tx, UpdateDelegationInput{
			Actor: f.human(ownerID), DelegationID: created.ID,
			ExpectedRevision: created.Revision, Policy: &wider,
		})
		return err
	}, problem.ValidationFailed)
	narrower := Policy{
		Actions:            []string{"com.example.monitor/*"},
		NodeIDs:            []string{"local"},
		RequestsPerMinute:  10,
		AutoApproveMaxRisk: "none",
	}
	f.update(func(tx *storage.Tx) error {
		_, err := f.z.UpdateDelegation(f.ctx, tx, UpdateDelegationInput{
			Actor: f.human(ownerID), DelegationID: created.ID,
			ExpectedRevision: created.Revision, Policy: &narrower,
		})
		return err
	})
	got, err := f.z.Delegation(f.ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Policy.RequestsPerMinute != 10 || got.Policy.AutoApproveMaxRisk != "none" {
		t.Fatalf("policy = %+v", got.Policy)
	}
}

func TestDelegationRevocation(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	created := f.createDelegation(f.human(ownerID), Policy{}, time.Hour)
	a := f.agent(created.Token)
	f.update(func(tx *storage.Tx) error {
		return f.z.RevokeDelegation(f.ctx, tx, RevokeDelegationInput{
			Actor: f.human(ownerID), DelegationID: created.ID, ExpectedRevision: created.Revision,
		})
	})
	if _, err := f.z.AuthenticateBearer(f.ctx, created.Token); !problem.HasCode(err, problem.Unauthenticated) {
		t.Fatalf("revoked token authenticated: %v", err)
	}
	// A stale actor value cannot be replayed either.
	if err := f.z.Authorize(f.ctx, a, "host.nodes:read", Resource{Name: "host.nodes"}); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("revoked delegation authorized: %v", err)
	}
	if _, err := f.z.Delegation(f.ctx, created.ID); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("revoked delegation still readable: %v", err)
	}
}

func TestOnlyOwnerOrAdminManagesDelegation(t *testing.T) {
	f := newFixture(t)
	ownerID := f.user("alice", "operator", false)
	otherID := f.user("bob", "operator", false)
	adminID := f.user("root", "admin", false)
	created := f.createDelegation(f.human(ownerID), Policy{}, time.Hour)
	suspended := StatusSuspended
	// Another operator may not touch it.
	f.try(func(tx *storage.Tx) error {
		_, err := f.z.UpdateDelegation(f.ctx, tx, UpdateDelegationInput{
			Actor: f.human(otherID), DelegationID: created.ID,
			ExpectedRevision: created.Revision, Status: &suspended,
		})
		return err
	}, problem.PermissionDenied)
	// An administrator may.
	f.update(func(tx *storage.Tx) error {
		_, err := f.z.UpdateDelegation(f.ctx, tx, UpdateDelegationInput{
			Actor: f.human(adminID), DelegationID: created.ID,
			ExpectedRevision: created.Revision, Status: &suspended,
		})
		return err
	})
}

func asProblem(err error, dst **problem.Error) bool {
	var pe *problem.Error
	if !errors.As(err, &pe) {
		return false
	}
	*dst = pe
	return true
}

// TestAuthorizeSessionHumanOnly: a native agent session gets its owner's role
// minus every human-only permission, whichever role the owner has, and an
// owner that is neither a user nor a service account fails closed.
func TestAuthorizeSessionHumanOnly(t *testing.T) {
	f := newFixture(t)
	adminID := f.user("root", "admin", false)
	viewerID := f.user("viewer", "viewer", false)
	disabledID := f.user("gone", "admin", true)
	var svc CreatedServiceAccount
	f.update(func(tx *storage.Tx) error {
		var err error
		svc, err = f.z.CreateServiceAccount(f.ctx, tx, CreateServiceAccountInput{
			Actor: f.human(adminID), Name: "agent-owner", Role: RoleOperator,
		})
		return err
	})

	cases := []struct {
		name  string
		owner string
		perm  string
		code  problem.Code // empty means allowed
	}{
		{"admin owner plugin op", adminID, "host.plugins:install", ""},
		{"admin owner creates user", adminID, "host.users:create", problem.PermissionDenied},
		{"admin owner updates user", adminID, "host.users:update", problem.PermissionDenied},
		{"admin owner creates delegation", adminID, "host.delegations:create", problem.PermissionDenied},
		{"admin owner approves", adminID, "host.approvals:approve", problem.PermissionDenied},
		{"viewer owner reads", viewerID, "host.nodes:read", ""},
		{"viewer owner writes", viewerID, "host.plugins:install", problem.PermissionDenied},
		{"disabled owner", disabledID, "host.nodes:read", problem.PermissionDenied},
		{"service owner plugin op", svc.ID, "host.plugins:install", ""},
		{"service owner creates user", svc.ID, "host.users:create", problem.PermissionDenied},
		{"empty owner", "", "host.nodes:read", problem.PermissionDenied},
		{"delegation owner", "dlg_01hzzzzzzzzzzzzzzzzzzzzzzz", "host.nodes:read", problem.PermissionDenied},
	}
	for _, c := range cases {
		err := f.z.AuthorizeSession(f.ctx, c.owner, c.perm, Resource{Name: permResource(c.perm)})
		if c.code == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if !problem.HasCode(err, c.code) {
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
		}
	}
	if err := f.z.AuthorizeSession(f.ctx, adminID, "not-a-permission", Resource{}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("malformed permission: %v", err)
	}

	for perm, want := range map[string]bool{
		"host.users:create": true, "host.approvals:approve": true, "garbage": true,
		"host.account:update":      true,
		"host.ai_providers:create": true,
		"host.plugins:install":     false, "host.nodes:read": false,
	} {
		if got := IsHumanOnly(perm); got != want {
			t.Errorf("IsHumanOnly(%q) = %v, want %v", perm, got, want)
		}
	}
}

// ======================== 实际主体类型与精确作用域 ========================

func TestAuthorizeSessionActorRejectsPrincipalKindConfusion(t *testing.T) {
	f, owner, created, scope := scopedServiceFixture(t)
	target := Resource{Name: "system.certificates", NodeID: "local",
		Action: "tls.certificates/renew_existing", Subject: scope.Subjects[0]}
	cases := []struct {
		name    string
		kind    actor.Kind
		id      string
		allowed bool
	}{
		{"explicit-human", actor.Human, owner, true},
		{"explicit-service", actor.Service, created.ID, true},
		{"reloaded-human", "", owner, true},
		{"reloaded-service", "", created.ID, true},
		{"service-id-as-human", actor.Human, created.ID, false},
		{"human-id-as-service", actor.Service, owner, false},
		{"unknown-kind", actor.System, owner, false},
		{"delegation-is-not-owner", actor.AIAgent, owner, false},
		{"malformed-human-id", actor.Human, "usr_short", false},
		{"malformed-service-id", actor.Service, "svc_short", false},
		{"missing-id", actor.Human, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.z.AuthorizeSessionActor(f.ctx, tc.kind, tc.id, "system.certificates:manage", target)
			if tc.allowed {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatalf("不一致的主体来源未拒绝: %v", err)
			}
		})
	}
}

func TestAuthorizeSessionActorKeepsScopedServiceLimits(t *testing.T) {
	f, owner, created, scope := scopedServiceFixture(t)
	exact := Resource{Name: "system.certificates", NodeID: "local",
		Action: "tls.certificates/renew_existing", Subject: scope.Subjects[0]}
	for _, kind := range []actor.Kind{actor.Service, ""} {
		if err := f.z.AuthorizeSessionActor(f.ctx, kind, created.ID, "system.certificates:manage", exact); err != nil {
			t.Fatal(err)
		}
		for _, target := range []Resource{
			{Name: exact.Name, NodeID: "other", Action: exact.Action, Subject: exact.Subject},
			{Name: exact.Name, NodeID: exact.NodeID, Action: "tls.certificates/issue", Subject: exact.Subject},
			{Name: exact.Name, NodeID: exact.NodeID, Action: exact.Action, Subject: exact.Subject + "-other"},
			{Name: exact.Name},
		} {
			if err := f.z.AuthorizeSessionActor(f.ctx, kind, created.ID, "system.certificates:manage", target); !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatalf("会话类型恢复扩大了精确权限: %v", err)
			}
		}
	}
	// 不能用已知主体类型缓存创建者权限；撤权后每次都查询当前账号状态。
	f.setRole(owner, "viewer")
	for _, kind := range []actor.Kind{actor.Service, ""} {
		if err := f.z.AuthorizeSessionActor(f.ctx, kind, created.ID, "system.certificates:manage", exact); !problem.HasCode(err, problem.PermissionDenied) {
			t.Fatalf("服务账号创建者撤权后仍获准: %v", err)
		}
	}
}
