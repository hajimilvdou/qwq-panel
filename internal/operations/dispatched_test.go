// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实 SQLite / authz 与受控执行 fixture ========================

type dispatchRBAC struct {
	backend *authz.Authorizer
	mu      sync.Mutex
	after   func(context.Context) error
}

func (a *dispatchRBAC) Authorize(ctx context.Context, who actor.Actor, action Action, target Target) error {
	permission, err := authz.ParsePermission(action.Permission)
	if err != nil {
		return err
	}
	if err := a.backend.Authorize(ctx, who, action.Permission, authz.Resource{Name: permission.Resource(), NodeID: target.NodeID, Action: action.ID}); err != nil {
		return err
	}
	a.mu.Lock()
	after := a.after
	a.mu.Unlock()
	if after != nil {
		return after(ctx)
	}
	return nil
}

type dispatchPolicies struct{ backend *authz.Authorizer }

func (p dispatchPolicies) Limits(ctx context.Context, who actor.Actor, _ Action, _ Target) (Limits, error) {
	limits := Limits{AutoApproveMaxRisk: RiskLow, OnApprovalRequired: ApprovalQueue}
	if who.Kind == actor.AIAgent {
		delegation, err := p.backend.Delegation(ctx, who.ID)
		if err != nil {
			return Limits{}, err
		}
		policy := delegation.Policy.Normalized()
		limits.AutoApproveMaxRisk, limits.OnApprovalRequired = policy.AutoApproveMaxRisk, policy.OnApprovalRequired
	}
	if mode, ok := PermissionModeFromContext(ctx); ok {
		limits.PermissionMode = mode
	}
	return limits, nil
}

type dispatchedFixture struct {
	env   *testEnv
	authz *authz.Authorizer
	rbac  *dispatchRBAC
	human actor.Actor
	exact DispatchTarget
	id    string
}

func newDispatchedFixture(t *testing.T) *dispatchedFixture {
	t.Helper()
	e := newTestEnv(t)
	principals, err := identity.New(identity.Options{DB: e.db, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	z, err := authz.New(authz.Options{DB: e.db, Clock: e.clock, Principals: principals})
	if err != nil {
		t.Fatal(err)
	}
	userID := e.ids.New(ids.User)
	if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		now := storage.FormatTime(tx.Now())
		_, err := tx.ExecContext(e.ctx, `INSERT INTO users (user_id, username, display_name, role, disabled, created_at, updated_at, revision) VALUES (?, 'scope-owner', 'Scope owner', 'admin', 0, ?, ?, 0)`, userID, now, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rbac := &dispatchRBAC{backend: z}
	e.svc.authorizer, e.svc.policy = rbac, dispatchPolicies{backend: z}
	e.setAction(actionJob, func(action *Action) { action.Capabilities = []Capability{{Name: "state.kv.read", Scope: "self"}} })
	// 人类创建入口在 fixture 中显式建模；持久 operation 必须丢弃此 SessionID。
	human := actor.Actor{Kind: actor.Human, ID: userID, SessionID: e.ids.New(ids.Session)}
	return &dispatchedFixture{env: e, authz: z, rbac: rbac, human: human}
}

func (f *dispatchedFixture) start(t *testing.T, who actor.Actor, placement string) {
	t.Helper()
	e := f.env
	e.setAction(actionJob, func(action *Action) { action.Placement = placement })
	started := make(chan struct{})
	release := make(chan struct{})
	var stop sync.Once
	t.Cleanup(func() { stop.Do(func() { close(release) }) })
	e.dispatcher.jobFn = func(ctx context.Context, _ PluginRunJobRequest, progress func(JobProgress) error) error {
		close(started)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return progress(JobProgress{Completed: true, Result: json.RawMessage(`{"completed":true}`)})
		}
	}
	if err := e.svc.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	target := nodeTarget()
	if placement == PlacementController {
		target.NodeID, target.InstanceID = "", ""
	}
	subject, err := prefixPluginSubject(placement, "local", pluginID, "default", "certificates/one")
	if err != nil {
		t.Fatal(err)
	}
	target.Subject = subject
	response, err := e.run(who, actionJob, target, map[string]any{"scope_nonce": e.ids.New(ids.Plan)})
	if err != nil || response.Status != 202 {
		t.Fatalf("真实任务派发失败：%v", err)
	}
	f.id = response.Operation.ID
	f.exact = DispatchTarget{ActionID: actionJob, NodeID: "local", PluginID: pluginID, InstanceID: "default", Subject: subject}
	if response.Operation.Status == AwaitingApproval {
		approval, err := e.svc.GetApproval(e.ctx, f.human, response.Operation.ApprovalID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.svc.Decide(e.ctx, DecisionRequest{Actor: f.human, ApprovalID: approval.ID, Decision: DecisionApprove,
			ExpectedRevision: approval.Revision, Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/approval"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("真实任务执行者没有启动")
	}
}

func (f *dispatchedFixture) delegation(t *testing.T) authz.Created {
	t.Helper()
	var created authz.Created
	err := f.env.db.Update(f.env.ctx, func(tx *storage.Tx) error {
		var err error
		created, err = f.authz.CreateDelegation(f.env.ctx, tx, authz.CreateDelegationInput{Actor: f.human, Label: "DNC scope fixture", Policy: authz.DefaultPolicy()})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func (f *dispatchedFixture) authenticate(t *testing.T, token string) actor.Actor {
	t.Helper()
	who, err := f.authz.AuthenticateBearer(f.env.ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	return who
}

// ======================== 精确目标、撤权、取消与快照保护 ========================

func TestDispatchedContextIsIndependentAndCannotClaimHumanSession(t *testing.T) {
	f := newDispatchedFixture(t)
	f.start(t, f.human, PlacementNode)
	first, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
	if err != nil || first.Actor.ID != f.human.ID || first.Actor.SessionID != "" || !bytes.Contains(first.Args, []byte("scope_nonce")) {
		t.Fatalf("真实执行快照无效：%v", err)
	}
	protected, err := json.Marshal(first)
	if err != nil || bytes.Contains(protected, first.Args) || bytes.Contains([]byte(fmt.Sprintf("%#v", first)), []byte("scope_nonce")) {
		t.Fatal("执行快照进入了 JSON 或调试日志")
	}
	first.Args[0] = 'x'
	first.Action.Capabilities[0].Name = "secret.reveal"
	first.Clear()
	second, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
	defer second.Clear()
	if err != nil || !json.Valid(second.Args) || second.Action.Capabilities[0].Name != "state.kv.read" {
		t.Fatal("返回快照修改影响了后续授权与参数")
	}
}

func TestDispatchedContextRejectsEveryOtherTargetAndAction(t *testing.T) {
	f := newDispatchedFixture(t)
	f.start(t, f.human, PlacementNode)
	for _, field := range []string{"action", "node", "plugin", "instance", "subject"} {
		t.Run(field, func(t *testing.T) {
			other := f.exact
			switch field {
			case "action":
				other.ActionID = actionJobOnce
			case "node":
				other.NodeID = "other"
			case "plugin":
				other.PluginID = "other.plugin"
			case "instance":
				other.InstanceID = "other"
			case "subject":
				other.Subject += "-other"
			}
			if _, err := f.env.svc.ResolveDispatched(f.env.ctx, other, f.id); !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatal("别人的目标或动作获得正在执行的 operation 权限")
			}
		})
	}
}

func TestDispatchedInstanceUsesHostStoredTargetAndRejectsReplica(t *testing.T) {
	f := newDispatchedFixture(t)
	f.start(t, f.human, PlacementNode)
	accepted, err := f.env.svc.ResolveDispatchedInstance(f.env.ctx, pluginID, "default", "local", f.id)
	if err != nil {
		t.Fatal("real instance dispatch resolution failed")
	}
	defer accepted.Clear()
	if accepted.Target != f.env.operation(f.id).Target {
		t.Fatal("instance resolution changed the stored target")
	}
	if err := f.env.svc.RevalidateDispatched(f.env.ctx, accepted); err != nil {
		t.Fatal("current exact executor could not be revalidated")
	}
	for _, target := range []DispatchTarget{
		{PluginID: "other.plugin", InstanceID: "default", NodeID: "local"},
		{PluginID: pluginID, InstanceID: "other", NodeID: "local"},
		{PluginID: pluginID, InstanceID: "default", NodeID: "other"},
	} {
		if _, err := f.env.svc.ResolveDispatchedInstance(f.env.ctx, target.PluginID, target.InstanceID, target.NodeID, f.id); err == nil {
			t.Fatal("a different instance obtained secret dispatch authority")
		}
	}
	replica, err := New(Options{DB: f.env.db, Clock: f.env.clock, Catalog: f.env.svc.catalog,
		Authorizer: f.env.svc.authorizer, Policy: f.env.svc.policy, NodeID: "local"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replica.ResolveDispatchedInstance(f.env.ctx, pluginID, "default", "local", f.id); err == nil {
		t.Fatal("a persisted RUNNING row substituted for a local executor")
	}
}

func TestDispatchedControllerPlacementHasOnlyStableDefaultInstance(t *testing.T) {
	f := newDispatchedFixture(t)
	f.start(t, f.human, PlacementController)
	snapshot, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
	defer snapshot.Clear()
	if err != nil {
		t.Fatal("controller placement 未映射真实常驻实例")
	}
	instance, err := f.env.svc.ResolveDispatchedInstance(f.env.ctx, pluginID, ControllerDispatchInstance, "local", f.id)
	if err != nil {
		t.Fatal("controller placement 的秘密入口没有映射真实常驻实例")
	}
	defer instance.Clear()
	if instance.Target.NodeID != "" || instance.Target.InstanceID != "" {
		t.Fatal("秘密入口修改了原 controller placement 目标")
	}
	if err := f.env.svc.RevalidateDispatched(f.env.ctx, instance); err != nil {
		t.Fatal("controller placement 的原 executor 无法重验")
	}
	other := f.exact
	other.InstanceID = "other"
	if _, err := f.env.svc.ResolveDispatched(f.env.ctx, other, f.id); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatal("controller placement 可以选择其他实例")
	}
	if _, err := f.env.svc.ResolveDispatchedInstance(f.env.ctx, pluginID, other.InstanceID, "local", f.id); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatal("controller placement 的秘密入口可以选择其他实例")
	}
}

func TestDispatchedContextRetainsHighRiskFloorAndActualApproval(t *testing.T) {
	f := newDispatchedFixture(t)
	f.human.MFA = true
	f.env.setAction(actionJob, func(action *Action) {
		action.Capabilities = []Capability{{Name: "system.certificates.manage", Scope: "self"}}
	})
	f.start(t, f.human, PlacementNode)
	snapshot, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
	defer snapshot.Clear()
	if err != nil || !snapshot.Approved || snapshot.Action.EffectiveRisk() != RiskHigh {
		t.Fatal("高风险 capability 降级或原人类审批未核验")
	}
}

func TestDispatchedContextRequiresLocalExecutorAndRealDependencies(t *testing.T) {
	f := newDispatchedFixture(t)
	f.start(t, f.human, PlacementNode)
	replica, err := New(Options{DB: f.env.db, Clock: f.env.clock, Catalog: f.env.catalog, Authorizer: f.rbac, Policy: dispatchPolicies{backend: f.authz}})
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Stop()
	if _, err := replica.ResolveDispatched(f.env.ctx, f.exact, f.id); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatal("只有数据库 RUNNING 状态的副本取得执行权限")
	}
	replica.authorizer = nil
	if _, err := replica.ResolveDispatched(f.env.ctx, f.exact, f.id); !problem.HasCode(err, problem.Unavailable) {
		t.Fatal("缺失真实 authorizer 退化为测试默认放行")
	}
	replica.authorizer, replica.policy = f.rbac, nil
	if _, err := replica.ResolveDispatched(f.env.ctx, f.exact, f.id); !problem.HasCode(err, problem.Unavailable) {
		t.Fatal("缺失真实 policy 后端仍返回执行快照")
	}
}

func TestDispatchedContextRechecksCancellationAfterAuthorization(t *testing.T) {
	f := newDispatchedFixture(t)
	f.start(t, f.human, PlacementNode)
	f.rbac.mu.Lock()
	f.rbac.after = func(ctx context.Context) error {
		// 取消也会查询当前授权；只在原快照查询注入一次取消，避免测试钩子递归。
		f.rbac.mu.Lock()
		f.rbac.after = nil
		f.rbac.mu.Unlock()
		_, err := f.env.svc.Cancel(ctx, CancelRequest{Actor: f.human, OperationID: f.id, Idempotency: Idempotency{Key: f.env.newKey(), Method: "POST", Route: "/fixture/cancel"}})
		return err
	}
	f.rbac.mu.Unlock()
	if _, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatal("授权查询期间取消的 operation 仍取得快照")
	}
}

func TestDispatchedContextRechecksRoleRevocationDuringAuthorization(t *testing.T) {
	f := newDispatchedFixture(t)
	f.start(t, f.human, PlacementNode)
	f.rbac.mu.Lock()
	f.rbac.after = func(ctx context.Context) error {
		return f.env.db.Update(ctx, func(tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE users SET role = 'viewer' WHERE user_id = ?`, f.human.ID)
			return err
		})
	}
	f.rbac.mu.Unlock()
	if _, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id); !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatal("首轮授权查询结束后撤销角色仍返回执行权限")
	}
}

func TestDispatchedContextRejectsTimeoutAndCurrentReadOnlyMode(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "read_only", true: "timeout"}[timeout], func(t *testing.T) {
			f := newDispatchedFixture(t)
			f.start(t, f.human, PlacementNode)
			ctx := f.env.ctx
			if timeout {
				f.env.clock.Advance(10 * time.Second)
			} else {
				ctx = WithPermissionMode(ctx, PermissionReadOnly)
			}
			if _, err := f.env.svc.ResolveDispatched(ctx, f.exact, f.id); !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatal("超时或当前只读模式没有阻止写权限")
			}
		})
	}
}

func TestDispatchedContextRechecksRealUserRoleAndServiceAccount(t *testing.T) {
	for _, service := range []bool{false, true} {
		t.Run(map[bool]string{false: "user_role", true: "service_revoked"}[service], func(t *testing.T) {
			f := newDispatchedFixture(t)
			who := f.human
			var account authz.CreatedServiceAccount
			if service {
				if err := f.env.db.Update(f.env.ctx, func(tx *storage.Tx) error {
					var err error
					account, err = f.authz.CreateServiceAccount(f.env.ctx, tx, authz.CreateServiceAccountInput{Actor: f.human, Name: "dnc-renewal-fixture", Role: authz.RoleOperator})
					return err
				}); err != nil {
					t.Fatal(err)
				}
				who = f.authenticate(t, account.Token)
			}
			f.start(t, who, PlacementNode)
			initial, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
			initial.Clear()
			if err != nil {
				t.Fatal(err)
			}
			if err := f.env.db.Update(f.env.ctx, func(tx *storage.Tx) error {
				if service {
					return f.authz.RevokeServiceAccount(f.env.ctx, tx, authz.RevokeServiceAccountInput{Actor: f.human, ServiceAccountID: account.ID, ExpectedRevision: account.Revision})
				}
				_, err := tx.ExecContext(f.env.ctx, `UPDATE users SET role = 'viewer' WHERE user_id = ?`, f.human.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id); !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatal("真实角色或服务账号撤销没有立即生效")
			}
		})
	}
}

func TestDispatchedContextRechecksRealDelegationAndPolicyTightening(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "policy_tightened", true: "delegation_revoked"}[revoke], func(t *testing.T) {
			f := newDispatchedFixture(t)
			delegation := f.delegation(t)
			f.start(t, f.authenticate(t, delegation.Token), PlacementNode)
			initial, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
			initial.Clear()
			if err != nil {
				t.Fatal(err)
			}
			if err := f.env.db.Update(f.env.ctx, func(tx *storage.Tx) error {
				if revoke {
					return f.authz.RevokeDelegation(f.env.ctx, tx, authz.RevokeDelegationInput{Actor: f.human, DelegationID: delegation.ID, ExpectedRevision: delegation.Revision})
				}
				policy := authz.DefaultPolicy()
				policy.AutoApproveMaxRisk = "none"
				_, err := f.authz.UpdateDelegation(f.env.ctx, tx, authz.UpdateDelegationInput{Actor: f.human, DelegationID: delegation.ID, ExpectedRevision: delegation.Revision, Policy: &policy})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id); err == nil {
				t.Fatal("真实委托撤销或自动执行策略收紧没有阻止后续调用")
			}
		})
	}
}
