// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实人类会话、批准、权限与持续执行的 job ========================

const cleanupFixtureAction = "tls.certificates/certificates.issue"
const cleanupFixtureRecord = "original-txt-one"

type cleanupFixtureJob struct {
	ctx      context.Context
	finished chan struct{}
	canceled chan struct{}
	once     sync.Once
}

func (j *cleanupFixtureJob) finish() { j.once.Do(func() { close(j.finished) }) }

type cleanupAuthorityFixture struct {
	*dispatchedFixture
	job     *cleanupFixtureJob
	source  CleanupSource
	started chan *cleanupFixtureJob
	actor   actor.Actor
	revoke  func() error
}

func newCleanupAuthorityFixture(t *testing.T, principal string, approval bool) *cleanupAuthorityFixture {
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
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	defer clear(entropy[:])
	token, _, err := principals.NewSetupToken(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	login, err := principals.CompleteSetup(e.ctx, identity.CompleteSetupInput{SetupToken: token, Username: "cleanup-admin",
		DisplayName: "清理许可测试用户", Password: "Dnc7!" + base64.RawURLEncoding.EncodeToString(entropy[:]), UserAgent: "DNC cleanup fixture"})
	if err != nil {
		t.Fatal(err)
	}
	human, _, err := principals.AuthenticateSession(e.ctx, login.Token)
	if err != nil || !human.IsHumanSession() {
		t.Fatal("真实控制面会话认证失败")
	}
	rbac := &dispatchRBAC{backend: z}
	e.svc.authorizer, e.svc.policy = rbac, dispatchPolicies{backend: z}
	f := &cleanupAuthorityFixture{dispatchedFixture: &dispatchedFixture{env: e, authz: z, rbac: rbac, human: human},
		started: make(chan *cleanupFixtureJob, 2), source: CleanupSource{CertificateID: "certificate-one", IssueAttemptID: "issue-one", DNSAttemptID: "dns-one"}}
	f.actor = f.principal(t, principal)
	meta := Action{ID: cleanupFixtureAction, Summary: "原证书清理许可回归", Effect: EffectWrite, Risk: RiskHigh, Mode: ModeJob,
		Idempotent: true, Permission: "system.certificates:manage", Source: PluginSource, PluginID: "tls.certificates",
		Placement: PlacementController, Operation: "certificates.issue", APIVersion: "1", TimeoutMS: 60000,
		Capabilities: []Capability{{Name: "system.certificates.manage", Scope: "self"}}, Approval: ApprovalConfirm}
	if !approval {
		meta.Approval = ApprovalAuto
		e.ctx = WithPermissionMode(e.ctx, PermissionFull)
	}
	e.catalog.mu.Lock()
	e.catalog.actions[meta.ID] = meta
	e.catalog.mu.Unlock()
	e.dispatcher.jobFn = func(ctx context.Context, _ PluginRunJobRequest, progress func(JobProgress) error) error {
		job := &cleanupFixtureJob{ctx: ctx, finished: make(chan struct{}), canceled: make(chan struct{})}
		select {
		case f.started <- job:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-job.finished:
		case <-ctx.Done():
			close(job.canceled)
			// 模拟 executor 在自身退出前执行补偿清理，不伪造数据库 RUNNING。
			<-job.finished
			return ctx.Err()
		}
		return progress(JobProgress{Completed: true, Result: json.RawMessage(`{"complete":true}`)})
	}
	if err := e.svc.Start(e.ctx); err != nil {
		t.Fatal(err)
	}
	subject := "plugins/tls.certificates/resources/certificates/" + f.source.CertificateID
	response, err := e.run(f.actor, meta.ID, Target{PluginID: "tls.certificates", Subject: subject},
		map[string]any{"certificate_id": f.source.CertificateID, "attempt_id": f.source.IssueAttemptID})
	if err != nil || response == nil || response.Operation == nil {
		t.Fatalf("真实清理源 operation 创建失败：%v", err)
	}
	f.id = response.Operation.ID
	f.exact = DispatchTarget{ActionID: meta.ID, NodeID: "local", PluginID: "tls.certificates", InstanceID: ControllerDispatchInstance, Subject: subject}
	if response.Operation.Status == AwaitingApproval {
		current, err := e.svc.GetApproval(e.ctx, human, response.Operation.ApprovalID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Decide(e.ctx, DecisionRequest{Actor: human, ApprovalID: current.ID, Decision: DecisionApprove,
			ExpectedRevision: current.Revision, Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/cleanup-approve"}}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case f.job = <-f.started:
		t.Cleanup(f.job.finish)
	case <-time.After(5 * time.Second):
		t.Fatal("真实清理源 executor 未派发")
	}
	return f
}

func (f *cleanupAuthorityFixture) principal(t *testing.T, kind string) actor.Actor {
	t.Helper()
	e := f.env
	switch kind {
	case "human":
		return f.human
	case "service":
		var created authz.CreatedServiceAccount
		if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
			var err error
			created, err = f.authz.CreateServiceAccount(e.ctx, tx, authz.CreateServiceAccountInput{Actor: f.human, Name: "cleanup-fixture", Role: authz.RoleAdmin})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		f.revoke = func() error {
			current, err := f.authz.ServiceAccount(e.ctx, created.ID)
			if err != nil {
				return err
			}
			return e.db.Update(e.ctx, func(tx *storage.Tx) error {
				return f.authz.RevokeServiceAccount(e.ctx, tx, authz.RevokeServiceAccountInput{Actor: f.human,
					ServiceAccountID: current.ID, ExpectedRevision: current.Revision})
			})
		}
		who, err := f.authz.AuthenticateBearer(e.ctx, created.Token)
		if err != nil {
			t.Fatal(err)
		}
		return who
	case "delegation":
		created := f.delegation(t)
		f.revoke = func() error {
			current, err := f.authz.Delegation(e.ctx, created.ID)
			if err != nil {
				return err
			}
			return e.db.Update(e.ctx, func(tx *storage.Tx) error {
				return f.authz.RevokeDelegation(e.ctx, tx, authz.RevokeDelegationInput{Actor: f.human,
					DelegationID: current.ID, ExpectedRevision: current.Revision})
			})
		}
		return f.authenticate(t, created.Token)
	default:
		t.Fatal("未知清理主体 fixture")
		return actor.Actor{}
	}
}

func (f *cleanupAuthorityFixture) accepted(t *testing.T) DispatchedContext {
	t.Helper()
	snapshot, err := f.env.svc.ResolveDispatched(f.env.ctx, f.exact, f.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(snapshot.Clear)
	return snapshot
}

func (f *cleanupAuthorityFixture) cancel(t *testing.T) {
	t.Helper()
	e := f.env
	f.waitForTimers(t, 1)
	before := e.clock.Waiters()
	if _, err := e.svc.Cancel(e.ctx, CancelRequest{Actor: f.human, OperationID: f.id,
		Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/cleanup-cancel"}}); err != nil {
		t.Fatal(err)
	}
	f.waitForTimers(t, before+1)
	e.clock.Advance(e.svc.cfg.JobCancelGrace)
	select {
	case <-f.job.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("真实 executor 未观察到取消")
	}
}

func (f *cleanupAuthorityFixture) waitForTimers(t *testing.T, minimum int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.env.clock.Waiters() < minimum && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.env.clock.Waiters() < minimum {
		t.Fatal("真实服务没有注册预期 FakeClock 定时器")
	}
}
