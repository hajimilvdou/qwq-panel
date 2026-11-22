// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/controller/testfixtures"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实登录与本次私有事务能力 ========================

func renewalBootstrapFixture(t *testing.T) (*Controller, actor.Actor, hostauth.RenewalServiceRequest) {
	t.Helper()
	c, _ := newVisibilityController(t)
	token, _, err := c.id.NewSetupToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	login, err := c.id.CompleteSetup(t.Context(), identity.CompleteSetupInput{SetupToken: token, Username: "renewal-admin", Password: rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	who, _, err := c.id.AuthenticateSession(t.Context(), login.Token)
	if err != nil {
		t.Fatal(err)
	}
	request := testfixtures.RenewalRequest()
	if err := c.SetRenewalPolicySource(testfixtures.PolicySource(func(ctx context.Context, _ actor.Actor, policyID, revision string) (hostauth.RenewalServiceRequest, error) {
		if err := ctx.Err(); err != nil {
			return hostauth.RenewalServiceRequest{}, err
		}
		if policyID != request.PolicyID || revision != "revision1" {
			return hostauth.RenewalServiceRequest{}, problem.New(problem.StateConflict, "fixture revision changed")
		}
		return request, nil
	})); err != nil {
		t.Fatal(err)
	}
	return c, who, request
}

func renewalProofContext(ctx context.Context, c *Controller, tx *storage.Tx, who actor.Actor, request hostauth.RenewalServiceRequest) (context.Context, context.CancelFunc) {
	lifetime, release := context.WithCancel(ctx)
	proof := &renewalBootstrapExecution{source: c.renewalServices, tx: tx, who: who, prepared: request,
		holder: c.renewalPolicies.Load(), lifetime: lifetime}
	return context.WithValue(ctx, renewalBootstrapKey{}, proof), release
}

func createRenewalFixtureAccount(t *testing.T, c *Controller, who actor.Actor, request hostauth.RenewalServiceRequest) string {
	t.Helper()
	var id string
	if err := c.db.Update(t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: who})
		ctx, release := renewalProofContext(t.Context(), c, tx, who, request)
		defer release()
		var err error
		id, err = c.renewalServices.EnsureRenewalService(ctx, who, request)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func approvedRenewalOperation(t *testing.T, c *Controller, who actor.Actor, request hostauth.RenewalServiceRequest) *operations.Operation {
	t.Helper()
	args := hostauth.RenewalBootstrapArgs{PolicyID: request.PolicyID, ExpectedRevision: "revision1"}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	response, err := c.ops.Run(t.Context(), operations.RunRequest{Actor: who, NodeID: "local", Action: hostauth.RenewalBootstrapAction,
		Target: operations.Target{Subject: args.Subject()}, Args: raw,
		Idempotency: operations.Idempotency{Key: "test-renewal-bootstrap-run", Route: "/api/v1/service-accounts/renewal-bootstrap"}})
	if err != nil || response.Operation == nil || response.Operation.Status != operations.AwaitingApproval {
		t.Fatalf("真实创建未进入高风险审批: %v", err)
	}
	approval, err := c.ops.GetApproval(t.Context(), who, response.Operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ops.Decide(t.Context(), operations.DecisionRequest{Actor: who, ApprovalID: approval.ID, Decision: operations.DecisionApprove,
		ExpectedRevision: approval.Revision,
		Idempotency:      operations.Idempotency{Key: "test-renewal-bootstrap-decision", Route: "/api/v1/approvals/" + approval.ID + "/decision"}}); err != nil {
		t.Fatal(err)
	}
	op, err := c.ops.Get(t.Context(), who, response.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestRenewalBootstrapSourceRejectsMissingAlteredAndExpiredProof(t *testing.T) {
	c, who, request := renewalBootstrapFixture(t)
	if _, err := c.RenewalServiceSource().EnsureRenewalService(t.Context(), who, request); !problem.HasCode(err, problem.ApprovalRequired) {
		t.Fatalf("普通调用取得了账号创建能力: %v", err)
	}
	var captured context.Context
	if err := c.db.Update(t.Context(), func(tx *storage.Tx) error {
		ctx, release := renewalProofContext(t.Context(), c, tx, who, request)
		defer release()
		captured = ctx
		altered := who
		altered.SessionID = "different_session"
		if _, err := c.renewalServices.EnsureRenewalService(ctx, altered, request); !problem.HasCode(err, problem.ApprovalRequired) {
			t.Fatalf("私有证明被另一会话借用: %v", err)
		}
		changed := request
		changed.Scope.Consumers = append([]certificates.Consumer(nil), request.Scope.Consumers...)
		changed.Scope.Consumers[0].ProfileID = "different_profile"
		if _, err := c.renewalServices.EnsureRenewalService(ctx, who, changed); !problem.HasCode(err, problem.PermissionDenied) {
			t.Fatalf("私有证明扩大了策略范围: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.renewalServices.EnsureRenewalService(captured, who, request); !problem.HasCode(err, problem.ApprovalRequired) {
		t.Fatalf("已结束的事务证明仍能使用: %v", err)
	}
}

func TestRenewalBootstrapSourceRejectsUncommittedSessionRevocation(t *testing.T) {
	c, who, request := renewalBootstrapFixture(t)
	if err := c.db.Update(t.Context(), func(tx *storage.Tx) error {
		ctx, release := renewalProofContext(t.Context(), c, tx, who, request)
		defer release()
		if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE session_id=?", who.SessionID); err != nil {
			return err
		}
		if _, err := c.renewalServices.EnsureRenewalService(ctx, who, request); !problem.HasCode(err, problem.Unauthenticated) {
			t.Fatalf("同事务会话撤销没有阻止账号创建: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalBootstrapCanonicalScopeRejectsMissingOrForeignFacts(t *testing.T) {
	c, _, request := renewalBootstrapFixture(t)
	for _, test := range []struct {
		name   string
		change func(*hostauth.RenewalServiceRequest)
	}{
		{"owner", func(req *hostauth.RenewalServiceRequest) { req.Scope.OwnerID = "domain.dns" }},
		{"expired", func(req *hostauth.RenewalServiceRequest) { req.ExpiresAt = time.Now().Add(-time.Hour) }},
		{"consumers", func(req *hostauth.RenewalServiceRequest) { req.Scope.Consumers = nil }},
		{"node", func(req *hostauth.RenewalServiceRequest) { req.Scope.Consumers[0].NodeID = "different_node" }},
		{"provider", func(req *hostauth.RenewalServiceRequest) { req.Scope.Issuance.Provider.ZoneName = "different.test" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := testfixtures.RenewalRequest()
			test.change(&req)
			if _, err := c.renewalServices.canonicalRequest(req); !problem.HasCode(err, problem.PermissionDenied) {
				t.Fatalf("缺失或外部事实仍被接纳: %v", err)
			}
		})
	}
	canonical, err := c.renewalServices.canonicalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Scope.Issuance.Spec.SANs[0] = "changed.example.test"
	request.Scope.Consumers[0].ProfileID = "changed_profile"
	if canonical.Scope.Issuance.Spec.SANs[0] != "proxy.example.test" || canonical.Scope.Consumers[0].ProfileID != "h2_fixture" {
		t.Fatal("已确认范围仍共享外部可变切片")
	}
}

func TestRenewalBootstrapCreationAuditAndEventsRollbackTogether(t *testing.T) {
	c, who, request := renewalBootstrapFixture(t)
	executed := false
	c.ops.RegisterHostAction(hostauth.RenewalBootstrapAction, func(ctx context.Context, tx *storage.Tx, req operations.HostRequest) (json.RawMessage, error) {
		if _, err := c.executeRenewalBootstrap(ctx, tx, req); err != nil {
			return nil, err
		}
		executed = true
		return nil, problem.New(problem.Unavailable, "fixture rollback after account and audit")
	}, c.planRenewalBootstrap)
	op := approvedRenewalOperation(t, c, who, request)
	if !executed || op.Status != operations.Failed {
		t.Fatalf("没有实际执行并回滚创建: %s", op.Status)
	}
	for _, query := range []string{
		"SELECT COUNT(*) FROM service_accounts",
		"SELECT COUNT(*) FROM event_journal WHERE subject LIKE 'service_accounts/%'",
		"SELECT COUNT(*) FROM audit_log WHERE action='host.service_accounts.renewal_bootstrap' AND subject LIKE 'service_accounts/%' AND outcome='success'",
	} {
		var count int
		if err := c.db.Reader().QueryRowContext(t.Context(), query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatal("失败事务留下了账号、资源事件或成功审计")
		}
	}
}

func TestRenewalBootstrapExistingAccountRequiresExactCreatorScopeAndState(t *testing.T) {
	for _, test := range []struct{ name, mutation string }{
		{"role", "UPDATE service_accounts SET role='admin' WHERE service_id=?"},
		{"disabled", "UPDATE service_accounts SET disabled=1 WHERE service_id=?"},
		{"creator", "UPDATE service_accounts SET created_by=? WHERE service_id=?"},
		{"scope", "UPDATE service_accounts SET scope_json=NULL WHERE service_id=?"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, who, request := renewalBootstrapFixture(t)
			id := createRenewalFixtureAccount(t, c, who, request)
			params := []any{id}
			if test.name == "creator" {
				other := createVisibilityUser(t, c, "renewal-other-creator", identity.RoleAdmin)
				params = []any{other.ID, id}
			}
			if err := c.db.Update(t.Context(), func(tx *storage.Tx) error {
				if _, err := tx.ExecContext(t.Context(), test.mutation, params...); err != nil {
					return err
				}
				ctx, release := renewalProofContext(t.Context(), c, tx, who, request)
				defer release()
				if _, err := c.renewalServices.EnsureRenewalService(ctx, who, request); !problem.HasCode(err, problem.StateConflict) {
					t.Fatalf("冲突账号被复用或静默扩大: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
