// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/controller/testfixtures"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
)

// ======================== 实际网关认证、幂等、审批与同事务账号创建 ========================

const renewalBootstrapPath = "/api/v1/service-accounts/renewal-bootstrap"

func renewalBootstrapBody(t *testing.T, policyID, revision string) string {
	t.Helper()
	raw, err := json.Marshal(hostauth.RenewalBootstrapArgs{PolicyID: policyID, ExpectedRevision: revision})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func submitRenewalBootstrap(t *testing.T, e *env, who auth, body, key string) (string, string) {
	t.Helper()
	req := who.sign(http.MethodPost, renewalBootstrapPath, body)
	req.Header.Set("Idempotency-Key", key)
	out := e.do(req).expect(t, http.StatusAccepted).decodeMap(t)
	return mustString(t, out, "approval_id"), mustString(t, out, "operation_id")
}

func approveRenewalBootstrap(t *testing.T, e *env, who auth, approvalID, operationID, key string) map[string]any {
	t.Helper()
	approval := e.approval(who, approvalID)
	e.decide(who, approvalID, "approve", mustString(t, approval, "revision"), key).expect(t, http.StatusOK)
	return e.do(who.sign(http.MethodGet, "/api/v1/operations/"+operationID, "")).expect(t, http.StatusOK).decodeMap(t)
}

func TestRenewalBootstrapHTTPAuthenticationAndValidation(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin(adminUser)
	body := renewalBootstrapBody(t, "renewal_fixture", "revision1")
	e.do(newRequest(http.MethodPost, renewalBootstrapPath, body)).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
	e.do(admin.sign(http.MethodPost, renewalBootstrapPath, body)).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	csrf := admin.sign(http.MethodPost, renewalBootstrapPath, body)
	csrf.Header.Set("Idempotency-Key", idempotencyKey(301))
	csrf.Header.Del("X-CSRF-Token")
	e.do(csrf).expectProblem(t, http.StatusForbidden, problem.CSRFFailed)
	service := bearer(http.MethodPost, renewalBootstrapPath, body, e.serviceToken(admin))
	service.Header.Set("Idempotency-Key", idempotencyKey(302))
	e.do(service).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	viewer := e.signIn("renewal-viewer", identity.RoleViewer)
	denied := viewer.sign(http.MethodPost, renewalBootstrapPath, body)
	denied.Header.Set("Idempotency-Key", idempotencyKey(303))
	e.do(denied).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	for index, invalid := range []string{
		`{"policy_id":"renewal_fixture"}`,
		`{"policy_id":"../other","expected_revision":"revision1"}`,
		`{"policy_id":"renewal_fixture","expected_revision":"revision1","scope":{"role":"admin"}}`,
		`{"policy_id":"renewal_fixture","policy_id":"other","expected_revision":"revision1"}`,
	} {
		req := admin.sign(http.MethodPost, renewalBootstrapPath, invalid)
		req.Header.Set("Idempotency-Key", idempotencyKey(310+index))
		e.do(req).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	}
}

func TestRenewalBootstrapHTTPApprovalCreatesOnlyExactScopeAndReplays(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin(adminUser)
	request := testfixtures.RenewalRequest()
	var calls atomic.Int32
	if err := e.c.SetRenewalPolicySource(testfixtures.PolicySource(func(ctx context.Context, who actor.Actor, policyID, revision string) (hostauth.RenewalServiceRequest, error) {
		calls.Add(1)
		if ctx.Err() != nil || !who.IsHumanSession() || who.ID != admin.userID || policyID != request.PolicyID || revision != "revision1" {
			return hostauth.RenewalServiceRequest{}, problem.New(problem.PermissionDenied, "fixture scope denied")
		}
		return request, nil
	})); err != nil {
		t.Fatal(err)
	}
	body := renewalBootstrapBody(t, request.PolicyID, "revision1")
	approvalID, operationID := submitRenewalBootstrap(t, e, admin, body, idempotencyKey(330))
	accounts, err := e.c.Authorizer().ListServiceAccounts(t.Context(), 200)
	if err != nil || len(accounts) != 0 {
		t.Fatal("审批前创建了账号")
	}
	beforeExecution := calls.Load()
	approval := e.approval(admin, approvalID)
	if approval["requires_mfa"] != false {
		t.Fatal("创建普通受限账号改变了现有高风险审批策略")
	}
	operation := approveRenewalBootstrap(t, e, admin, approvalID, operationID, idempotencyKey(331))
	if operation["status"] != "SUCCEEDED" {
		t.Fatalf("续期创建未完成: %v", operation["error"])
	}
	result, ok := operation["result"].(map[string]any)
	if !ok || len(result) != 1 {
		t.Fatal("续期创建结果泄露了凭据或私有范围")
	}
	serviceID := mustString(t, result, "service_account_id")
	accounts, err = e.c.Authorizer().ListServiceAccounts(t.Context(), 200)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("账号创建数量错误: %v", err)
	}
	account := accounts[0]
	if account.ID != serviceID || account.CreatedBy != admin.userID || account.Role != authz.RoleOperator || account.Disabled || account.Scope == nil ||
		!account.Scope.ExpiresAt.Equal(request.ExpiresAt) || !slices.Equal(account.Scope.Actions, []string{"tls.certificates/renew_existing"}) ||
		!slices.Equal(account.Scope.NodeIDs, []string{"local"}) || !slices.Equal(account.Scope.Subjects, []string{"plugins/tls.certificates/resources/certificates/" + request.Scope.CertificateID}) {
		t.Fatal("账号超出了原确认的证书、节点、动作、到期时间或创建者范围")
	}
	replay := admin.sign(http.MethodPost, renewalBootstrapPath, body)
	replay.Header.Set("Idempotency-Key", idempotencyKey(330))
	replayed := e.do(replay).expect(t, http.StatusAccepted)
	if replayed.header.Get("Idempotency-Replayed") != "true" || calls.Load() != beforeExecution+1 {
		t.Fatal("重放重复执行了私有账号创建")
	}
	changed := admin.sign(http.MethodPost, renewalBootstrapPath, renewalBootstrapBody(t, "different_policy", "revision1"))
	changed.Header.Set("Idempotency-Key", idempotencyKey(330))
	e.do(changed).expectProblem(t, http.StatusUnprocessableEntity, problem.IdempotencyKeyReused)
	secondApproval, secondOperation := submitRenewalBootstrap(t, e, admin, body, idempotencyKey(332))
	second := approveRenewalBootstrap(t, e, admin, secondApproval, secondOperation, idempotencyKey(333))
	secondResult, ok := second["result"].(map[string]any)
	if !ok || secondResult["service_account_id"] != serviceID {
		t.Fatal("相同私有范围没有复用仍有效的账号")
	}
	accounts, err = e.c.Authorizer().ListServiceAccounts(t.Context(), 200)
	if err != nil || len(accounts) != 1 {
		t.Fatal("不同幂等键重复创建了同范围账号")
	}
}

func TestRenewalBootstrapHTTPMissingPolicyBackendFailsWithoutAccount(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin(adminUser)
	approvalID, operationID := submitRenewalBootstrap(t, e, admin, renewalBootstrapBody(t, "renewal_fixture", "revision1"), idempotencyKey(340))
	operation := approveRenewalBootstrap(t, e, admin, approvalID, operationID, idempotencyKey(341))
	if operation["status"] != "FAILED" {
		t.Fatal("缺私有策略后端仍创建了续期账号")
	}
	accounts, err := e.c.Authorizer().ListServiceAccounts(t.Context(), 200)
	if err != nil || len(accounts) != 0 {
		t.Fatal("后端失败留下了账号")
	}
	if operation["error"] == nil {
		t.Fatal("后端错误没有保存在操作结果中")
	}
}
