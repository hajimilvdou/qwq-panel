// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== Track 06：服务账号通用 CRUD API 测试 ========================

func TestServiceAccountsCRUDAndScopeGuard(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin(adminUser)
	viewer := e.signIn("sa-viewer", identity.RoleViewer)

	// Viewer 不可列出、创建或吊销服务账号。
	e.do(viewer.sign(http.MethodGet, "/api/v1/service-accounts", "")).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	reqV := viewer.sign(http.MethodPost, "/api/v1/service-accounts", `{"name":"ci-bot","role":"viewer"}`)
	reqV.Header.Set("Idempotency-Key", idempotencyKey(1))
	e.do(reqV).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// 含通配符 * 的 scope 必须被 ADR-0026 校验拦截。
	exp := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	reqWild := admin.sign(http.MethodPost, "/api/v1/service-accounts", `{
		"name":"wild-bot",
		"role":"operator",
		"scope":{
			"actions":["host.*"],
			"node_ids":["local"],
			"subjects":["nodes/local/plugins/tls.certificates"],
			"expires_at":"`+exp+`"
		}
	}`)
	reqWild.Header.Set("Idempotency-Key", idempotencyKey(2))
	e.do(reqWild).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// 管理员创建精确作用域服务账号：单次返回 token。
	reqCreate := admin.sign(http.MethodPost, "/api/v1/service-accounts", `{
		"name":"acme-helper",
		"role":"operator",
		"scope":{
			"actions":["tls.certificates/cert.renew"],
			"node_ids":["local"],
			"subjects":["nodes/local/plugins/tls.certificates/instances/default"],
			"expires_at":"`+exp+`"
		}
	}`)
	reqCreate.Header.Set("Idempotency-Key", idempotencyKey(3))
	created := e.do(reqCreate).expect(t, http.StatusCreated).decodeMap(t)
	tok, _ := created["token"].(string)
	if !strings.HasPrefix(tok, "qwq_sa_") {
		t.Fatalf("unexpected service account token = %q", tok)
	}
	id, _ := created["id"].(string)
	rev, _ := created["revision"].(string)
	if id == "" || rev == "" {
		t.Fatalf("created missing id/revision: %v", created)
	}

	// GET 列表绝不泄露 token 明文。
	listed := e.do(admin.sign(http.MethodGet, "/api/v1/service-accounts", "")).
		expect(t, http.StatusOK).decodeMap(t)
	items := listed["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("listed items = %d, want 1", len(items))
	}
	first := items[0].(map[string]any)
	if _, leaked := first["token"]; leaked {
		t.Fatalf("GET /api/v1/service-accounts leaked token field: %v", first)
	}
	if first["name"] != "acme-helper" || first["status"] != "active" {
		t.Fatalf("unexpected listed item: %v", first)
	}

	// DELETE 携带过期 revision 返回 409 REVISION_CONFLICT。
	reqBadDel := admin.sign(http.MethodDelete, "/api/v1/service-accounts/"+id+"?expected_revision=99999", "")
	reqBadDel.Header.Set("Idempotency-Key", idempotencyKey(4))
	e.do(reqBadDel).expectProblem(t, http.StatusConflict, problem.RevisionConflict)

	// DELETE 携带正确 revision 成功吊销。
	reqDel := admin.sign(http.MethodDelete, "/api/v1/service-accounts/"+id+"?expected_revision="+rev, "")
	reqDel.Header.Set("Idempotency-Key", idempotencyKey(5))
	e.do(reqDel).expect(t, http.StatusNoContent)

	listedAfter := e.do(admin.sign(http.MethodGet, "/api/v1/service-accounts", "")).
		expect(t, http.StatusOK).decodeMap(t)
	if len(listedAfter["items"].([]any)) != 0 {
		t.Fatalf("expected 0 service accounts after revoke, got %v", listedAfter["items"])
	}
}
