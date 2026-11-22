// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 全局写权限不能替代回放时的当前对象归属 ========================

func TestCatalogReplayKeepsCurrentDelegationOwnerBoundary(t *testing.T) {
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		for _, ownership := range []string{"own", "foreign"} {
			t.Run(method+"/"+ownership, func(t *testing.T) {
				e := newEnv(t)
				admin := e.setupAdmin(adminUser)
				e.insertUser("keeper", identity.RoleAdmin, adminPass)
				owner := admin
				if ownership == "foreign" {
					owner = e.signIn("bobby", identity.RoleOperator)
				}
				create := owner.sign(http.MethodPost, "/api/v1/delegations", `{"label":"owned delegation"}`)
				create.Header.Set("Idempotency-Key", idempotencyKey(708))
				delegation := e.do(create).expect(t, http.StatusCreated).decodeMap(t)
				id, revision := mustString(t, delegation, "delegation_id"), mustString(t, delegation, "revision")
				path, body, status := "/api/v1/delegations/"+id, "", http.StatusNoContent
				if method == http.MethodPatch {
					body = `{"expected_revision":"` + revision + `","status":"suspended"}`
					status = http.StatusOK
				} else {
					path += "?expected_revision=" + revision
				}
				write := func() response {
					req := admin.sign(method, path, body)
					req.Header.Set("Idempotency-Key", idempotencyKey(709))
					return e.do(req)
				}
				write().expect(t, status)
				current, err := e.c.Identity().User(t.Context(), admin.userID)
				if err != nil {
					t.Fatal(err)
				}
				role := identity.RoleOperator
				if err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
					_, err := e.c.Identity().UpdateUser(t.Context(), tx, identity.UpdateUserInput{
						UserID: admin.userID, ExpectedRevision: current.Revision, Role: &role,
					})
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if ownership == "foreign" {
					e.do(admin.sign(http.MethodGet, "/api/v1/delegations/"+id, "")).expectProblem(t, http.StatusNotFound, problem.NotFound)
					write().expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
					return
				}
				// 保留本人范围；删除后数据库行已不存在，仍须安全回放同一 204。
				replay := write().expect(t, status)
				if replay.header.Get("Idempotency-Replayed") != "true" {
					t.Fatal("a still-authorized owner could not replay the completed request")
				}
				if method == http.MethodDelete {
					requireCatalogCount(t, e, "SELECT COUNT(*) FROM delegations", 0)
					if len(replay.body) != 0 {
						t.Fatal("a deletion replay exposed its private ownership facts")
					}
				}
			})
		}
	}
}
