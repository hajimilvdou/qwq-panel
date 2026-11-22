// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== Track 08 P4：多节点入网令牌、列表与吊销 API 测试 ========================

func TestClusterNodesEnrollmentTokenListAndRevoke(t *testing.T) {
	var kicked []string
	e := newEnvWith(t, func(d *api.Deps) {
		d.ClusterCAHash = func() string { return "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" }
		d.NodeRevoker = func(nodeID string) { kicked = append(kicked, nodeID) }
	})
	admin := e.setupAdmin(adminUser)
	viewer := e.signIn("node-viewer", identity.RoleViewer)

	// 1. Viewer 不可签发入网令牌或吊销节点。
	reqV := viewer.sign(http.MethodPost, "/api/v1/nodes/enrollment-tokens", `{"preset_name":"edge-hk","mode":"probe_512m"}`)
	reqV.Header.Set("Idempotency-Key", idempotencyKey(1))
	e.do(reqV).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// 2. 非法 mode 拦截。
	reqBad := admin.sign(http.MethodPost, "/api/v1/nodes/enrollment-tokens", `{"preset_name":"edge-hk","mode":"invalid"}`)
	reqBad.Header.Set("Idempotency-Key", idempotencyKey(2))
	e.do(reqBad).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// 3. 管理员签发 probe_512m 单次入网令牌。
	reqTok := admin.sign(http.MethodPost, "/api/v1/nodes/enrollment-tokens", `{"preset_name":"edge-hk","mode":"probe_512m","ttl_seconds":900}`)
	reqTok.Header.Set("Idempotency-Key", idempotencyKey(3))
	tokResp := e.do(reqTok).expect(t, http.StatusCreated).decodeMap(t)
	tok, _ := tokResp["token"].(string)
	if !strings.HasPrefix(tok, "qwq_enroll_") {
		t.Fatalf("unexpected enrollment token = %q", tok)
	}
	if tokResp["mode"] != "probe_512m" || !strings.HasPrefix(tokResp["ca_spki_sha256"].(string), "sha256:") {
		t.Fatalf("unexpected token response: %v", tokResp)
	}

	// 4. 插入一个已入网的远端节点并验证 GET /api/v1/nodes 和 GET /api/v1/nodes/{id}。
	nowMs := time.Now().UTC().UnixMilli()
	if err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `
INSERT INTO nodes (id, name, mode, enrollment_state, cert_serial, cert_fingerprint, cert_expires_at,
                   agent_version, arch, public_addrs_json, last_heartbeat_at, last_ack_seq, revision, created_at, updated_at)
VALUES ('node_hk1', 'edge-hk', 'probe_512m', 'active', 'aa11', 'fp11', ?, '0.2.0', 'linux/amd64', '["203.0.113.20"]', ?, 5, 'nrev_1', ?, ?)`,
			nowMs+int64(30*24*time.Hour/time.Millisecond), nowMs, nowMs, nowMs,
		)
		return err
	}); err != nil {
		t.Fatalf("seed remote node: %v", err)
	}

	listResp := e.do(viewer.sign(http.MethodGet, "/api/v1/nodes", "")).expect(t, http.StatusOK).decodeMap(t)
	items := listResp["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("expected 2 nodes (local + node_hk1), got %d: %v", len(items), items)
	}
	remote := e.do(viewer.sign(http.MethodGet, "/api/v1/nodes/node_hk1", "")).expect(t, http.StatusOK).decodeMap(t)
	if remote["status"] != "online" || remote["mode"] != "probe_512m" || remote["enrollment_state"] != "active" {
		t.Fatalf("unexpected remote node: %v", remote)
	}

	// 5. 不允许吊销 local 节点。
	reqLocal := admin.sign(http.MethodPost, "/api/v1/nodes/local/revoke", "")
	reqLocal.Header.Set("Idempotency-Key", idempotencyKey(4))
	e.do(reqLocal).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// 6. 吊销远端节点应落库为 revoked 并立即触发 NodeRevoker 踢断回调。
	reqRevoke := admin.sign(http.MethodPost, "/api/v1/nodes/node_hk1/revoke", "")
	reqRevoke.Header.Set("Idempotency-Key", idempotencyKey(5))
	revResp := e.do(reqRevoke).expect(t, http.StatusOK).decodeMap(t)
	if revResp["enrollment_state"] != "revoked" {
		t.Fatalf("revoke response = %v", revResp)
	}
	if len(kicked) != 1 || kicked[0] != "node_hk1" {
		t.Fatalf("kicked = %v, want [node_hk1]", kicked)
	}

	remoteAfter := e.do(admin.sign(http.MethodGet, "/api/v1/nodes/node_hk1", "")).expect(t, http.StatusOK).decodeMap(t)
	if remoteAfter["status"] != "revoked" {
		t.Fatalf("expected revoked status after revoke, got %v", remoteAfter)
	}
}
