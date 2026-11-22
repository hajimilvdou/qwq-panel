// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestFailedPluginConfigWriteReclaimsNewSecretCiphertext(t *testing.T) {
	for _, committed := range []bool{false, true} {
		mgr := newFakePluginManager()
		mgr.schemas["com.example.monitor"] = json.RawMessage(`{"properties":{"password":{"x-secret":true}}}`)
		mgr.applyConfigErr = problem.New(problem.StateConflict, "TEST-ONLY-config-write-failure")
		e := newPluginTestEnv(t, mgr)
		if committed {
			mgr.onApply = func(ctx context.Context, req api.ApplyPluginConfigRequest) error {
				return e.c.DB().Update(ctx, func(tx *storage.Tx) error {
					_, err := tx.ExecContext(ctx, `INSERT INTO plugin_configs
					(plugin_id, revision, config_json, created_at) VALUES (?, 1, ?, ?)`,
						req.PluginID, string(req.Config), storage.FormatTime(tx.Now()))
					return err
				})
			}
		}
		who := e.setupAdmin(adminUser)
		var before, after int
		if err := e.c.DB().Reader().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM secrets`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		response := e.do(withIdempotency(who.sign(http.MethodPut,
			"/api/v1/plugins/com.example.monitor/config",
			`{"config":{"password":"TEST-ONLY-failed-secret-write"},"expected_revision":"0"}`), idempotencyKey(87)))
		response.expectProblem(t, http.StatusConflict, problem.StateConflict)
		if mgr.configReq == nil || !bytes.Contains(mgr.configReq.Config, []byte("$secret")) {
			t.Fatal("the fixture did not reach the protected configuration write")
		}
		if bytes.Contains(response.body, []byte("TEST-ONLY-failed-secret-write")) || bytes.Contains(response.body, []byte("$secret")) {
			t.Fatal("a failed configuration response leaked secret material")
		}
		want := before
		if committed {
			want++
		}
		if err := e.c.DB().Reader().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM secrets`).Scan(&after); err != nil || want != after {
			t.Fatal("configuration compensation did not follow the committed snapshot reference")
		}
	}
}
