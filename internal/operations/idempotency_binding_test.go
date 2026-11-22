// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 绑定事实不随错误分类或错误包装丢失 ========================

func TestBoundIdempotencySurvivesRetryableAndMissingOperationErrors(t *testing.T) {
	for _, code := range []problem.Code{problem.Internal, problem.RateLimited, problem.Unauthenticated, problem.CSRFFailed, problem.ValidationFailed} {
		for _, attachID := range []bool{false, true} {
			name := string(code) + "/missing_id"
			if attachID {
				name = string(code) + "/attached_id"
			}
			t.Run(name, func(t *testing.T) {
				e := newTestEnv(t)
				operation, err := e.run(humanActor(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "one"})
				if err != nil {
					t.Fatal(err)
				}
				claim, _, err := e.svc.claimIdempotency(e.ctx, humanActor(),
					Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/bound"}, fingerprintOf("bound", operation.OperationID))
				if err != nil {
					t.Fatal(err)
				}
				if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
					return bindIdempotency(e.ctx, tx, claim, operation.OperationID)
				}); err != nil {
					t.Fatal(err)
				}
				failure := &problem.Error{Code: code, Detail: "failure after binding"}
				if attachID {
					failure.OperationID = operation.OperationID
				}
				e.svc.finishIdempotency(e.ctx, claim, nil, failure, "req_fixture", "/fixture/bound")
				var bound string
				if err := e.db.Reader().QueryRowContext(e.ctx,
					`SELECT operation_id FROM idempotency_keys WHERE key_id = ?`, claim.keyID).Scan(&bound); err != nil {
					t.Fatalf("bound key was released: %v", err)
				}
				if bound != operation.OperationID || e.countOperations() != 1 {
					t.Fatal("error classification or wrapping lost the original operation binding")
				}
			})
		}
	}
}

func TestUnboundRetryableIdempotencyStillReleases(t *testing.T) {
	e := newTestEnv(t)
	claim, _, err := e.svc.claimIdempotency(e.ctx, humanActor(),
		Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/unbound"}, fingerprintOf("unbound"))
	if err != nil {
		t.Fatal(err)
	}
	e.svc.finishIdempotency(e.ctx, claim, nil, problem.New(problem.RateLimited, "retry later"), "req_fixture", "/fixture/unbound")
	var remaining int
	if err := e.db.Reader().QueryRowContext(e.ctx,
		`SELECT COUNT(*) FROM idempotency_keys WHERE key_id = ?`, claim.keyID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("an unbound retryable failure retained its key")
	}
}
