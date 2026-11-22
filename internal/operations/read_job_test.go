// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 显式只读 job：复用真实 SQLite / 身份 / RBAC fixture ========================

func newReadJobFixture(t *testing.T) *dispatchedFixture {
	t.Helper()
	f := newDispatchedFixture(t)
	f.human.SessionID, f.human.MFA = "", false
	f.env.setAction(actionJob, func(action *Action) {
		action.Effect, action.Risk, action.Permission = EffectRead, RiskLow, pluginID+":read"
		action.Approval = ApprovalAuto
	})
	return f
}

func TestReadJobRunsWithReadOnlyPermissionAndRealDispatch(t *testing.T) {
	f := newReadJobFixture(t)
	e := f.env
	if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(e.ctx, "UPDATE users SET role = 'viewer', revision = revision + 1 WHERE user_id = ?", f.human.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.ctx = WithPermissionMode(e.ctx, PermissionReadOnly)
	f.start(t, f.human, PlacementController)
	snapshot, err := e.svc.ResolveDispatched(e.ctx, f.exact, f.id)
	defer snapshot.Clear()
	if err != nil || snapshot.Action.Effect != EffectRead || snapshot.Action.Mode != ModeJob || snapshot.Actor.SessionID != "" {
		t.Fatalf("真实只读派发上下文无效：%v", err)
	}
	op, err := e.svc.Get(e.ctx, f.human, f.id)
	if err != nil || op.Status != Running || op.PermissionMode != PermissionReadOnly || e.countOperations() != 1 {
		t.Fatalf("显式只读 job 未持久 RUNNING：%v", err)
	}
	e.setAction(actionPlugin, func(action *Action) { action.Permission = pluginID + ":read" })
	_, err = e.run(f.human, actionPlugin, nodeTarget(), nil)
	if !problem.HasCode(err, problem.PermissionDenied) {
		t.Fatalf("只读模式接受写动作：%v", err)
	}
}

func TestReadJobIdempotencyReplaysWithoutAnotherDispatch(t *testing.T) {
	f := newReadJobFixture(t)
	f.start(t, f.human, PlacementController)
	e := f.env
	var key, method, route string
	if err := e.db.Reader().QueryRowContext(e.ctx, "SELECT key, method, route FROM idempotency_keys WHERE operation_id = ?", f.id).Scan(&key, &method, &route); err != nil {
		t.Fatal(err)
	}
	snapshot, err := e.svc.ResolveDispatched(e.ctx, f.exact, f.id)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Clear()
	response, err := e.svc.Run(e.ctx, RunRequest{Actor: f.human, Action: actionJob, Target: snapshot.Target, Args: snapshot.Args,
		ExpectedRevision: snapshot.ExpectedRevision, Idempotency: Idempotency{Key: key, Method: method, Route: route}})
	if err != nil || !response.Replayed || response.Status != 202 || response.OperationID != f.id || e.countOperations() != 1 {
		t.Fatalf("只读持久 job 幂等重放改变了派发：%v", err)
	}
}

func TestReadJobMissingReadPermissionAndKeyFailClosed(t *testing.T) {
	for _, denial := range []string{"role", "key"} {
		t.Run(denial, func(t *testing.T) {
			f := newReadJobFixture(t)
			e := f.env
			e.setAction(actionJob, func(action *Action) { action.Placement = PlacementController })
			request := RunRequest{Actor: f.human, Action: actionJob, Target: Target{PluginID: pluginID, Subject: "plugins/" + pluginID + "/resources/read"},
				Args: json.RawMessage(`{}`), Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/read-job"}}
			if denial == "key" {
				request.Idempotency.Key = ""
			} else {
				if err := e.db.Update(e.ctx, func(tx *storage.Tx) error {
					_, err := tx.ExecContext(e.ctx, "UPDATE users SET disabled = 1, revision = revision + 1 WHERE user_id = ?", f.human.ID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			_, err := e.svc.Run(e.ctx, request)
			if err == nil || e.countOperations() != 0 {
				t.Fatal("无当前读权限或幂等键仍创建了只读任务")
			}
		})
	}
}

func TestReadJobRejectsNewSecretsBeforePersistence(t *testing.T) {
	f := newReadJobFixture(t)
	e := f.env
	keys, err := secrets.LoadKeyRing(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(secrets.Options{DB: e.db, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.argumentProtector, err = secrets.NewOperationProtector(e.ctx, vault)
	if err != nil {
		t.Fatal(err)
	}
	e.setAction(actionJob, func(action *Action) {
		action.ArgsSchema = json.RawMessage(`{"type":"object","properties":{"material":{"type":"string","x-secret":true}},"additionalProperties":false}`)
	})
	_, err = e.run(f.human, actionJob, nodeTarget(), map[string]any{"material": "new-fixture-material"})
	if !problem.HasCode(err, problem.ValidationFailed) || e.countOperations() != 0 || e.countRows("idempotency_keys") != 0 {
		t.Fatalf("只读 job 持久化了新的秘密材料：%v", err)
	}
}

func TestReadJobCancellationAndDeadlineRevokeDispatch(t *testing.T) {
	for _, terminal := range []string{"cancel", "deadline"} {
		t.Run(terminal, func(t *testing.T) {
			f := newReadJobFixture(t)
			f.start(t, f.human, PlacementController)
			e := f.env
			if terminal == "cancel" {
				_, err := e.svc.Cancel(e.ctx, CancelRequest{Actor: f.human, OperationID: f.id,
					Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/cancel-read"}})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				e.clock.Advance(6 * time.Second)
			}
			if _, err := e.svc.ResolveDispatched(e.ctx, f.exact, f.id); err == nil {
				t.Fatal("取消或超时后只读 job 派发仍有效")
			}
		})
	}
}

func TestReadJobKeepsParentRiskApprovalRules(t *testing.T) {
	f := newDispatchedFixture(t)
	f.human.SessionID, f.human.MFA = "", false
	f.start(t, f.human, PlacementController)
	e := f.env
	e.setAction(actionRead, func(action *Action) {
		action.Mode, action.Risk, action.Placement = ModeJob, RiskHigh, PlacementController
		action.Permission = pluginID + ":read"
	})
	response, err := e.svc.Run(context.Background(), RunRequest{Actor: f.human, Action: actionRead,
		Target: Target{PluginID: pluginID, Subject: "plugins/" + pluginID + "/resources/read"}, Args: json.RawMessage(`{}`), ParentOperationID: f.id,
		Idempotency: Idempotency{Key: e.newKey(), Method: "POST", Route: "/fixture/child-read"}})
	if err != nil || response.Operation.Status != AwaitingApproval || response.Operation.ApprovalID == "" {
		t.Fatalf("更高风险子读任务跳过了原审批规则：%v", err)
	}
}

func TestReadJobPreservesSynchronousReadWithoutRecords(t *testing.T) {
	f := newDispatchedFixture(t)
	f.human.SessionID, f.human.MFA = "", false
	e := f.env
	e.setAction(actionRead, func(action *Action) { action.Permission = pluginID + ":read" })
	for range 3 {
		response, err := e.run(f.human, actionRead, nodeTarget(), nil)
		if err != nil || response.Status != 200 || response.OperationID != "" {
			t.Fatalf("同步只读调用语义变化：%v", err)
		}
	}
	if e.countOperations() != 0 || e.countRows("idempotency_keys") != 0 {
		t.Fatal("同步轮询产生持久记录")
	}
}
