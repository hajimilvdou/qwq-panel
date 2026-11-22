// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实持久审批；身份 fixture 与数据库事实分开 ========================

func TestInteractiveHostDirectUsesCurrentHumanSession(t *testing.T) {
	e := newTestEnv(t)
	var captured HostRequest
	e.svc.RegisterHostAction(actionWrite, func(ctx context.Context, tx *storage.Tx, req HostRequest) (json.RawMessage, error) {
		captured = req
		who, ok := req.InteractiveActor()
		if !ok || who != humanMFA() {
			t.Fatal("同步宿主调用丢失当前人类会话")
		}
		return e.writeResource(ctx, tx, req)
	}, nil)
	response, err := e.run(humanMFA(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "direct"})
	if err != nil || response.Operation.Status != Succeeded {
		t.Fatalf("同步宿主调用未完成: %v", err)
	}
	if _, ok := captured.InteractiveActor(); ok {
		t.Fatal("已结束的同步事务仍可取得会话")
	}
}

func TestInteractiveHostApprovalUsesCurrentRequestAndExpires(t *testing.T) {
	e := newTestEnv(t)
	var captured HostRequest
	calls := 0
	e.svc.RegisterHostAction(actionHigh, func(ctx context.Context, tx *storage.Tx, req HostRequest) (json.RawMessage, error) {
		captured = req
		calls++
		who, ok := req.InteractiveActor()
		if !ok || who != humanMFA() || req.Actor.SessionID != "" || req.Actor.MFA {
			t.Fatal("当前审批身份与持久操作者混淆")
		}
		raw, err := json.Marshal(req)
		if err != nil || strings.Contains(string(raw), humanMFA().SessionID) || strings.Contains(string(raw), "interactive") {
			t.Fatal("同步身份进入序列化结果")
		}
		return e.writeResource(ctx, tx, req)
	}, nil)
	response, err := e.run(humanActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "confirmed"})
	if err != nil || response.Operation.Status != AwaitingApproval || calls != 0 {
		t.Fatalf("高风险规则被放宽: %v", err)
	}
	request := DecisionRequest{Actor: humanMFA(), ApprovalID: response.Operation.ApprovalID, Decision: DecisionApprove,
		Idempotency: Idempotency{Key: e.newKey(), Route: "/api/v1/approvals/" + response.Operation.ApprovalID + "/decision"}}
	if _, err := e.svc.Decide(e.ctx, request); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || e.operation(response.Operation.ID).Status != Succeeded {
		t.Fatal("真实批准后没有完成一次宿主事务")
	}
	if _, ok := captured.InteractiveActor(); ok {
		t.Fatal("审批请求结束后仍可取得人类会话")
	}
	approval := e.approval(response.Operation.ApprovalID)
	if approval.DecidedBy == nil || approval.DecidedBy.SessionID != "" || approval.DecidedBy.MFA {
		t.Fatal("持久批准记录保存了可恢复的会话")
	}
	if _, err := e.svc.Decide(e.ctx, request); err != nil || calls != 1 {
		t.Fatalf("同幂等批准重放触发了新执行: %v", err)
	}
}

// ======================== 换用请求、Service、后台类型和重启全部拒绝 ========================

func TestInteractiveHostSessionRejectsChangedRequestAndOtherService(t *testing.T) {
	e := newTestEnv(t)
	e.svc.RegisterHostAction(actionHigh, func(ctx context.Context, tx *storage.Tx, req HostRequest) (json.RawMessage, error) {
		op, err := loadOperation(ctx, tx, req.OperationID)
		if err != nil {
			return nil, err
		}
		for _, change := range []func(*HostRequest){
			func(r *HostRequest) { r.OperationID += "-other" },
			func(r *HostRequest) { r.Attempt++ },
			func(r *HostRequest) { r.Action.Permission = "test:other" },
			func(r *HostRequest) { r.Target.Subject += "-other" },
			func(r *HostRequest) { r.ExpectedRevision += "-other" },
			func(r *HostRequest) { r.Args = json.RawMessage("{}") },
			func(r *HostRequest) { r.Actor = actor.SystemActor("other") },
			func(r *HostRequest) { r.Actor.SessionID = "ses_other" },
			func(r *HostRequest) { r.Actor.MFA = !r.Actor.MFA },
			func(r *HostRequest) { r.Action.ArgsSchema = json.RawMessage("{}") },
			func(r *HostRequest) {
				r.Action.Capabilities = []Capability{{Name: "system.certificates.manage", Scope: "local"}}
			},
		} {
			changed := req
			change(&changed)
			if _, ok := changed.InteractiveActor(); ok {
				t.Fatal("换用完整请求后仍可以取得会话")
			}
		}
		other := &Service{}
		if _, ok := other.interactiveHostRequest(ctx, op).InteractiveActor(); ok {
			t.Fatal("另一 Service 复用了当次会话")
		}
		for _, change := range []func(*Operation){
			func(o *Operation) { o.ApprovalID += "-other" },
			func(o *Operation) { o.Mode = ModeJob },
			func(o *Operation) { o.Meta.Source = PluginSource },
		} {
			changed := *op
			change(&changed)
			if _, ok := e.svc.interactiveHostRequest(ctx, &changed).InteractiveActor(); ok {
				t.Fatal("审批、后台任务或插件换用了同步身份")
			}
		}
		if _, ok := e.svc.hostRequest(op).InteractiveActor(); ok {
			t.Fatal("普通请求构造器泄漏了同步身份")
		}
		if _, ok := e.svc.interactiveHostRequest(context.Background(), op).InteractiveActor(); ok {
			t.Fatal("重启恢复从持久记录补造了会话")
		}
		return e.writeResource(ctx, tx, req)
	}, nil)
	response, err := e.run(humanActor(), actionHigh, Target{Subject: resourceSubject}, map[string]any{"value": "bound"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.decide(humanMFA(), response.Operation.ApprovalID, DecisionApprove); err != nil {
		t.Fatal(err)
	}
	if e.operation(response.Operation.ID).Status != Succeeded {
		t.Fatal("范围矩阵未真正进入宿主执行")
	}
}

func TestInteractiveHostSessionPreservesDeadlineAndRejectsNilProof(t *testing.T) {
	e := newTestEnv(t)
	e.svc.RegisterHostAction(actionWrite, func(ctx context.Context, tx *storage.Tx, req HostRequest) (json.RawMessage, error) {
		op, err := loadOperation(ctx, tx, req.OperationID)
		if err != nil {
			return nil, err
		}
		for _, budget := range []struct {
			name   string
			parent time.Duration
			action time.Duration
		}{
			{"original-parent", 10 * time.Millisecond, time.Second},
			{"operation", time.Second, 10 * time.Millisecond},
		} {
			parent, cancelParent := context.WithTimeout(context.Background(), budget.parent)
			op.Timeout = budget.action
			proofCtx, release := e.svc.interactiveHostContext(parent, op, humanMFA())
			request := e.svc.interactiveHostRequest(proofCtx, op)
			session := request.interactive
			if session == nil {
				release()
				cancelParent()
				t.Fatal("有效预算没有建立当前会话")
			}
			_, bounded := session.lifetime.Deadline()
			if !bounded {
				release()
				cancelParent()
				t.Fatalf("%s 的执行凭据丢弃了有界期限", budget.name)
			}
			select {
			case <-session.lifetime.Done():
			case <-time.After(500 * time.Millisecond):
				release()
				cancelParent()
				t.Fatalf("%s 的执行凭据超过原期限", budget.name)
			}
			if _, ok := request.InteractiveActor(); ok {
				t.Fatal("期限耗尽后仍然取得当前人类会话")
			}
			release()
			cancelParent()
		}
		nilProof := context.WithValue(ctx, interactiveHostKey{}, (*interactiveHostSession)(nil))
		if _, ok := e.svc.interactiveHostRequest(nilProof, op).InteractiveActor(); ok {
			t.Fatal("空私有证明被当成有效身份")
		}
		return e.writeResource(ctx, tx, req)
	}, nil)
	if _, err := e.run(humanMFA(), actionWrite, Target{Subject: resourceSubject}, map[string]any{"value": "deadline"}); err != nil {
		t.Fatal(err)
	}
}
