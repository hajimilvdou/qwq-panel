// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/contextbudget"
)

// ======================== 当次真人请求；没有持久化或跨执行恢复渠道 ========================

type interactiveHostKey struct{}

type interactiveHostSession struct {
	owner         *Service
	lifetime      context.Context
	actor         actor.Actor
	requestActor  actor.Actor
	approvalID    string
	requestDigest [sha256.Size]byte
}

func (interactiveHostSession) String() string { return "operations.interactiveHostSession{[REDACTED]}" }
func (interactiveHostSession) GoString() string {
	return "operations.interactiveHostSession{[REDACTED]}"
}

// InteractiveActor 只在同一次同步宿主执行中返回当前真人会话。
// 请求换用、回调结束或序列化恢复后返回空值；创建账号仍须核验真实 session/RBAC。
func (r HostRequest) InteractiveActor() (actor.Actor, bool) {
	session := r.interactive
	if session == nil || !session.matches(r) {
		return actor.Actor{}, false
	}
	return session.actor, true
}

func interactiveRequestDigest(request HostRequest) ([sha256.Size]byte, error) {
	raw, err := json.Marshal(struct {
		Request    HostRequest     `json:"request"`
		ArgsSchema json.RawMessage `json:"args_schema"`
	}{Request: request, ArgsSchema: request.Action.ArgsSchema})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer clear(raw)
	return sha256.Sum256(raw), nil
}

func (session *interactiveHostSession) matches(request HostRequest) bool {
	if session == nil || session.owner == nil || session.lifetime == nil || session.lifetime.Err() != nil ||
		!session.actor.IsHumanSession() || request.Action.Source != HostSource || request.Action.Mode != ModeInvoke ||
		request.Actor != session.requestActor {
		return false
	}
	digest, err := interactiveRequestDigest(request)
	return err == nil && digest == session.requestDigest
}

func (s *Service) interactiveHostContext(ctx context.Context, op *Operation, who actor.Actor) (context.Context, context.CancelFunc) {
	if ctx == nil || s == nil || op == nil || !who.IsHumanSession() || who.Valid() != nil ||
		op.Mode != ModeInvoke || op.Meta.Mode != ModeInvoke || op.Meta.Source != HostSource || op.Timeout <= 0 {
		return ctx, func() {}
	}
	request := s.hostRequest(op)
	digest, err := interactiveRequestDigest(request)
	if err != nil {
		return ctx, func() {}
	}
	lifetime, release := contextbudget.Detached(ctx, op.Timeout)
	session := &interactiveHostSession{owner: s, lifetime: lifetime, actor: who,
		requestActor: request.Actor, approvalID: op.ApprovalID, requestDigest: digest}
	return context.WithValue(ctx, interactiveHostKey{}, session), release
}

func (s *Service) interactiveHostRequest(ctx context.Context, op *Operation) HostRequest {
	if op == nil {
		return HostRequest{}
	}
	request := s.hostRequest(op)
	if ctx == nil || s == nil || op.Mode != ModeInvoke {
		return request
	}
	session, ok := ctx.Value(interactiveHostKey{}).(*interactiveHostSession)
	if ok && session != nil && session.owner == s && session.approvalID == op.ApprovalID && session.matches(request) {
		request.interactive = session
	}
	return request
}

func (s *Service) executeApproved(ctx context.Context, op *Operation, who actor.Actor) error {
	interactiveCtx, release := s.interactiveHostContext(ctx, op, who)
	defer release()
	return s.executeCreated(interactiveCtx, op)
}
