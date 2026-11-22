// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 本地只读策略源与同步宿主账号入口 ========================

// RenewalPolicySource 每次从宿主私有登记重查当前确认与完整固定范围。
// 实现只读本地状态，不能调用网络、Ensure 或另一写事务。
type RenewalPolicySource interface {
	PrepareRenewalService(context.Context, actor.Actor, string, string) (hostauth.RenewalServiceRequest, error)
}

type renewalPolicyHolder struct{ source RenewalPolicySource }

// SetRenewalPolicySource 在网关接收请求前装配一次真实私有策略源。
func (c *Controller) SetRenewalPolicySource(source RenewalPolicySource) error {
	if c == nil || c.closed.Load() || source == nil {
		return problem.New(problem.Unavailable, "续期策略后端不可用。")
	}
	if !c.renewalPolicies.CompareAndSwap(nil, &renewalPolicyHolder{source: source}) {
		return problem.New(problem.StateConflict, "续期策略后端已经装配。")
	}
	return nil
}

func (c *Controller) RenewalServiceSource() hostauth.RenewalServiceSource {
	if c == nil || c.closed.Load() {
		return nil
	}
	return c.renewalServices
}

func (c *Controller) registerRenewalBootstrap() {
	c.ops.RegisterHostAction(hostauth.RenewalBootstrapAction, c.executeRenewalBootstrap, c.planRenewalBootstrap)
}

func renewalBootstrapArgs(req operations.HostRequest) (hostauth.RenewalBootstrapArgs, error) {
	var args hostauth.RenewalBootstrapArgs
	decoder := json.NewDecoder(bytes.NewReader(req.Args))
	decoder.DisallowUnknownFields()
	if len(req.Args) > 16<<10 || decoder.Decode(&args) != nil {
		return args, problem.Validation(problem.Violation{Pointer: "", Code: "INVALID", Message: "续期账号创建参数无效。"})
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return args, problem.Validation(problem.Violation{Pointer: "", Code: "INVALID", Message: "续期账号参数必须是单个 JSON 对象。"})
	}
	if err := args.Validate(); err != nil {
		return args, err
	}
	if req.Action.ID != hostauth.RenewalBootstrapAction || req.Action.Source != operations.HostSource ||
		(req.Target.Subject != "" && req.Target.Subject != args.Subject()) ||
		(req.ExpectedRevision != "" && req.ExpectedRevision != args.ExpectedRevision) {
		return args, problem.New(problem.PermissionDenied, "续期账号创建与当前宿主动作或策略目标不符。")
	}
	return args, nil
}

func (c *Controller) prepareRenewalBootstrap(ctx context.Context, who actor.Actor, args hostauth.RenewalBootstrapArgs) (hostauth.RenewalServiceRequest, *renewalPolicyHolder, error) {
	holder := c.renewalPolicies.Load()
	if holder == nil || holder.source == nil {
		return hostauth.RenewalServiceRequest{}, nil, problem.New(problem.Unavailable, "续期策略后端尚未装配。")
	}
	prepared, err := holder.source.PrepareRenewalService(ctx, who, args.PolicyID, args.ExpectedRevision)
	if err != nil {
		return hostauth.RenewalServiceRequest{}, nil, renewalBootstrapProblem(err)
	}
	if prepared.PolicyID != args.PolicyID || c.renewalPolicies.Load() != holder {
		return hostauth.RenewalServiceRequest{}, nil, problem.New(problem.PermissionDenied, "续期账号的私有策略来源已经变化。")
	}
	prepared, err = c.renewalServices.canonicalRequest(prepared)
	return prepared, holder, err
}

func (c *Controller) executeRenewalBootstrap(ctx context.Context, tx *storage.Tx, req operations.HostRequest) (json.RawMessage, error) {
	args, err := renewalBootstrapArgs(req)
	if err != nil {
		return nil, err
	}
	if req.Target.NodeID != "" && req.Target.NodeID != c.renewalServices.nodeID {
		return nil, problem.New(problem.PermissionDenied, "续期账号不属于当前实际节点。")
	}
	who, ok := req.InteractiveActor()
	if !ok {
		return nil, problem.New(problem.ApprovalRequired, "续期服务账号必须由当前真实人类会话创建。")
	}
	who, err = c.id.VerifyHumanSessionTx(ctx, tx, who)
	if err != nil {
		return nil, err
	}
	if err := c.auth.AuthorizeHumanTx(ctx, tx, who, "host.service_accounts:create"); err != nil {
		return nil, err
	}
	prepared, holder, err := c.prepareRenewalBootstrap(ctx, who, args)
	if err != nil {
		return nil, err
	}
	lifetime, release := context.WithCancel(ctx)
	defer release()
	proof := &renewalBootstrapExecution{source: c.renewalServices, tx: tx, who: who, prepared: prepared, holder: holder, lifetime: lifetime}
	serviceID, err := c.renewalServices.EnsureRenewalService(context.WithValue(ctx, renewalBootstrapKey{}, proof), who, prepared)
	if err != nil {
		return nil, err
	}
	if err := operations.Audit(ctx, tx, operations.AuditRecord{Actor: who, Action: hostauth.RenewalBootstrapAction,
		Subject: "service_accounts/" + serviceID, Outcome: operations.AuditSuccess, OperationID: req.OperationID,
		TraceID: req.TraceID, RequestID: req.RequestID}); err != nil {
		return nil, err
	}
	return json.Marshal(hostauth.RenewalBootstrapResult{ServiceAccountID: serviceID})
}

func (c *Controller) planRenewalBootstrap(ctx context.Context, _ *sql.Tx, req operations.HostRequest) (operations.Preview, error) {
	args, err := renewalBootstrapArgs(req)
	if err != nil {
		return operations.Preview{}, err
	}
	prepared, _, err := c.prepareRenewalBootstrap(ctx, req.Actor, args)
	if err != nil {
		return operations.Preview{}, err
	}
	after, err := json.Marshal(struct {
		Role  authz.Role          `json:"role"`
		Scope *authz.ServiceScope `json:"scope"`
	}{authz.RoleOperator, c.renewalServices.serviceScope(prepared)})
	if err != nil {
		return operations.Preview{}, err
	}
	// 私有策略版本在 Prepare 与实际创建事务再次复核；不解析为宿主核心表的版本。
	return operations.Preview{Changes: []operations.PlannedChange{{Kind: "create", Subject: "service_accounts", After: after}}}, nil
}

func renewalBootstrapProblem(err error) error {
	if err == nil {
		return nil
	}
	var known *problem.Error
	if errors.As(err, &known) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	code := problem.PermissionDenied
	switch fault.Code(err) {
	case "REVISION_CONFLICT":
		code = problem.StateConflict
	case "NOT_FOUND":
		code = problem.NotFound
	case "APPROVAL_REQUIRED":
		code = problem.ApprovalRequired
	case "BACKEND_REQUIRED", "INTERNAL":
		code = problem.Unavailable
	}
	return problem.New(code, "私有续期策略无法用于当前服务账号创建，请刷新策略状态。")
}
