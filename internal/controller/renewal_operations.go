// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 自动续期宿主 Operation 生命周期桥接 ========================

const (
	defaultRenewalOwnerID       = "tls.certificates"
	defaultRenewalStartTimeout  = 10 * time.Second
	defaultRenewalFinishTimeout = 10 * time.Second
	renewalActionID             = "tls.certificates/renew_existing"
	renewalIdempotencyRoute     = "/internal/tls.certificates/renew_existing"
)

// RenewalOperationsOptions 配置自动续期 service operation 调度器所需的宿主后端与超时上限。
type RenewalOperationsOptions struct {
	Operations    *operations.Service
	Authority     *hostauth.Authority
	Runs          *certificates.PrivateRenewalRuns
	NodeID        string
	OwnerID       string        // default "tls.certificates"
	StartTimeout  time.Duration // default 10s
	FinishTimeout time.Duration // default 10s
}

type renewalSlot struct {
	runAttemptID string
	claimed      bool
	started      chan string
	finish       chan string
	done         chan struct{}
}

// RenewalOperations 将证书自动续期的 Begin/Finish 绑定到真实的 scoped service operation 执行器，
// 确保 hostauth.RenewalContexts 始终依托活跃的 DispatchedJobContext 运行并在取消时立即收敛。
type RenewalOperations struct {
	ops           *operations.Service
	authority     *hostauth.Authority
	runs          *certificates.PrivateRenewalRuns
	nodeID        string
	ownerID       string
	startTimeout  time.Duration
	finishTimeout time.Duration

	mu        sync.Mutex
	byAttempt map[string]*renewalSlot
	byOpID    map[string]*renewalSlot
}

// NewRenewalOperations 校验依赖并构造续期 operation 桥接器。
func NewRenewalOperations(opts RenewalOperationsOptions) (*RenewalOperations, error) {
	if opts.Operations == nil || opts.Authority == nil || opts.Runs == nil {
		return nil, fault.New("BACKEND_REQUIRED", "续期 operation 桥接器需要真实 operations、hostauth 与 PrivateRenewalRuns")
	}
	if !names.ID(opts.NodeID) {
		return nil, fault.New("VALIDATION_FAILED", "续期 operation 桥接器需要有效的 node_id")
	}
	ownerID := opts.OwnerID
	if ownerID == "" {
		ownerID = defaultRenewalOwnerID
	}
	if !names.ID(ownerID) {
		return nil, fault.New("VALIDATION_FAILED", "续期 operation 桥接器的 owner_id 无效")
	}
	startTimeout := opts.StartTimeout
	if startTimeout <= 0 {
		startTimeout = defaultRenewalStartTimeout
	}
	finishTimeout := opts.FinishTimeout
	if finishTimeout <= 0 {
		finishTimeout = defaultRenewalFinishTimeout
	}
	return &RenewalOperations{
		ops:           opts.Operations,
		authority:     opts.Authority,
		runs:          opts.Runs,
		nodeID:        opts.NodeID,
		ownerID:       ownerID,
		startTimeout:  startTimeout,
		finishTimeout: finishTimeout,
		byAttempt:     make(map[string]*renewalSlot),
		byOpID:        make(map[string]*renewalSlot),
	}, nil
}

var _ certificates.RenewalOperations = (*RenewalOperations)(nil)

func renewalIdempotencyKey(runAttemptID string) string {
	if len(runAttemptID) >= 16 && len(runAttemptID) <= 128 {
		return runAttemptID
	}
	return "renewal.existing:" + runAttemptID
}

// Begin 使用策略绑定的精确受限服务账号发起真实的 renew_existing 作业，并等待执行器进入 RUNNING。
func (r *RenewalOperations) Begin(ctx context.Context, policyID, policyRevision, runAttemptID string, scope certificates.RenewalScope) (certificates.Caller, error) {
	if r == nil {
		return certificates.Caller{}, fault.New("BACKEND_REQUIRED", "续期 operation 桥接器未初始化")
	}
	if ctx == nil {
		return certificates.Caller{}, fault.New("VALIDATION_FAILED", "续期发起需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return certificates.Caller{}, errors.Join(fault.New("CANCELLED", "续期发起已取消"), err)
	}
	if !names.ID(policyID) || policyRevision == "" || !names.ID(runAttemptID) || !names.ID(scope.CertificateID) {
		return certificates.Caller{}, fault.New("VALIDATION_FAILED", "续期发起缺少有效的 policy、版本或 run_attempt 标识")
	}
	if scope.OwnerID != r.ownerID {
		return certificates.Caller{}, fault.New("POLICY_SCOPE_DENIED", "续期发起 owner 与宿主配置不符")
	}
	serviceID, err := r.authority.ActiveRenewalServiceAccount(ctx, policyID, scope)
	if err != nil {
		return certificates.Caller{}, err
	}
	start, err := r.runs.Starting(ctx, policyID, policyRevision, runAttemptID, scope)
	if err != nil {
		return certificates.Caller{}, err
	}
	argsJSON, err := json.Marshal(hostauth.RenewExistingArgs{
		PolicyID:       policyID,
		PolicyRevision: policyRevision,
		CertificateID:  scope.CertificateID,
		RunAttemptID:   runAttemptID,
		AttemptID:      start.IssueAttemptID,
	})
	if err != nil {
		return certificates.Caller{}, fault.New("STATE_INVALID", "续期 operation 参数编码失败")
	}

	slot := &renewalSlot{
		runAttemptID: runAttemptID,
		started:      make(chan string, 1),
		finish:       make(chan string, 1),
		done:         make(chan struct{}),
	}
	r.mu.Lock()
	if _, exists := r.byAttempt[runAttemptID]; exists {
		r.mu.Unlock()
		return certificates.Caller{}, fault.New("STATE_CONFLICT", "该续期 run_attempt 已有正在启动或运行的宿主 operation")
	}
	r.byAttempt[runAttemptID] = slot
	r.mu.Unlock()

	cleanup := func(opID string) {
		r.mu.Lock()
		if r.byAttempt[runAttemptID] == slot {
			delete(r.byAttempt, runAttemptID)
		}
		if opID != "" && r.byOpID[opID] == slot {
			delete(r.byOpID, opID)
		}
		r.mu.Unlock()
		select {
		case slot.finish <- "failed":
		default:
		}
	}

	subject := "plugins/tls.certificates/resources/certificates/" + scope.CertificateID
	// 后台自动续期已通过 ActiveRenewalServiceAccount 核验人类确认策略与精确受限服务账号；
	// 仅在调用方未显式收紧权限模式时以 PermissionFull 提交受控 renew_existing 插件作业。
	runCtx := ctx
	if _, hasMode := operations.PermissionModeFromContext(ctx); !hasMode {
		runCtx = operations.WithPermissionMode(ctx, operations.PermissionFull)
	}
	resp, err := r.ops.Run(runCtx, operations.RunRequest{
		Actor:            actor.Actor{Kind: actor.Service, ID: serviceID},
		NodeID:           r.nodeID,
		Action:           renewalActionID,
		Target:           operations.Target{PluginID: "tls.certificates", Subject: subject},
		ExpectedRevision: policyRevision,
		Idempotency: operations.Idempotency{
			Key:    renewalIdempotencyKey(runAttemptID),
			Method: "POST",
			Route:  renewalIdempotencyRoute,
		},
		Args: argsJSON,
	})
	if err != nil {
		cleanup("")
		return certificates.Caller{}, err
	}
	if resp == nil || resp.Operation == nil {
		cleanup("")
		return certificates.Caller{}, fault.New("RENEWAL_OPERATION_FAILED", "续期 operation 未返回有效记录")
	}
	op := resp.Operation
	if op.Status != operations.Pending && op.Status != operations.Running && op.Status != operations.Approved {
		cleanup(op.ID)
		return certificates.Caller{}, fault.New("RENEWAL_OPERATION_FAILED", "续期 operation 未进入可执行状态")
	}

	timer := time.NewTimer(r.startTimeout)
	defer timer.Stop()
	select {
	case startedOpID := <-slot.started:
		if startedOpID != op.ID {
			cleanup(startedOpID)
			return certificates.Caller{}, fault.New("RENEWAL_OPERATION_FAILED", "续期执行器返回的 operation 标识不匹配")
		}
	case <-slot.done:
		cleanup(op.ID)
		return certificates.Caller{}, fault.New("RENEWAL_OPERATION_FAILED", "续期执行器在握手完成前已退出")
	case <-ctx.Done():
		cleanup(op.ID)
		return certificates.Caller{}, errors.Join(fault.New("CANCELLED", "等待续期执行器启动已取消"), ctx.Err())
	case <-timer.C:
		cleanup(op.ID)
		return certificates.Caller{}, fault.New("RENEWAL_OPERATION_FAILED", "等待续期执行器启动超时")
	}

	return certificates.Caller{
		OwnerID:        r.ownerID,
		OperationID:    op.ID,
		PolicyID:       policyID,
		PolicyRevision: policyRevision,
	}, nil
}

// HandleJob 仅接管由本 RenewalOperations.Begin 登记的精确续期作业，绝不劫持外部插件调用。
func (r *RenewalOperations) HandleJob(ctx context.Context, req operations.PluginRunJobRequest) (bool, error) {
	if r == nil || req.PluginID != "tls.certificates" || req.Operation != "renew_existing" {
		return false, nil
	}
	var args hostauth.RenewExistingArgs
	if len(req.Payload) == 0 || json.Unmarshal(req.Payload, &args) != nil || !names.ID(args.RunAttemptID) {
		return false, nil
	}
	r.mu.Lock()
	slot, ok := r.byAttempt[args.RunAttemptID]
	if !ok || slot == nil || slot.claimed {
		r.mu.Unlock()
		return false, nil
	}
	slot.claimed = true
	r.byOpID[req.OperationID] = slot
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		if r.byAttempt[args.RunAttemptID] == slot {
			delete(r.byAttempt, args.RunAttemptID)
		}
		if r.byOpID[req.OperationID] == slot {
			delete(r.byOpID, req.OperationID)
		}
		r.mu.Unlock()
		close(slot.done)
	}()

	select {
	case slot.started <- req.OperationID:
	case <-ctx.Done():
		return true, ctx.Err()
	}

	select {
	case status := <-slot.finish:
		if status == "succeeded" {
			return true, nil
		}
		return true, problem.New(problem.Internal, "证书自动续期执行失败。")
	case <-ctx.Done():
		return true, ctx.Err()
	}
}

// Finish 向活跃的续期执行器发送终态信号并等待其收尾退出；已退出时幂等返回。
func (r *RenewalOperations) Finish(ctx context.Context, caller certificates.Caller, status string) error {
	if r == nil {
		return fault.New("BACKEND_REQUIRED", "续期 operation 桥接器未初始化")
	}
	if ctx == nil {
		return fault.New("VALIDATION_FAILED", "续期收尾需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(fault.New("CANCELLED", "续期收尾已取消"), err)
	}
	if !names.ID(caller.OperationID) {
		return fault.New("VALIDATION_FAILED", "续期收尾缺少有效的 operation 标识")
	}
	r.mu.Lock()
	slot, ok := r.byOpID[caller.OperationID]
	r.mu.Unlock()
	if !ok || slot == nil {
		return nil
	}
	select {
	case slot.finish <- status:
	case <-slot.done:
		return nil
	}
	timer := time.NewTimer(r.finishTimeout)
	defer timer.Stop()
	select {
	case <-slot.done:
		return nil
	case <-ctx.Done():
		return errors.Join(fault.New("CANCELLED", "等待续期执行器结束已取消"), ctx.Err())
	case <-timer.C:
		return fault.New("RENEWAL_AUDIT_FAILED", "等待续期执行器结束超时")
	}
}
