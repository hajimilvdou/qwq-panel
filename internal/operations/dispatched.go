// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 精确派发与当前执行权限 ========================

// DispatchTarget 由宿主按实际能力 verb 和资源登记构造，不接受 RPC 自报身份。
// ActionID 和 Subject 同样需要精确匹配，运行中的其他操作不能充当泛用权限。
type DispatchTarget struct {
	ActionID   string
	NodeID     string
	PluginID   string
	InstanceID string
	Subject    string
}

// ControllerDispatchInstance 与宿主常驻 controller 插件通道的稳定实例一致。
// controller placement 的 operation 没有 Target.InstanceID，只允许此固定实例。
const ControllerDispatchInstance = "default"

// ValidArgumentDigest 复用宿主 canonical JSON 摘要格式，仅校验原参数指纹。
// 授权登记不能把带算法前缀的 ArgsDigest 当成裸资源 revision，也不自行生成摘要。
func ValidArgumentDigest(value string) bool {
	if !strings.HasPrefix(value, canonicalJSONPrefix) {
		return false
	}
	digest := strings.TrimPrefix(value, canonicalJSONPrefix)
	if len(digest) != 64 {
		return false
	}
	raw, err := hex.DecodeString(digest)
	return err == nil && hex.EncodeToString(raw) == digest
}

// DispatchedContext 只表示一个已经接受且仍在执行的 operation。
// 持久 Actor 不保留 SessionID，因此此快照不能用来伪造新的人类登录会话。
// Args 是提取敏感字段后的私有参数，调用者必须 Clear，禁止进入 DTO/事件/日志。
type DispatchedContext struct {
	OperationID       string
	Actor             actor.Actor
	Action            Action
	Target            Target
	Args              json.RawMessage
	ArgsDigest        string
	ExpectedRevision  string
	Deadline          time.Time
	Limits            Limits
	Approved          bool
	ConfirmationActor actor.Actor
	runtimeProof      *runtimeDispatchProof
}

func (DispatchedContext) String() string   { return "operations.DispatchedContext{[REDACTED]}" }
func (DispatchedContext) GoString() string { return "operations.DispatchedContext{[REDACTED]}" }
func (DispatchedContext) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}
func (c *DispatchedContext) Clear() {
	if c != nil {
		clear(c.Args)
		c.Args = nil
	}
}

// ResolveDispatched 重读真实 operation、当前 RBAC/委托策略与权限模式。
// 读取前后都确认本进程 executor 和当前状态，不允许仅凭数据库 RUNNING 取权限。
// 创建时的有效审批允许原操作继续；撤权、风险上限或只读模式收紧仍立即拒绝。
func (s *Service) ResolveDispatched(ctx context.Context, exact DispatchTarget, operationID string) (DispatchedContext, error) {
	if exact.Subject == "" {
		return DispatchedContext{}, dispatchDenied()
	}
	return s.resolveDispatched(ctx, exact, operationID)
}

// ResolveDispatchedInstance 供宿主秘密边界按真实操作构造完整目标。
// 原操作可没有可选 subject；插件/实例/节点仍由已验证的宿主通道指定。
func (s *Service) ResolveDispatchedInstance(ctx context.Context, pluginID, instanceID, nodeID, operationID string) (DispatchedContext, error) {
	if s == nil || s.db == nil || !ids.Valid(operationID, ids.Operation) {
		return DispatchedContext{}, dispatchDenied()
	}
	op, err := loadOperation(ctx, s.db.Reader(), operationID)
	if err != nil {
		return DispatchedContext{}, dispatchDenied()
	}
	return s.resolveDispatched(ctx, DispatchTarget{ActionID: op.Action, PluginID: pluginID,
		InstanceID: instanceID, NodeID: nodeID, Subject: op.Target.Subject}, operationID)
}

// ArgumentSchema 返回原已接受操作的独立 schema 副本，仅供宿主核对敏感字段成员。
// 调用者必须清理副本；没有真实 runtime proof 的快照不提供 schema。
func (c DispatchedContext) ArgumentSchema() json.RawMessage {
	if c.runtimeProof == nil || c.runtimeProof.original == nil {
		return nil
	}
	return bytes.Clone(c.runtimeProof.original.Meta.ArgsSchema)
}

// RevalidateDispatched 在明文返回前再次核对同一 executor、原意图与当前授权。
func (s *Service) RevalidateDispatched(ctx context.Context, accepted DispatchedContext) error {
	proof := accepted.runtimeProof
	if s == nil || proof == nil || proof.service != s || !sameCleanupSnapshot(accepted, proof) || !s.cleanupRuntimeAlive(proof) {
		return dispatchDenied()
	}
	current, err := s.resolveDispatched(ctx, proof.exact, accepted.OperationID)
	if err != nil {
		return err
	}
	defer current.Clear()
	if !sameCleanupSnapshot(accepted, current.runtimeProof) || current.runtimeProof.job != proof.job {
		return dispatchDenied()
	}
	return nil
}

func (s *Service) resolveDispatched(ctx context.Context, exact DispatchTarget, operationID string) (DispatchedContext, error) {
	if s == nil || s.db == nil || s.authorizer == nil || s.policy == nil {
		return DispatchedContext{}, problem.New(problem.Unavailable, "精确能力需要真实 operation 授权和策略后端。")
	}
	if !ids.Valid(operationID, ids.Operation) || exact.ActionID == "" || exact.NodeID == "" || exact.PluginID == "" || exact.InstanceID == "" {
		return DispatchedContext{}, dispatchDenied()
	}
	before, err := s.currentDispatch(ctx, exact, operationID)
	if err != nil {
		return DispatchedContext{}, err
	}
	proof, err := s.captureRuntimeProof(exact, before)
	if err != nil {
		return DispatchedContext{}, err
	}
	if err := s.authorize(ctx, before.Actor, before.Meta, before.Target); err != nil {
		return DispatchedContext{}, err
	}
	limits, err := s.limits(ctx, before.Actor, before.Meta, before.Target)
	if err != nil {
		return DispatchedContext{}, err
	}
	approved, err := s.checkDispatchPolicy(ctx, before, limits)
	if err != nil {
		return DispatchedContext{}, err
	}
	// 授权源可能在查询期间撤销或取消 operation；任何状态变化都先拒绝本次调用。
	after, err := s.currentDispatch(ctx, exact, operationID)
	if err != nil {
		return DispatchedContext{}, err
	}
	if !sameDispatch(before, after) {
		return DispatchedContext{}, dispatchDenied()
	}
	// 首次授权查询结束后也可能发生角色或委托撤销，不能只再次读取 operation。
	if err := s.authorize(ctx, after.Actor, after.Meta, after.Target); err != nil {
		return DispatchedContext{}, err
	}
	currentLimits, err := s.limits(ctx, after.Actor, after.Meta, after.Target)
	if err != nil {
		return DispatchedContext{}, err
	}
	if currentLimits != limits {
		return DispatchedContext{}, dispatchDenied()
	}
	if _, err := s.checkDispatchPolicy(ctx, after, currentLimits); err != nil {
		return DispatchedContext{}, err
	}
	final, err := s.currentDispatch(ctx, exact, operationID)
	if err != nil {
		return DispatchedContext{}, err
	}
	if !sameDispatch(after, final) {
		return DispatchedContext{}, dispatchDenied()
	}
	after = final
	if err := ctx.Err(); err != nil {
		return DispatchedContext{}, problem.From(err)
	}
	confirmation, err := s.dispatchConfirmation(ctx, after)
	if err != nil {
		return DispatchedContext{}, err
	}
	latest, err := s.currentDispatch(ctx, exact, operationID)
	if err != nil || !sameDispatch(after, latest) || !sameCleanupIntent(proof.original, latest) || !s.cleanupRuntimeAlive(proof) {
		return DispatchedContext{}, dispatchDenied()
	}
	proof.limits, proof.approved, proof.confirmation = limits, approved, confirmation
	action := after.Meta
	action.Capabilities = slices.Clone(after.Meta.Capabilities)
	action.ArgsSchema = nil // 创建时已验证 schema；私有快照不输出或复用其可变缓冲。
	return DispatchedContext{OperationID: after.ID, Actor: after.Actor, Action: action, Target: after.Target, Args: bytes.Clone(after.Args),
		ArgsDigest: after.ArgsDigest, ExpectedRevision: after.ExpectedRevision, Deadline: after.StartedAt.Add(after.Timeout), Limits: limits,
		Approved: approved, ConfirmationActor: confirmation, runtimeProof: proof}, nil
}

func (s *Service) currentDispatch(ctx context.Context, exact DispatchTarget, operationID string) (*Operation, error) {
	if err := ctx.Err(); err != nil {
		return nil, problem.From(err)
	}
	if !s.isRunning(operationID) {
		return nil, dispatchDenied()
	}
	op, err := loadOperation(ctx, s.db.Reader(), operationID)
	if err != nil {
		return nil, dispatchDenied()
	}
	instanceID := op.Target.InstanceID
	if op.Meta.Placement == PlacementController && instanceID == "" {
		instanceID = ControllerDispatchInstance
	}
	if op.Status != Running || op.CancelRequested || op.StartedAt == nil || op.Timeout <= 0 || !s.clock.Now().Before(op.StartedAt.Add(op.Timeout)) || op.Actor.Kind == actor.System || op.Actor.Valid() != nil || op.Action != exact.ActionID || op.Meta.ID != exact.ActionID || op.NodeID != exact.NodeID || op.Target.PluginID != exact.PluginID || instanceID != exact.InstanceID || op.Target.Subject != exact.Subject {
		return nil, dispatchDenied()
	}
	// controller placement 的 Target.NodeID 可为空，但持久 NodeID 必须为当前宿主。
	if (op.Target.NodeID != "" && op.Target.NodeID != exact.NodeID) || (op.Meta.Source == PluginSource && op.Meta.PluginID != exact.PluginID) || op.Meta.Effect != op.Effect || riskRank(op.Meta.EffectiveRisk()) > riskRank(op.EffectiveRisk) || len(op.Args) > 1<<20 || (len(op.Args) != 0 && !json.Valid(op.Args)) {
		return nil, dispatchDenied()
	}
	return op, nil
}

func sameDispatch(a, b *Operation) bool {
	return a.Actor == b.Actor && a.Action == b.Action && a.Target == b.Target && reflect.DeepEqual(a.Meta, b.Meta) && a.ArgsDigest == b.ArgsDigest && bytes.Equal(a.Args, b.Args) && a.ExpectedRevision == b.ExpectedRevision && a.ApprovalID == b.ApprovalID && a.PermissionMode == b.PermissionMode && a.Timeout == b.Timeout && a.StartedAt.Equal(*b.StartedAt)
}

func (s *Service) checkDispatchPolicy(ctx context.Context, op *Operation, limits Limits) (bool, error) {
	if !limits.PermissionMode.Valid() || !dispatchRisk(limits.MaxRisk, true) || !dispatchRisk(limits.AutoApproveMaxRisk, false) || (limits.OnApprovalRequired != ApprovalQueue && limits.OnApprovalRequired != ApprovalFail) {
		return false, dispatchDenied()
	}
	if limits.MaxRisk != "" && riskRank(op.EffectiveRisk) > riskRank(limits.MaxRisk) {
		return false, dispatchDenied()
	}
	decision := op.Meta.DecideApproval(op.Actor, op.EffectiveRisk, limits)
	if decision.Denied {
		return false, dispatchDenied()
	}
	if !decision.NeedApproval {
		return false, nil
	}
	if op.ApprovalID == "" {
		return false, dispatchDenied()
	}
	approval, err := loadApproval(ctx, s.db.Reader(), op.ApprovalID)
	if err != nil || approval.Status != ApprovalApproved || approval.OperationID != op.ID {
		return false, dispatchDenied()
	}
	return true, nil
}

func dispatchRisk(value string, empty bool) bool {
	switch value {
	case RiskLow, RiskMedium, RiskHigh, "none":
		return true
	case "":
		return empty
	default:
		return false
	}
}

func dispatchDenied() error {
	return problem.New(problem.PermissionDenied, "operation 未在精确目标上执行，或当前授权、策略和状态已变化。")
}
