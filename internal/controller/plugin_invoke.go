// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ---------------------------------------------------------------------------
// 插件间调用（ADR-0011 + ADR-0023 §3.3 H3 受控后台只读调用）
//
// InvokePlugin 不直连目标插件，而是把调用变成调用方"当前被派发的 operation"的
// 子 operation，走唯一写入通路 operations.Run：
//
//   1. 父 operation 由宿主核实（RUNNING 且派发给本实例），插件自报的 id 只当选择子；
//   2. 以父 operation 的 actor 提交，RBAC / 委托策略 / 权限模式照常生效；
//   3. 能力 plugin.invoke:<plugin_id>/<operation> 精确匹配，插件级 ∩ 父 operation 级；
//   4. 审批、风险、深度、参数 schema、幂等由 operations.Run 负责；
//   5. 无父调用仅在同时持有 plugin.invoke + plugin.invoke.background、目标为同步
//      effect==read、目标已 live、且符合 ≤12/min 限频与 ≤10s 截止时间时放行（H3）；
//   6. 任何拒绝都写一条 plugin.invoke / denied 审计。
// ---------------------------------------------------------------------------

// capPluginInvoke is the capability of a plugin-to-plugin call; its scope is
// the target action ID <plugin_id>/<operation> (ARCH §10.3).
const (
	capPluginInvoke           = "plugin.invoke"
	capPluginInvokeBackground = "plugin.invoke.background"

	backgroundInvokePerMin  = 12.0
	backgroundInvokeBurst   = 4.0
	backgroundInvokeTimeout = 10 * time.Second
)

// operationRunner submits one operation; *operations.Service implements it.
type operationRunner interface {
	Run(ctx context.Context, req operations.RunRequest) (*operations.Response, error)
}

// pluginGrantSource returns what a verified manifest grants a plugin;
// *catalog.Catalog implements it.
type pluginGrantSource interface {
	PluginGrants(pluginID string) ([]catalog.Capability, string, bool)
	Get(id string) (*catalog.Entry, bool)
}

// Refusal reasons recorded in the audit row of a denied call.
const (
	invokeNoParent          = "parent_not_dispatched"
	invokeNoCapability      = "capability_missing"
	invokeOperationCapGated = "operation_capability_missing"
	invokeCrossNode         = "cross_node_not_allowed"
	// invokeDeniedByPolicy covers the refusals of operations.Run: RBAC, the
	// delegation policy, the permission mode and the call depth.
	invokeDeniedByPolicy = "denied_by_policy"
)

// InvokePlugin runs one plugin-to-plugin call as a child operation. Every
// refusal is a domain result with gRPC OK (platform.proto, "Errors").
func (h *hostInvoker) InvokePlugin(ctx context.Context, call hostsvc.InvokeCall) (hostsvc.InvokeResult, error) {
	if h == nil || h.reader == nil || h.runner == nil || h.grants == nil || h.db == nil {
		return hostsvc.InvokeResult{}, problem.New(problem.Unavailable, "controller: plugin invocation is not available")
	}
	action := call.TargetPluginID + "/" + call.Operation

	// 1. The parent is the host's record, never the plugin's word.
	parent, ok := dispatchedOperation(ctx, h.reader, h.pluginID, h.instanceID, h.nodeID, call.ParentOperationID)
	if !ok {
		if call.ParentOperationID == "" {
			return h.invokeBackgroundRead(ctx, call, action)
		}
		return h.refuse(ctx, nil, call, action, invokeNoParent,
			"The call has no running operation of this plugin instance as its parent.")
	}

	// 2. plugin.invoke:<target> must be granted to the plugin and, when the
	//    parent operation narrows its capabilities, to that operation too.
	caps, placement, ok := h.grants.PluginGrants(h.pluginID)
	if !ok || !slices.Contains(caps, catalog.Capability{Name: capPluginInvoke, Scope: action}) {
		return h.refuse(ctx, parent, call, action, invokeNoCapability,
			"The plugin does not hold plugin.invoke for this operation.")
	}
	if len(parent.Meta.Capabilities) > 0 &&
		!slices.Contains(parent.Meta.Capabilities, operations.Capability{Name: capPluginInvoke, Scope: action}) {
		return h.refuse(ctx, parent, call, action, invokeOperationCapGated,
			"The parent operation does not use plugin.invoke for this operation.")
	}

	// 3. Only a controller-placement plugin may reach another node (ADR-0007 #6).
	nodeID := call.TargetNodeID
	if nodeID == "" {
		nodeID = h.nodeID
	}
	if nodeID != h.nodeID && placement != "controller" {
		return h.refuse(ctx, parent, call, action, invokeCrossNode,
			"Only a controller plugin may invoke a plugin on another node.")
	}
	instanceID := call.TargetInstanceID
	if instanceID == "" {
		instanceID = DefaultInstanceID
	}

	// 4. The single write path decides the rest.
	args := call.PayloadJSON
	if len(args) == 0 {
		args = []byte("{}")
	}
	key := call.IdempotencyKey
	if key == "" {
		key = oneTimeInvokeKey()
	}
	target := operations.Target{NodeID: nodeID, PluginID: call.TargetPluginID, InstanceID: instanceID}
	expectedRevision := ""
	if call.TargetPluginID == "tls.certificates" {
		if call.Operation == "certificates.list" {
			target.Subject = "plugins/tls.certificates/resources/certificates"
		} else if len(args) > 0 {
			var certArgs struct {
				CertificateID string `json:"certificate_id"`
			}
			if json.Unmarshal(args, &certArgs) == nil && names.ID(certArgs.CertificateID) {
				target.Subject = "plugins/tls.certificates/resources/certificates/" + certArgs.CertificateID
				switch call.Operation {
				case "certificates.issue", "certificates.import", "certificates.test",
					"bindings.reserve", "bindings.bind", "bindings.deploy", "bindings.rollback", "bindings.unbind",
					"generations.remove", "certificates.remove":
					if h.certRevision != nil {
						if rev, found, rerr := h.certRevision(ctx, certArgs.CertificateID); rerr == nil {
							if found && rev != "" {
								expectedRevision = rev
							} else if call.Operation == "certificates.issue" || call.Operation == "certificates.import" || call.Operation == "certificates.test" {
								expectedRevision = certificates.MissingRevision
							}
						}
					}
				}
			}
		}
	}
	resp, err := h.runner.Run(ctx, operations.RunRequest{
		Actor:            parent.Actor,
		TraceID:          parent.TraceID,
		RequestID:        parent.RequestID,
		NodeID:           h.nodeID,
		Action:           action,
		Target:           target,
		Args:             json.RawMessage(args),
		ExpectedRevision: expectedRevision,
		// The child runs as the parent's actor, so keys are scoped to the
		// calling instance by route (ADR-0011 §7).
		Idempotency: operations.Idempotency{
			Key: key, Method: "POST", Route: "plugin-invoke:" + h.pluginID + "/" + h.instanceID,
		},
		ParentOperationID: parent.ID,
		InvokedBy:         &operations.PluginInstanceRef{PluginID: h.pluginID, InstanceID: h.instanceID},
	})
	if err != nil {
		p := problem.From(err)
		if p.Code == problem.PermissionDenied {
			return h.refuse(ctx, parent, call, action, invokeDeniedByPolicy, p.Detail)
		}
		return hostsvc.InvokeResult{Error: domainError(p)}, nil
	}
	return h.invokeResult(ctx, parent, call, action, resp), nil
}

// invokeResult maps the outcome: a finished call answers with its result, an
// unfinished one with its operation (job, approval) for WaitOperation.
func (h *hostInvoker) invokeResult(ctx context.Context, parent *operations.Operation, call hostsvc.InvokeCall,
	action string, resp *operations.Response) hostsvc.InvokeResult {
	if resp.OperationID == "" && resp.Outcome != nil {
		// A read creates no operation, so the host audits it here (ADR-0011 §1).
		h.audit(ctx, parent, call, action, operations.AuditSuccess, "")
		return hostsvc.InvokeResult{PayloadJSON: resp.Outcome.Result}
	}
	op := resp.Operation
	if op == nil {
		return hostsvc.InvokeResult{OperationID: resp.OperationID, State: hostsvc.OperationPending}
	}
	if op.Status == operations.Succeeded {
		return hostsvc.InvokeResult{PayloadJSON: op.Result}
	}
	return hostsvc.InvokeResult{OperationID: op.ID, State: hostOperationState(op.Status)}
}

// refuse writes the denied audit row and returns the PERMISSION_DENIED result.
func (h *hostInvoker) refuse(ctx context.Context, parent *operations.Operation, call hostsvc.InvokeCall,
	action, reason, detail string) (hostsvc.InvokeResult, error) {
	h.audit(ctx, parent, call, action, operations.AuditDenied, reason)
	return hostsvc.InvokeResult{Error: &hostsvc.DomainError{
		Code: string(problem.PermissionDenied), Message: detail,
	}}, nil
}

// audit records one plugin.invoke decision. A failure is logged: the call's
// answer does not depend on it, and a denied call stays denied.
func (h *hostInvoker) audit(ctx context.Context, parent *operations.Operation, call hostsvc.InvokeCall,
	action, outcome, reason string) {
	details := map[string]any{
		"caller": map[string]string{"plugin_id": h.pluginID, "instance_id": h.instanceID},
		"target": map[string]string{
			"action": action, "instance_id": call.TargetInstanceID, "node_id": call.TargetNodeID,
		},
	}
	if reason != "" {
		details["reason"] = reason
	}
	rec := operations.AuditRecord{
		Actor:   actor.SystemActor("plugin:" + h.pluginID),
		Action:  "plugin.invoke",
		Subject: "nodes/" + h.nodeID + "/plugins/" + h.pluginID + "/instances/" + h.instanceID,
		Outcome: outcome,
		NodeID:  h.nodeID,
		Source:  "plugin",
	}
	if parent != nil {
		rec.OperationID, rec.TraceID, rec.RequestID = parent.ID, parent.TraceID, parent.RequestID
	} else if call.ParentOperationID != "" {
		// Unverified, so only kept as data, never as the row's operation link.
		details["claimed_parent_operation_id"] = call.ParentOperationID
	}
	raw, err := json.Marshal(details)
	if err == nil {
		rec.Details = raw
		// A caller that hung up must not erase the record of its refusal.
		actx := context.WithoutCancel(ctx)
		err = h.db.Update(actx, func(tx *storage.Tx) error {
			return operations.Audit(actx, tx, rec)
		})
	}
	if err != nil && h.logger != nil {
		h.logger.Error("plugin invoke audit failed", "plugin_id", h.pluginID, "action", action, "error", err)
	}
}

// domainError renders a host problem as the ABI ErrorDetail; field
// violations travel in details_json so the caller can fix its payload.
func domainError(p *problem.Error) *hostsvc.DomainError {
	rendered := p.Problem("", "")
	out := &hostsvc.DomainError{Code: string(p.Code), Message: p.Detail, Retryable: rendered.Retryable}
	if len(p.Violations) > 0 {
		if raw, err := json.Marshal(map[string]any{"violations": p.Violations}); err == nil {
			out.DetailsJSON = raw
		}
	}
	return out
}

// oneTimeInvokeKey is the idempotency key of a call that brought none: the
// call is still recorded once, it just cannot be retried by key.
func oneTimeInvokeKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "host-" + hex.EncodeToString(b[:])
}

// invokeBackgroundRead implements ADR-0023 §3.3 (H3): parentless plugin-to-plugin
// invocation strictly restricted to synchronous read operations when the caller
// holds both plugin.invoke:<action> and plugin.invoke.background:<action>, the
// target instance is already live, and the ≤12/min rate limit holds.
func (h *hostInvoker) invokeBackgroundRead(ctx context.Context, call hostsvc.InvokeCall, action string) (hostsvc.InvokeResult, error) {
	caps, placement, ok := h.grants.PluginGrants(h.pluginID)
	if !ok ||
		!slices.Contains(caps, catalog.Capability{Name: capPluginInvoke, Scope: action}) ||
		!slices.Contains(caps, catalog.Capability{Name: capPluginInvokeBackground, Scope: action}) {
		return h.refuse(ctx, nil, call, action, invokeNoParent,
			"The call has no running operation of this plugin instance as its parent.")
	}
	entry, found := h.grants.Get(action)
	if !found || entry.Effect != "read" || entry.Mode != "invoke" {
		return h.refuse(ctx, nil, call, action, invokeNoParent,
			"Background plugin invocation is permitted only for synchronous read operations.")
	}
	nodeID := call.TargetNodeID
	if nodeID == "" {
		nodeID = h.nodeID
	}
	if nodeID != h.nodeID && placement != "controller" {
		return h.refuse(ctx, nil, call, action, invokeCrossNode,
			"Only a controller plugin may invoke a plugin on another node.")
	}
	if h.isLive != nil && !h.isLive(call.TargetPluginID) {
		return hostsvc.InvokeResult{Error: &hostsvc.DomainError{
			Code:      string(problem.PluginUnavailable),
			Message:   "The target plugin is not running.",
			Retryable: true,
		}}, nil
	}
	if !h.allowBackground() {
		return hostsvc.InvokeResult{Error: &hostsvc.DomainError{
			Code:      string(problem.RateLimited),
			Message:   "Background plugin invocation rate limit exceeded (max 12/min).",
			Retryable: true,
		}}, nil
	}

	bgCtx, cancel := context.WithTimeout(ctx, backgroundInvokeTimeout)
	defer cancel()

	instanceID := call.TargetInstanceID
	if instanceID == "" {
		instanceID = DefaultInstanceID
	}
	args := call.PayloadJSON
	if len(args) == 0 {
		args = []byte("{}")
	}
	key := call.IdempotencyKey
	if key == "" {
		key = oneTimeInvokeKey()
	}
	bgTarget := operations.Target{NodeID: nodeID, PluginID: call.TargetPluginID, InstanceID: instanceID}
	if call.TargetPluginID == "tls.certificates" && call.Operation == "certificates.list" {
		bgTarget.Subject = "plugins/tls.certificates/resources/certificates"
	}
	resp, err := h.runner.Run(bgCtx, operations.RunRequest{
		Actor:  actor.SystemActor("plugin:" + h.pluginID),
		NodeID: h.nodeID,
		Action: action,
		Target: bgTarget,
		Args:   json.RawMessage(args),
		Idempotency: operations.Idempotency{
			Key: key, Method: "POST", Route: "plugin-invoke-bg:" + h.pluginID + "/" + h.instanceID,
		},
		InvokedBy: &operations.PluginInstanceRef{PluginID: h.pluginID, InstanceID: h.instanceID},
	})
	if err != nil {
		p := problem.From(err)
		if p.Code == problem.PermissionDenied {
			return h.refuse(ctx, nil, call, action, invokeDeniedByPolicy, p.Detail)
		}
		return hostsvc.InvokeResult{Error: domainError(p)}, nil
	}
	h.auditBackground(ctx, call, action)
	if resp.Outcome != nil {
		return hostsvc.InvokeResult{PayloadJSON: resp.Outcome.Result}, nil
	}
	return hostsvc.InvokeResult{}, nil
}

func (h *hostInvoker) allowBackground() bool {
	clk := h.clock
	if clk == nil {
		clk = clock.System{}
	}
	now := clk.Now()
	h.bgMu.Lock()
	defer h.bgMu.Unlock()
	if h.bgLast.IsZero() {
		h.bgLast = now
		h.bgTokens = backgroundInvokeBurst - 1
		return true
	}
	if elapsed := now.Sub(h.bgLast).Seconds(); elapsed > 0 {
		h.bgTokens = min(backgroundInvokeBurst, h.bgTokens+elapsed*(backgroundInvokePerMin/60.0))
		h.bgLast = now
	}
	if h.bgTokens < 1.0 {
		return false
	}
	h.bgTokens -= 1.0
	return true
}

func (h *hostInvoker) auditBackground(ctx context.Context, call hostsvc.InvokeCall, action string) {
	details := map[string]any{
		"background": true,
		"invoked_by": map[string]string{"plugin_id": h.pluginID, "instance_id": h.instanceID},
		"caller":     map[string]string{"plugin_id": h.pluginID, "instance_id": h.instanceID},
		"target": map[string]string{
			"action": action, "instance_id": call.TargetInstanceID, "node_id": call.TargetNodeID,
		},
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return
	}
	actx := context.WithoutCancel(ctx)
	_ = h.db.Update(actx, func(tx *storage.Tx) error {
		return operations.Audit(actx, tx, operations.AuditRecord{
			Actor:   actor.SystemActor("plugin:" + h.pluginID),
			Action:  "plugin.invoke",
			Subject: "nodes/" + h.nodeID + "/plugins/" + h.pluginID + "/instances/" + h.instanceID,
			Outcome: operations.AuditSuccess,
			Details: raw,
			NodeID:  h.nodeID,
			Source:  "plugin",
		})
	})
}
