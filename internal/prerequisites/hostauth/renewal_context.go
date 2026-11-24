// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"math"
	"slices"
	"strconv"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 原policy/certificate交集，不从RPC猜另一策略 ========================

type RenewalTargetArgs struct {
	PolicyID      string `json:"policy_id"`
	CertificateID string `json:"certificate_id"`
}

func (a *Authority) renewalTarget(ctx context.Context, policyID, certificateID string) (*execution, renewalRegistration, error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, renewalRegistration{}, err
	}
	if !names.ID(policyID) || !names.ID(certificateID) || value.invocation.PluginID != "tls.certificates" ||
		value.invocation.Subject != renewalPolicySubject(policyID) || value.snapshot.Actor.Kind == actor.System || value.snapshot.Actor.Kind == actor.Service {
		return nil, renewalRegistration{}, fault.New("PERMISSION_DENIED", "续期策略不是当前实际主体的固定目标")
	}
	switch value.invocation.Operation {
	case "renewal.configure":
		input, err := DecodeArguments[RenewalPolicyArgs](ctx, a)
		if err != nil {
			return nil, renewalRegistration{}, err
		}
		if input.PolicyID != policyID || input.CertificateID != certificateID {
			return nil, renewalRegistration{}, fault.New("PERMISSION_DENIED", "续期配置替换了原policy/certificate")
		}
	case "renewal.get", "renewal.revoke":
		input, err := DecodeArguments[RenewalTargetArgs](ctx, a)
		if err != nil {
			return nil, renewalRegistration{}, err
		}
		if input.PolicyID != policyID || input.CertificateID != certificateID {
			return nil, renewalRegistration{}, fault.New("PERMISSION_DENIED", "续期查询或撤销替换了原policy/certificate")
		}
	case "renewal.attach_service":
		input, err := DecodeArguments[RenewalServiceArgs](ctx, a)
		if err != nil {
			return nil, renewalRegistration{}, err
		}
		if input.PolicyID != policyID {
			return nil, renewalRegistration{}, fault.New("PERMISSION_DENIED", "账号登记替换了原policy")
		}
	default:
		return nil, renewalRegistration{}, fault.New("PERMISSION_DENIED", "当前operation没有续期管理入口")
	}
	state, _, err := a.loadRenewalLedger(ctx)
	if err != nil {
		return nil, renewalRegistration{}, err
	}
	index := renewalIndex(state, policyID)
	if index < 0 || state.Entries[index].Dependencies.Scope.CertificateID != certificateID {
		return nil, renewalRegistration{}, fault.New("NOT_FOUND", "该证书没有原固定policy登记")
	}
	if value.invocation.Operation == "renewal.get" {
		if err := validateCertificateAction(value.snapshot.Action, certificates.Read); err != nil {
			return nil, renewalRegistration{}, err
		}
	} else if _, _, _, err := a.renewalDispatch(ctx, value.invocation.Operation, policyID, value.snapshot.ExpectedRevision); err != nil {
		return nil, renewalRegistration{}, err
	}
	return value, state.Entries[index], nil
}

// CurrentRenewalPolicy 只输出原已接受policy对应的公开登记状态；active不等于后台enabled。
func (a *Authority) CurrentRenewalPolicy(ctx context.Context, policyID, certificateID string) (RenewalPolicyView, error) {
	_, entry, err := a.renewalTarget(ctx, policyID, certificateID)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	if _, err := a.current(ctx); err != nil {
		return RenewalPolicyView{}, err
	}
	return renewalView(entry)
}

// RenewalCertificateContext 仅为该原policy的证书建立只读范围，不生成service运行权限。
func (a *Authority) RenewalCertificateContext(ctx context.Context, policyID, certificateID string) (context.Context, certificates.Caller, certificates.RenewalScope, error) {
	value, entry, err := a.renewalTarget(ctx, policyID, certificateID)
	if err != nil {
		return nil, certificates.Caller{}, certificates.RenewalScope{}, err
	}
	scope, err := certificates.CanonicalRenewalScope(entry.Dependencies.Scope)
	if err != nil {
		return nil, certificates.Caller{}, certificates.RenewalScope{}, err
	}
	bound, caller, err := a.certificateReadContext(ctx, value, certificateID)
	return bound, caller, scope, err
}

// RevokeRenewalPolicy 先CAS撤销原授权并保留attachment元数据；普通续期立即失效。
func (a *Authority) RevokeRenewalPolicy(ctx context.Context, policyID, certificateID, expected string) (RenewalPolicyView, error) {
	value, entry, err := a.renewalTarget(ctx, policyID, certificateID)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	if value.invocation.Operation != "renewal.revoke" {
		return RenewalPolicyView{}, fault.New("PERMISSION_DENIED", "当前原意图不是撤销该policy")
	}
	if err := a.RequireRevision(ctx, expected); err != nil {
		return RenewalPolicyView{}, err
	}
	origin := bindingOriginFrom(value)
	if entry.State == renewalRevoked && entry.RevokedOrigin != nil && *entry.RevokedOrigin == origin && entry.RevokedRevision == expected {
		return renewalView(entry)
	}
	current, err := renewalRevision(entry)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	if current != expected || entry.Version == math.MaxUint64 {
		return RenewalPolicyView{}, fault.New("REVISION_CONFLICT", "原policy授权版本已经变化")
	}
	state, revision, err := a.loadRenewalLedger(ctx)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	index := renewalIndex(state, policyID)
	if index < 0 {
		return RenewalPolicyView{}, fault.New("POLICY_REVOKED", "原policy登记不存在")
	}
	latest, err := renewalRevision(state.Entries[index])
	if err != nil {
		return RenewalPolicyView{}, err
	}
	if latest != current {
		return RenewalPolicyView{}, fault.New("REVISION_CONFLICT", "撤销期间原policy登记已变化")
	}
	if _, _, _, err := a.renewalDispatch(ctx, "renewal.revoke", policyID, expected); err != nil {
		return RenewalPolicyView{}, err
	}
	entry.State, entry.Version = renewalRevoked, entry.Version+1
	entry.RevokedOrigin, entry.RevokedBy, entry.RevokedRevision = &origin, value.snapshot.Actor, expected
	state.Entries[index] = entry
	if err := a.saveRenewalLedger(ctx, state, revision); err != nil {
		return RenewalPolicyView{}, err
	}
	return renewalView(entry)
}

// RenewalConfirmations 只核验真实私有确认及当前管理operation；Validate不产生运行proof。
type RenewalConfirmations struct{ Authority *Authority }

func (p RenewalConfirmations) Confirm(ctx context.Context, caller certificates.Caller, scope certificates.RenewalScope) error {
	if p.Authority == nil || caller.PolicyID != "" {
		return fault.New("BACKEND_REQUIRED", "续期确认需要真实私有授权来源")
	}
	a := p.Authority
	value, err := a.current(ctx)
	if err != nil {
		return err
	}
	if value.invocation.Operation != "renewal.configure" && value.invocation.Operation != "renewal.attach_service" && value.invocation.Operation != "renewal.revoke" {
		return fault.New("PERMISSION_DENIED", "只读意图不能启用或撤销后台policy")
	}
	policyID := ""
	switch value.invocation.Operation {
	case "renewal.configure":
		input, failure := DecodeArguments[RenewalPolicyArgs](ctx, a)
		policyID, err = input.PolicyID, failure
	case "renewal.attach_service":
		input, failure := DecodeArguments[RenewalServiceArgs](ctx, a)
		policyID, err = input.PolicyID, failure
	case "renewal.revoke":
		input, failure := DecodeArguments[RenewalTargetArgs](ctx, a)
		policyID, err = input.PolicyID, failure
	}
	if err != nil {
		return err
	}
	_, entry, err := a.renewalTarget(ctx, policyID, scope.CertificateID)
	if err != nil {
		return err
	}
	if caller.OwnerID != a.ownerID || caller.OperationID != value.invocation.OperationID || !sameRenewalScope(entry.Dependencies.Scope, scope) {
		return fault.New("POLICY_SCOPE_DENIED", "后台policy替换了原caller或确认Scope")
	}
	if value.invocation.Operation != "renewal.revoke" {
		if entry.State != renewalActive {
			return fault.New("SERVICE_REQUIRED", "policy尚未绑定真实受限服务账号")
		}
		return a.checkRenewalRegistration(ctx, entry)
	}
	return nil
}

func (p RenewalConfirmations) Validate(ctx context.Context, scope certificates.RenewalScope) error {
	if p.Authority == nil || scope.OwnerID != p.Authority.ownerID {
		return fault.New("POLICY_SCOPE_DENIED", "续期Scope没有真实宿主owner")
	}
	a := p.Authority
	state, _, err := a.loadRenewalLedger(ctx)
	if err != nil {
		return err
	}
	for _, entry := range state.Entries {
		if entry.State == renewalActive && sameRenewalScope(entry.Dependencies.Scope, scope) {
			return a.checkRenewalRegistration(ctx, entry)
		}
	}
	return fault.New("POLICY_REVOKED", "原policy或固定Scope已经撤销")
}

// ActiveRenewalServiceAccount 只读返回已确认激活续期策略绑定的精确服务账号 ID；不泄露令牌或修改账本。
func (a *Authority) ActiveRenewalServiceAccount(ctx context.Context, policyID string, scope certificates.RenewalScope) (string, error) {
	if a == nil || ctx == nil {
		return "", fault.New("BACKEND_REQUIRED", "续期策略账号查询需要有效宿主授权器与上下文")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !names.ID(policyID) || scope.OwnerID != a.ownerID {
		return "", fault.New("POLICY_SCOPE_DENIED", "续期策略标识或固定 owner 无效")
	}
	canonical, err := certificates.CanonicalRenewalScope(scope)
	if err != nil {
		return "", fault.New("POLICY_SCOPE_DENIED", "续期固定 Scope 无效")
	}
	state, _, err := a.loadRenewalLedger(ctx)
	if err != nil {
		return "", err
	}
	index := renewalIndex(state, policyID)
	if index < 0 {
		return "", fault.New("NOT_FOUND", "原续期策略登记不存在")
	}
	entry := state.Entries[index]
	if entry.State != renewalActive || entry.ServiceAccountID == "" || !sameRenewalScope(entry.Dependencies.Scope, canonical) {
		return "", fault.New("POLICY_REVOKED", "续期策略未激活、未绑定账号或 Scope 已变化")
	}
	if err := a.checkRenewalRegistration(ctx, entry); err != nil {
		return "", err
	}
	return entry.ServiceAccountID, nil
}

var _ certificates.RenewalConfirmations = RenewalConfirmations{}

// ======================== 真实Begin之后的阶段Context，候选不会变成proof ========================

type RenewExistingArgs struct {
	PolicyID       string `json:"policy_id"`
	PolicyRevision string `json:"policy_revision"`
	CertificateID  string `json:"certificate_id"`
	RunAttemptID   string `json:"run_attempt_id"`
	AttemptID      string `json:"attempt_id"`
}

type renewalExecutionKey struct{}

type renewalExecution struct {
	authority  *Authority
	parent     *execution
	caller     certificates.Caller
	scope      certificates.RenewalScope
	runAttempt string
	runs       *certificates.PrivateRenewalRuns
}

func (*renewalExecution) String() string               { return "hostauth.renewalExecution{[REDACTED]}" }
func (*renewalExecution) GoString() string             { return "hostauth.renewalExecution{[REDACTED]}" }
func (*renewalExecution) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// RenewalContexts只在当前实际service executor上兑换阶段许可。
type RenewalContexts struct {
	Authority *Authority
	Runs      *certificates.PrivateRenewalRuns
}

func (p RenewalContexts) Context(ctx context.Context, request certificates.RenewalContextRequest) (context.Context, context.CancelFunc, error) {
	if p.Authority == nil || p.Runs == nil || ctx == nil || request.Caller.PolicyID == "" {
		return nil, nil, fault.New("BACKEND_REQUIRED", "续期执行需要真实job与private runtime来源")
	}
	a := p.Authority
	invocation := Invocation{PluginID: "tls.certificates", InstanceID: "default", OperationID: request.Caller.OperationID,
		Operation: "renew_existing", Subject: "plugins/tls.certificates/resources/certificates/" + request.Scope.CertificateID}
	// 后台自动续期已由人类确认策略并绑定精确受限服务账号；仅在调用方未显式收紧模式时沿用
	// PermissionFull 供已接受的 renew_existing 插件作业核验，撤权、到期与取消仍实时生效。
	authCtx := ctx
	if _, hasMode := operations.PermissionModeFromContext(ctx); !hasMode {
		authCtx = operations.WithPermissionMode(ctx, operations.PermissionFull)
	}
	admission, releaseAdmission, err := a.Begin(authCtx, invocation)
	if err != nil {
		return nil, nil, err
	}
	defer releaseAdmission()
	lifetime, releaseLifetime, err := a.JobContext(admission)
	if err != nil {
		return nil, nil, err
	}
	// 阶段必须同时受原executor与worker调用方约束，不能扩大更早的deadline。
	var stage context.Context
	var releaseStage context.CancelFunc
	if deadline, found := ctx.Deadline(); found {
		stage, releaseStage = context.WithDeadline(lifetime, deadline)
	} else {
		stage, releaseStage = context.WithCancel(lifetime)
	}
	if mode, hasMode := operations.PermissionModeFromContext(authCtx); hasMode {
		stage = operations.WithPermissionMode(stage, mode)
	}
	stopCaller := context.AfterFunc(ctx, releaseStage)
	bound, releaseBound, err := a.Begin(stage, invocation)
	if err != nil {
		stopCaller()
		releaseStage()
		releaseLifetime()
		return nil, nil, err
	}
	release := func() { releaseBound(); stopCaller(); releaseStage(); releaseLifetime() }
	fail := func(err error) (context.Context, context.CancelFunc, error) { release(); return nil, nil, err }
	value, err := a.current(bound)
	if err != nil {
		return fail(err)
	}
	scope, err := certificates.CanonicalRenewalScope(request.Scope)
	if err != nil || request.Caller.OwnerID != a.ownerID {
		return fail(fault.New("POLICY_SCOPE_DENIED", "续期请求Scope不是原host owner"))
	}
	permission := &renewalExecution{authority: a, parent: value, caller: request.Caller, scope: scope,
		runAttempt: request.RunAttemptID, runs: p.Runs}
	bound = context.WithValue(bound, renewalExecutionKey{}, permission)
	run, entry, err := a.currentRenewalExecution(bound, permission)
	if err != nil {
		return fail(err)
	}
	certificate, revision, found, err := a.loadCertificate(bound, scope.CertificateID)
	if err != nil {
		return fail(err)
	}
	if !found || revision != entry.Dependencies.CertificateRevision || !sameCertificateSpec(certificate.Spec, scope.Issuance.Spec) {
		return fail(fault.New("POLICY_REVOKED", "续期证书private登记已经变化"))
	}
	grant := &certificateExecution{parent: value, certificateID: scope.CertificateID, registryRevision: revision,
		spec: cloneCertificateSpec(certificate.Spec), access: certificates.Read}
	switch request.Access {
	case certificates.Read:
		if request.IssueAttemptID != "" || request.ExpectedRevision != "" || request.Generation != 0 || request.Consumer != nil {
			return fail(fault.New("PERMISSION_DENIED", "续期读取不能附加签发或部署参数"))
		}
	case certificates.RenewExisting:
		if request.IssueAttemptID != run.IssueAttemptID || request.IssueAttemptID == "" || request.ExpectedRevision != run.ExpectedRevision ||
			request.ExpectedRevision == "" || request.Generation != 0 || request.Consumer != nil {
			return fail(fault.New("PERMISSION_DENIED", "续期签发替换了原private issue阶段"))
		}
		issuance := cloneCertificateIssuance(scope.Issuance)
		grant.access, grant.attemptID, grant.expectedRevision, grant.issuance, grant.acceptTerms = certificates.Issue,
			request.IssueAttemptID, request.ExpectedRevision, &issuance, true
		grant.providerRevision, grant.zoneRevision = entry.Dependencies.ProviderRevision, entry.Dependencies.ZoneRevision
	case certificates.Bind:
		if request.Consumer == nil || request.Generation == 0 || request.Generation != run.DeployGeneration || request.IssueAttemptID != "" || request.ExpectedRevision != "" {
			return fail(fault.New("PERMISSION_DENIED", "续期部署替换了原private generation阶段"))
		}
		index := slices.Index(scope.Consumers, *request.Consumer)
		if index < 0 {
			return fail(fault.New("POLICY_SCOPE_DENIED", "续期部署扩展了原consumer"))
		}
		ledger, _, err := a.loadBindingLedger(bound)
		if err != nil {
			return fail(err)
		}
		bindingIndex := slices.IndexFunc(ledger.Entries, func(binding bindingRegistration) bool {
			return binding.CertificateID == scope.CertificateID && binding.Consumer == *request.Consumer &&
				slices.ContainsFunc(entry.Dependencies.Bindings, func(owned renewalBinding) bool { return owned.ID == binding.ID })
		})
		if bindingIndex < 0 {
			return fail(fault.New("POLICY_REVOKED", "续期consumer没有原private绑定"))
		}
		binding := ledger.Entries[bindingIndex]
		facts, err := a.currentRegisteredConsumer(bound, invocation, binding.Consumer)
		if err != nil {
			return fail(err)
		}
		if !bindingFactsMatch(binding, facts) {
			return fail(fault.New("BINDING_REVOKED", "续期配置或真实安装能力已经变化"))
		}
		policy, err := bindingPolicyRevision(binding)
		if err != nil {
			return fail(err)
		}
		grant.access, grant.generation, grant.attemptID = certificates.Bind, request.Generation,
			request.RunAttemptID+"-deploy-"+strconv.Itoa(index)
		bound = context.WithValue(bound, bindingExecutionKey{}, &bindingExecution{parent: value, certificate: grant,
			id: binding.ID, policy: policy, facts: facts})
	default:
		return fail(fault.New("PERMISSION_DENIED", "续期Context不支持该访问"))
	}
	bound = context.WithValue(bound, certificateExecutionKey{}, grant)
	if _, err := a.certificateGrant(bound, request.Caller); err != nil {
		return fail(err)
	}
	return bound, release, nil
}

func (a *Authority) currentRenewalExecution(ctx context.Context, permission *renewalExecution) (certificates.RenewalRun, renewalRegistration, error) {
	if permission == nil || permission.authority != a || ctx.Value(renewalExecutionKey{}) != permission {
		return certificates.RenewalRun{}, renewalRegistration{}, fault.New("PERMISSION_DENIED", "缺少当次private续期Context")
	}
	value, err := a.current(ctx)
	if err != nil {
		return certificates.RenewalRun{}, renewalRegistration{}, err
	}
	input, err := DecodeArguments[RenewExistingArgs](ctx, a)
	if err != nil {
		return certificates.RenewalRun{}, renewalRegistration{}, err
	}
	if value != permission.parent || value.invocation.Operation != "renew_existing" || value.snapshot.Actor.Kind != actor.Service ||
		value.snapshot.ExpectedRevision != permission.caller.PolicyRevision || input.PolicyID != permission.caller.PolicyID ||
		input.PolicyRevision != permission.caller.PolicyRevision || input.CertificateID != permission.scope.CertificateID || input.RunAttemptID != permission.runAttempt {
		return certificates.RenewalRun{}, renewalRegistration{}, fault.New("PERMISSION_DENIED", "续期原service/policy/Args已变化")
	}
	state, _, err := a.loadRenewalLedger(ctx)
	if err != nil {
		return certificates.RenewalRun{}, renewalRegistration{}, err
	}
	index := renewalIndex(state, permission.caller.PolicyID)
	if index < 0 {
		return certificates.RenewalRun{}, renewalRegistration{}, fault.New("POLICY_REVOKED", "原private续期policy不存在")
	}
	entry := state.Entries[index]
	if entry.State != renewalActive || entry.ServiceAccountID != value.snapshot.Actor.ID || !sameRenewalScope(entry.Dependencies.Scope, permission.scope) {
		return certificates.RenewalRun{}, renewalRegistration{}, fault.New("POLICY_REVOKED", "续期账号或Scope不是原确认范围")
	}
	if err := a.checkRenewalRegistration(ctx, entry); err != nil {
		return certificates.RenewalRun{}, renewalRegistration{}, err
	}
	run, err := permission.runs.Current(ctx, permission.caller, permission.scope, permission.runAttempt)
	if err != nil {
		return certificates.RenewalRun{}, renewalRegistration{}, err
	}
	if input.AttemptID != run.IssueAttemptID || value.invocation.Subject != "plugins/tls.certificates/resources/certificates/"+run.CertificateID {
		return certificates.RenewalRun{}, renewalRegistration{}, fault.New("PERMISSION_DENIED", "续期原Args不是实际issue attempt")
	}
	return run, entry, nil
}

var _ certificates.RenewalContexts = RenewalContexts{}
