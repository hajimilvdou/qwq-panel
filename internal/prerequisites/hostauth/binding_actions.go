// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"math"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 固定部署与窄解绑，不授整份证书删除权限 ========================

func bindingOperationAccess(operation string) certificates.Access {
	switch operation {
	case "bindings.bind", "bindings.deploy", "bindings.rollback":
		return certificates.Bind
	case "bindings.unbind":
		return certificates.Unbind
	}
	return ""
}

func (a *Authority) acceptedBindingIntent(ctx context.Context, certificateID, expectedRevision string) (*execution, BindCertificateArgs, certificates.Access, error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, BindCertificateArgs{}, "", err
	}
	access := bindingOperationAccess(value.invocation.Operation)
	if value.invocation.PluginID != "tls.certificates" || access == "" ||
		value.invocation.Subject != "plugins/tls.certificates/resources/certificates/"+certificateID {
		return nil, BindCertificateArgs{}, "", fault.New("PERMISSION_DENIED", "原operation不能建立该消费绑定上下文")
	}
	if err := validateCertificateAction(value.snapshot.Action, access); err != nil {
		return nil, BindCertificateArgs{}, "", err
	}
	if err := a.RequireRevision(ctx, expectedRevision); err != nil {
		return nil, BindCertificateArgs{}, "", err
	}
	input, err := DecodeArguments[BindCertificateArgs](ctx, a)
	if err != nil {
		return nil, BindCertificateArgs{}, "", err
	}
	if input.CertificateID != certificateID || !names.ID(input.BindingRef) || !names.ID(input.AttemptID) || input.Generation == 0 || !validDigest(expectedRevision) {
		return nil, BindCertificateArgs{}, "", fault.New("PERMISSION_DENIED", "原绑定参数缺少精确ID、generation或资源版本")
	}
	return value, input, access, nil
}

// CompletedConsumerUnbindContext只兑换原成功operation的只读重放，撤销登记不能产生新的执行许可。
func (a *Authority) CompletedConsumerUnbindContext(ctx context.Context, certificateID, bindingID, expected string) (context.Context, certificates.Caller, bool, error) {
	value, input, access, err := a.acceptedBindingIntent(ctx, certificateID, expected)
	if err != nil {
		return nil, certificates.Caller{}, false, err
	}
	if access != certificates.Unbind || bindingID != input.BindingRef {
		return nil, certificates.Caller{}, false, fault.New("PERMISSION_DENIED", "解绑重放替换了原固定动作或binding")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	state, _, err := a.loadBindingLedger(bounded)
	if err != nil {
		return nil, certificates.Caller{}, false, err
	}
	index := bindingIndex(state, bindingID)
	if index < 0 || state.Entries[index].CertificateID != certificateID {
		return nil, certificates.Caller{}, false, fault.New("BINDING_DENIED", "解绑目标没有原私有登记")
	}
	entry := state.Entries[index]
	if entry.Phase != bindingRevoked {
		return nil, certificates.Caller{}, false, nil
	}
	origin := bindingOriginFrom(value)
	if entry.UnboundOrigin == nil || *entry.UnboundOrigin != origin || entry.UnboundRevision != expected {
		return nil, certificates.Caller{}, false, fault.New("BINDING_REVOKED", "撤销登记不是当前原operation的完成收据")
	}
	if err := a.checkBindingDependencies(bounded, entry); err != nil {
		return nil, certificates.Caller{}, false, err
	}
	if err := a.authorizeConsumerConfiguration(bounded, value.snapshot.Actor, a.nodeID, entry.Consumer.PluginID); err != nil {
		return nil, certificates.Caller{}, false, err
	}
	bound, caller, err := a.certificateReadContext(ctx, value, certificateID)
	return bound, caller, err == nil, err
}

type UnbindTarget struct {
	Caller           certificates.Caller
	CertificateID    string
	BindingID        string
	AttemptID        string
	ExpectedRevision string
	Generation       uint64
}

func (UnbindTarget) String() string   { return "hostauth.UnbindTarget{[REDACTED]}" }
func (UnbindTarget) GoString() string { return "hostauth.UnbindTarget{[REDACTED]}" }

// AcceptedUnbindTarget 只兑换原已接受的固定绑定、generation及attempt。
func (a *Authority) AcceptedUnbindTarget(ctx context.Context) (UnbindTarget, error) {
	value, err := a.current(ctx)
	if err != nil {
		return UnbindTarget{}, err
	}
	caller := certificates.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	permission, _, err := a.bindingGrant(ctx, caller)
	if err != nil {
		return UnbindTarget{}, err
	}
	grant := permission.certificate
	if grant.access != certificates.Unbind || value.invocation.Operation != "bindings.unbind" {
		return UnbindTarget{}, fault.New("PERMISSION_DENIED", "当前上下文不是窄解绑意图")
	}
	return UnbindTarget{Caller: caller, CertificateID: grant.certificateID, BindingID: permission.id,
		AttemptID: grant.attemptID, ExpectedRevision: grant.expectedRevision, Generation: grant.generation}, nil
}

// AuthorizeConsumerRemoval 只核验原私有解绑范围；停止/References由真实Bindings后端确认。
func (a *Authority) AuthorizeConsumerRemoval(ctx context.Context, caller certificates.Caller, binding certificates.HostBinding) error {
	permission, entry, err := a.bindingGrant(ctx, caller)
	if err != nil {
		return err
	}
	grant := permission.certificate
	if grant.access != certificates.Unbind || binding.ID != permission.id || binding.CertificateID != grant.certificateID ||
		binding.Generation != grant.generation || binding.Consumer != entry.Consumer || binding.PolicyRevision != permission.policy {
		return fault.New("PERMISSION_DENIED", "消费者清理替换了原绑定或generation")
	}
	return nil
}

// CompleteConsumerUnbind 在真实Manager确认解绑后撤销原预留，不证明停止或材料已删除。
func (a *Authority) CompleteConsumerUnbind(ctx context.Context, caller certificates.Caller, bindingID string) error {
	permission, _, err := a.bindingGrant(ctx, caller)
	if err != nil {
		return err
	}
	if permission.certificate.access != certificates.Unbind || permission.id != bindingID {
		return fault.New("PERMISSION_DENIED", "不能撤销原意图之外的消费登记")
	}
	state, revision, err := a.loadBindingLedger(ctx)
	if err != nil {
		return err
	}
	index := bindingIndex(state, bindingID)
	if index < 0 {
		return fault.New("BINDING_REVOKED", "消费登记不存在")
	}
	entry := state.Entries[index]
	policy, err := bindingPolicyRevision(entry)
	if err != nil {
		return err
	}
	if policy != permission.policy || entry.Phase != bindingConfirmed || entry.Version == math.MaxUint64 {
		return fault.New("REVISION_CONFLICT", "完成解绑时消费登记已经变化")
	}
	if _, _, err := a.bindingGrant(ctx, caller); err != nil {
		return err
	}
	entry.Phase, entry.Version = bindingRevoked, entry.Version+1
	origin := bindingOriginFrom(permission.parent)
	entry.UnboundOrigin, entry.UnboundRevision = &origin, permission.certificate.expectedRevision
	state.Entries[index] = entry
	return a.saveBindingLedger(ctx, state, revision)
}
