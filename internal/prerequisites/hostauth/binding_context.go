// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 当次真实绑定 operation 的私有范围 ========================

type bindingExecutionKey struct{}

type bindingExecution struct {
	parent      *execution
	certificate *certificateExecution
	id          string
	policy      string
	facts       ConsumerFacts
}

func (*bindingExecution) String() string               { return "hostauth.bindingExecution{[REDACTED]}" }
func (*bindingExecution) GoString() string             { return "hostauth.bindingExecution{[REDACTED]}" }
func (*bindingExecution) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// BindingContext 从原Args加载固定预留；部署重读实际已提交消费者配置。
// 解绑只持有原confirmed范围，停止/脱离事实由真实Bindings后端确认。
func (a *Authority) BindingContext(ctx context.Context, certificateID, expectedRevision string) (context.Context, certificates.Caller, error) {
	value, input, access, err := a.acceptedBindingIntent(ctx, certificateID, expectedRevision)
	if err != nil {
		return nil, certificates.Caller{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	state, _, err := a.loadBindingLedger(bounded)
	if err != nil {
		return nil, certificates.Caller{}, err
	}
	index := bindingIndex(state, input.BindingRef)
	if index < 0 || state.Entries[index].CertificateID != certificateID {
		return nil, certificates.Caller{}, fault.New("BINDING_DENIED", "原绑定不属于该私有证书预留")
	}
	entry := state.Entries[index]
	if err := a.checkBindingRegistration(bounded, entry); err != nil {
		return nil, certificates.Caller{}, err
	}
	if err := a.authorizeConsumerConfiguration(bounded, value.snapshot.Actor, a.nodeID, entry.Consumer.PluginID); err != nil {
		return nil, certificates.Caller{}, err
	}
	facts := ConsumerFacts{Consumer: entry.Consumer}
	if access == certificates.Bind {
		facts, err = a.currentRegisteredConsumer(bounded, value.invocation, entry.Consumer)
		if err != nil {
			return nil, certificates.Caller{}, err
		}
		if !bindingFactsMatch(entry, facts) {
			return nil, certificates.Caller{}, fault.New("BINDING_DENIED", "真实配置未消费该预留或安装版本已经变化")
		}
	} else if entry.Phase != bindingConfirmed {
		return nil, certificates.Caller{}, fault.New("BINDING_DENIED", "只能解除已真实确认的原绑定")
	}
	policy, err := bindingPolicyRevision(entry)
	if err != nil {
		return nil, certificates.Caller{}, err
	}
	grant := &certificateExecution{parent: value, certificateID: certificateID, attemptID: input.AttemptID, registryRevision: entry.CertificateRevision,
		expectedRevision: expectedRevision, spec: cloneCertificateSpec(entry.Spec), generation: input.Generation, access: access}
	permission := &bindingExecution{parent: value, certificate: grant, id: entry.ID, policy: policy, facts: facts}
	bound := context.WithValue(context.WithValue(ctx, certificateExecutionKey{}, grant), bindingExecutionKey{}, permission)
	caller := certificates.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	if _, _, err := a.bindingGrant(bound, caller); err != nil {
		return nil, certificates.Caller{}, err
	}
	return bound, caller, nil
}

func (a *Authority) bindingGrant(ctx context.Context, caller certificates.Caller) (*bindingExecution, bindingRegistration, error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, bindingRegistration{}, err
	}
	permission, found := ctx.Value(bindingExecutionKey{}).(*bindingExecution)
	if !found || permission == nil || permission.parent != value || permission.certificate == nil {
		return nil, bindingRegistration{}, fault.New("PERMISSION_DENIED", "消费绑定缺少当次私有运行范围")
	}
	certificate, err := a.certificateGrant(ctx, caller)
	if err != nil {
		return nil, bindingRegistration{}, err
	}
	renewal, isRenewal := ctx.Value(renewalExecutionKey{}).(*renewalExecution)
	isRenewal = isRenewal && renewal != nil && renewal.parent == value && certificate.access == certificates.Bind
	if certificate != permission.certificate || (certificate.access != certificates.Bind && certificate.access != certificates.Unbind) ||
		(!isRenewal && bindingOperationAccess(value.invocation.Operation) != certificate.access) {
		return nil, bindingRegistration{}, fault.New("PERMISSION_DENIED", "消费绑定与原证书许可不符")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	state, _, err := a.loadBindingLedger(bounded)
	if err != nil {
		return nil, bindingRegistration{}, err
	}
	index := bindingIndex(state, permission.id)
	if index < 0 {
		return nil, bindingRegistration{}, fault.New("BINDING_REVOKED", "消费绑定登记已经移除")
	}
	entry := state.Entries[index]
	policy, err := bindingPolicyRevision(entry)
	if err != nil {
		return nil, bindingRegistration{}, err
	}
	if policy != permission.policy || entry.CertificateID != certificate.certificateID || entry.Consumer != permission.facts.Consumer {
		return nil, bindingRegistration{}, fault.New("BINDING_REVOKED", "消费授权的证书、范围或代际已变化")
	}
	if err := a.checkBindingRegistration(bounded, entry); err != nil {
		return nil, bindingRegistration{}, err
	}
	if !isRenewal {
		if err := a.authorizeConsumerConfiguration(bounded, value.snapshot.Actor, a.nodeID, entry.Consumer.PluginID); err != nil {
			return nil, bindingRegistration{}, err
		}
	}
	if certificate.access == certificates.Bind {
		facts, err := a.currentRegisteredConsumer(bounded, value.invocation, entry.Consumer)
		if err != nil {
			return nil, bindingRegistration{}, err
		}
		if facts != permission.facts {
			return nil, bindingRegistration{}, fault.New("BINDING_REVOKED", "绑定步骤之间真实配置或安装事实已变化")
		}
	} else if entry.Phase != bindingConfirmed {
		return nil, bindingRegistration{}, fault.New("BINDING_REVOKED", "原解绑范围不再是已确认绑定")
	}
	if _, err := a.current(bounded); err != nil {
		return nil, bindingRegistration{}, err
	}
	current, _, err := a.loadBindingLedger(bounded)
	if err != nil {
		return nil, bindingRegistration{}, err
	}
	index = bindingIndex(current, permission.id)
	if index < 0 {
		return nil, bindingRegistration{}, fault.New("BINDING_REVOKED", "事实读取期间绑定登记已移除")
	}
	entry = current.Entries[index]
	actual, err := bindingPolicyRevision(entry)
	if err != nil {
		return nil, bindingRegistration{}, err
	}
	if actual != permission.policy {
		return nil, bindingRegistration{}, fault.New("BINDING_REVOKED", "事实读取期间绑定授权已经换代")
	}
	if err := a.checkBindingRegistration(bounded, entry); err != nil {
		return nil, bindingRegistration{}, err
	}
	return permission, entry, nil
}

// AcceptedBindRequest 只从私有原operation范围构造请求，不接受替代参数。
func (a *Authority) AcceptedBindRequest(ctx context.Context) (certificates.BindRequest, error) {
	value, err := a.current(ctx)
	if err != nil {
		return certificates.BindRequest{}, err
	}
	caller := certificates.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	permission, entry, err := a.bindingGrant(ctx, caller)
	if err != nil {
		return certificates.BindRequest{}, err
	}
	grant := permission.certificate
	if grant.access != certificates.Bind {
		return certificates.BindRequest{}, fault.New("PERMISSION_DENIED", "解绑上下文不能取得部署请求")
	}
	return certificates.BindRequest{Caller: caller, CertificateID: grant.certificateID, AttemptID: grant.attemptID,
		ExpectedRevision: grant.expectedRevision, Generation: grant.generation, Consumer: entry.Consumer}, nil
}

// ConfirmConsumerBinding 仅供真实材料校验后的Bindings adapter确认授权；
// confirmed是权限状态，运行代与健康结果仍由实际部署后端单独确认。
func (a *Authority) ConfirmConsumerBinding(ctx context.Context, caller certificates.Caller, certificateID string, generation uint64, consumer certificates.Consumer) (certificates.HostBinding, error) {
	permission, entry, err := a.bindingGrant(ctx, caller)
	if err != nil {
		return certificates.HostBinding{}, err
	}
	grant := permission.certificate
	if grant.access != certificates.Bind || certificateID != grant.certificateID || generation != grant.generation || consumer != entry.Consumer {
		return certificates.HostBinding{}, fault.New("PERMISSION_DENIED", "材料确认不能换用证书、代或消费者")
	}
	if renewal, ok := ctx.Value(renewalExecutionKey{}).(*renewalExecution); ok && renewal != nil {
		// 精确service续期复用原人类confirmed来源，不把renew_existing写成新的确认Origin。
		if _, _, err := a.bindingGrant(ctx, caller); err != nil {
			return certificates.HostBinding{}, err
		}
		return certificates.HostBinding{ID: entry.ID, CertificateID: certificateID, Generation: generation, Consumer: entry.Consumer,
			PolicyRevision: permission.policy}, nil
	}
	state, revision, err := a.loadBindingLedger(ctx)
	if err != nil {
		return certificates.HostBinding{}, err
	}
	index := bindingIndex(state, entry.ID)
	if index < 0 {
		return certificates.HostBinding{}, fault.New("BINDING_REVOKED", "确认期间绑定登记已移除")
	}
	actual, err := bindingPolicyRevision(state.Entries[index])
	if err != nil {
		return certificates.HostBinding{}, err
	}
	if actual != permission.policy || state.Entries[index].Phase == bindingRevoked {
		return certificates.HostBinding{}, fault.New("BINDING_REVOKED", "确认期间授权已经换代或撤销")
	}
	origin := bindingOriginFrom(permission.parent)
	confirmed := state.Entries[index]
	if confirmed.Phase != bindingConfirmed || confirmed.ConfirmedOrigin == nil || *confirmed.ConfirmedOrigin != origin || confirmed.ConfirmedRevision != permission.facts.ConfigRevision {
		confirmed.Phase, confirmed.ConfirmedOrigin, confirmed.ConfirmedRevision = bindingConfirmed, &origin, permission.facts.ConfigRevision
		state.Entries[index] = confirmed
		if _, _, err := a.bindingGrant(ctx, caller); err != nil {
			return certificates.HostBinding{}, err
		}
		if err := a.saveBindingLedger(ctx, state, revision); err != nil {
			return certificates.HostBinding{}, err
		}
	}
	if _, _, err := a.bindingGrant(ctx, caller); err != nil {
		return certificates.HostBinding{}, err
	}
	return certificates.HostBinding{ID: entry.ID, CertificateID: certificateID, Generation: generation, Consumer: entry.Consumer, PolicyRevision: permission.policy}, nil
}
