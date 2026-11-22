// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 原受控参数与预留视图 ========================

type ReserveBindingArgs struct {
	CertificateID          string                `json:"certificate_id"`
	Consumer               certificates.Consumer `json:"consumer"`
	ExpectedConfigRevision string                `json:"expected_config_revision"`
}

type BindCertificateArgs struct {
	CertificateID string `json:"certificate_id"`
	BindingRef    string `json:"binding_ref"`
	AttemptID     string `json:"attempt_id"`
	Generation    uint64 `json:"generation"`
}

// BindingReservation 不携带材料、原actor或可恢复运行许可。
type BindingReservation struct {
	BindingRef    string                `json:"binding_ref"`
	CertificateID string                `json:"certificate_id"`
	Consumer      certificates.Consumer `json:"consumer"`
	Revision      string                `json:"revision"`
	Status        string                `json:"status"`
}

// ReserveBinding 只从已接受的高风险 operation 参数预留稳定消费 ID。
func (a *Authority) ReserveBinding(ctx context.Context, certificateID, expectedRevision string) (BindingReservation, error) {
	if a == nil || a.reservations == nil || ctx == nil {
		return BindingReservation{}, fault.New("BACKEND_REQUIRED", "消费预留需要真实宿主授权来源")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	value, err := a.current(bounded)
	if err != nil {
		return BindingReservation{}, err
	}
	if value.invocation.PluginID != "tls.certificates" || value.invocation.Operation != "bindings.reserve" ||
		!names.ID(certificateID) || value.invocation.Subject != "plugins/tls.certificates/resources/certificates/"+certificateID {
		return BindingReservation{}, fault.New("PERMISSION_DENIED", "原 operation 不能预留该证书的消费者")
	}
	if err := validateCertificateAction(value.snapshot.Action, certificates.Bind); err != nil {
		return BindingReservation{}, err
	}
	if err := a.RequireRevision(bounded, expectedRevision); err != nil {
		return BindingReservation{}, err
	}
	if !validDigest(expectedRevision) {
		return BindingReservation{}, fault.New("VALIDATION_FAILED", "预留需要既有证书的有效资源版本")
	}
	input, err := DecodeArguments[ReserveBindingArgs](bounded, a)
	if err != nil {
		return BindingReservation{}, err
	}
	want, err := certificates.CanonicalConsumer(input.Consumer)
	if err != nil || input.CertificateID != certificateID || want.NodeID != a.nodeID || !boundedSourceVersion(input.ExpectedConfigRevision) {
		return BindingReservation{}, fault.New("PERMISSION_DENIED", "原预留参数的证书、节点或配置前置条件无效")
	}
	if err := a.authorizeConsumerConfiguration(bounded, value.snapshot.Actor, a.nodeID, want.PluginID); err != nil {
		return BindingReservation{}, err
	}
	certificate, certificateRevision, found, err := a.loadCertificate(bounded, certificateID)
	if err != nil {
		return BindingReservation{}, err
	}
	if !found {
		return BindingReservation{}, fault.New("NOT_FOUND", "消费预留的私有证书登记不存在")
	}
	facts, err := a.reservations.AuthorizeReservation(bounded, value.invocation, want)
	if err != nil {
		return BindingReservation{}, err
	}
	consumer, err := certificates.CanonicalConsumer(facts.Consumer)
	want.Test = consumer.Test // 仅使用宿主授权事实；请求不能升级测试信任。
	if err != nil || consumer != want || !boundedSourceVersion(facts.ConfigRevision) || !boundedSourceVersion(facts.PluginVersion) {
		return BindingReservation{}, fault.New("BINDING_DENIED", "真实预留来源与拟建消费者不符")
	}
	if facts.ConfigRevision != input.ExpectedConfigRevision {
		return BindingReservation{}, fault.New("REVISION_CONFLICT", "消费者配置在预留前已经变化")
	}
	if err := validateBindingSpec(certificate.Spec, consumer); err != nil {
		return BindingReservation{}, err
	}
	if _, err := a.current(bounded); err != nil {
		return BindingReservation{}, err
	}
	state, revision, err := a.loadBindingLedger(bounded)
	if err != nil {
		return BindingReservation{}, err
	}
	origin := bindingOriginFrom(value)
	index := -1
	for i, entry := range state.Entries {
		if sameBindingScope(entry, certificateID, consumer) {
			index = i
			break
		}
	}
	entry := bindingRegistration{Version: 1, CertificateID: certificateID, CertificateRevision: certificateRevision, Spec: cloneCertificateSpec(certificate.Spec),
		Consumer: consumer, CreatedBy: value.snapshot.Actor, AuthorizedBy: value.snapshot.Actor, ConfirmationActor: value.snapshot.ConfirmationActor,
		Origin: origin, ConfigRevision: facts.ConfigRevision, PluginVersion: facts.PluginVersion, Phase: bindingReserved}
	if index >= 0 {
		previous := state.Entries[index]
		if previous.Origin == origin && previous.ConfigRevision == facts.ConfigRevision && previous.PluginVersion == facts.PluginVersion &&
			previous.CertificateRevision == certificateRevision && previous.Phase != bindingRevoked {
			if err := a.checkBindingRegistration(bounded, previous); err != nil {
				return BindingReservation{}, err
			}
			return reservationView(previous)
		}
		if previous.Version == ^uint64(0) {
			return BindingReservation{}, fault.New("RESOURCE_EXHAUSTED", "消费绑定授权代际已经耗尽")
		}
		entry.ID, entry.CreatedBy, entry.Version = previous.ID, previous.CreatedBy, previous.Version+1
		if previous.Phase == bindingConfirmed && previous.PluginVersion == facts.PluginVersion && previous.CertificateRevision == certificateRevision {
			entry.Phase, entry.ConfirmedOrigin, entry.ConfirmedRevision = bindingConfirmed, previous.ConfirmedOrigin, previous.ConfirmedRevision
		}
		state.Entries[index] = entry
	} else {
		if len(state.Entries) >= maxBindingReservations {
			return BindingReservation{}, fault.New("RESOURCE_EXHAUSTED", "消费预留登记已经达到上限")
		}
		entry.ID, err = newBindingReference()
		if err != nil {
			return BindingReservation{}, err
		}
		if bindingIndex(state, entry.ID) >= 0 {
			return BindingReservation{}, fault.New("REVISION_CONFLICT", "消费预留标识冲突，请重新提交")
		}
		state.Entries = append(state.Entries, entry)
	}
	if _, err := a.current(bounded); err != nil {
		return BindingReservation{}, err
	}
	if err := a.authorizeConsumerConfiguration(bounded, value.snapshot.Actor, a.nodeID, consumer.PluginID); err != nil {
		return BindingReservation{}, err
	}
	if err := a.saveBindingLedger(bounded, state, revision); err != nil {
		return BindingReservation{}, err
	}
	if _, err := a.current(bounded); err != nil {
		return BindingReservation{}, err
	}
	if err := a.checkBindingRegistration(bounded, entry); err != nil {
		return BindingReservation{}, err
	}
	return reservationView(entry)
}

// 复用宿主 ID 生成器；熵源失败只能拒绝登记，不能生成可预测的替代 ID。
func newBindingReference() (id string, err error) {
	defer func() {
		if recover() != nil {
			id, err = "", fault.New("ID_UNAVAILABLE", "宿主绑定标识生成失败")
		}
	}()
	return ids.New(nil).New("certbind"), nil
}
