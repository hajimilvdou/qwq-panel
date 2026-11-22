// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 单一有界 CAS 账本；无双键索引窗口 ========================

const maxBindingReservations = 256

const (
	bindingReserved  = "reserved"
	bindingConfirmed = "confirmed"
	bindingRevoked   = "revoked"
)

// origin 不使用 Invocation.MarshalJSON；这里只保存已核验的明确来源字段。
// 存档来源不包含 runtime proof，不能重开原 operation 或恢复执行权限。
type bindingOrigin struct {
	PluginID    string `json:"plugin_id"`
	InstanceID  string `json:"instance_id"`
	OperationID string `json:"operation_id"`
	Operation   string `json:"operation"`
	Subject     string `json:"subject"`
	ArgsDigest  string `json:"args_digest"`
}

type bindingRegistration struct {
	Version             uint64                `json:"version"`
	ID                  string                `json:"id"`
	CertificateID       string                `json:"certificate_id"`
	CertificateRevision string                `json:"certificate_revision"`
	Spec                certificates.Spec     `json:"spec"`
	Consumer            certificates.Consumer `json:"consumer"`
	CreatedBy           actor.Actor           `json:"created_by"`
	AuthorizedBy        actor.Actor           `json:"authorized_by"`
	ConfirmationActor   actor.Actor           `json:"confirmation_actor"`
	Origin              bindingOrigin         `json:"origin"`
	ConfigRevision      string                `json:"config_revision"`
	PluginVersion       string                `json:"plugin_version"`
	Phase               string                `json:"phase"`
	ConfirmedRevision   string                `json:"confirmed_revision,omitempty"`
	ConfirmedOrigin     *bindingOrigin        `json:"confirmed_origin,omitempty"`
	UnboundOrigin       *bindingOrigin        `json:"unbound_origin,omitempty"`
	UnboundRevision     string                `json:"unbound_revision,omitempty"`
}

type bindingLedger struct {
	Version uint32                `json:"version"`
	OwnerID string                `json:"owner_id"`
	NodeID  string                `json:"node_id"`
	Entries []bindingRegistration `json:"entries"`
}

type bindingScopeKey struct {
	CertificateID string
	Consumer      certificates.Consumer
}

func (bindingOrigin) String() string         { return "hostauth.bindingOrigin{[REDACTED]}" }
func (bindingOrigin) GoString() string       { return "hostauth.bindingOrigin{[REDACTED]}" }
func (bindingRegistration) String() string   { return "hostauth.bindingRegistration{[REDACTED]}" }
func (bindingRegistration) GoString() string { return "hostauth.bindingRegistration{[REDACTED]}" }

func (o bindingOrigin) invocation() Invocation {
	return Invocation{PluginID: o.PluginID, InstanceID: o.InstanceID, OperationID: o.OperationID, Operation: o.Operation, Subject: o.Subject}
}

func (o bindingOrigin) valid(certificateID, operation string) bool {
	return o.PluginID == "tls.certificates" && o.InstanceID == operations.ControllerDispatchInstance &&
		ids.Valid(o.OperationID, ids.Operation) && o.Operation == operation &&
		o.Subject == "plugins/tls.certificates/resources/certificates/"+certificateID && operations.ValidArgumentDigest(o.ArgsDigest)
}

func bindingOriginFrom(value *execution) bindingOrigin {
	call := value.invocation
	return bindingOrigin{PluginID: call.PluginID, InstanceID: call.InstanceID, OperationID: call.OperationID,
		Operation: call.Operation, Subject: call.Subject, ArgsDigest: value.snapshot.ArgsDigest}
}

func (a *Authority) bindingLedgerKey() (string, error) {
	return registryKey("consumer-bindings", a.ownerID, a.nodeID)
}

func validBindingConfirmation(who actor.Actor) bool {
	return who == (actor.Actor{}) || (who.Kind == actor.Human && validInitiator(who))
}

func (a *Authority) loadBindingLedger(ctx context.Context) (bindingLedger, string, error) {
	key, err := a.bindingLedgerKey()
	if err != nil {
		return bindingLedger{}, "", err
	}
	state := bindingLedger{Version: 1, OwnerID: a.ownerID, NodeID: a.nodeID, Entries: []bindingRegistration{}}
	revision, found, err := loadPrivate(ctx, a, key, &state)
	if err != nil || !found {
		return state, revision, err
	}
	if state.Version != 1 || state.OwnerID != a.ownerID || state.NodeID != a.nodeID || state.Entries == nil || len(state.Entries) > maxBindingReservations {
		return bindingLedger{}, "", fault.New("STATE_INVALID", "消费绑定账本的作用域或容量无效")
	}
	seen := make(map[string]bool, len(state.Entries))
	scopes := make(map[bindingScopeKey]bool, len(state.Entries))
	for _, entry := range state.Entries {
		consumer, consumerErr := certificates.CanonicalConsumer(entry.Consumer)
		spec, specErr := certificates.CanonicalSpec(entry.Spec)
		validScope := ids.Valid(entry.ID, "certbind") && names.ID(entry.CertificateID) && validDigest(entry.CertificateRevision) &&
			consumerErr == nil && consumer == entry.Consumer && consumer.NodeID == a.nodeID && specErr == nil && sameCertificateSpec(spec, entry.Spec)
		validIntent := entry.Version != 0 && validInitiator(entry.CreatedBy) && validInitiator(entry.AuthorizedBy) &&
			validBindingConfirmation(entry.ConfirmationActor) && entry.Origin.valid(entry.CertificateID, "bindings.reserve") &&
			boundedSourceVersion(entry.ConfigRevision) && boundedSourceVersion(entry.PluginVersion)
		validPhase := entry.Phase == bindingReserved || entry.Phase == bindingConfirmed || entry.Phase == bindingRevoked
		validConfirmed := entry.ConfirmedOrigin == nil && entry.ConfirmedRevision == ""
		if entry.ConfirmedOrigin != nil {
			validConfirmed = (entry.ConfirmedOrigin.valid(entry.CertificateID, "bindings.bind") ||
				entry.ConfirmedOrigin.valid(entry.CertificateID, "bindings.deploy") ||
				entry.ConfirmedOrigin.valid(entry.CertificateID, "bindings.rollback")) && boundedSourceVersion(entry.ConfirmedRevision)
		}
		validUnbound := entry.UnboundOrigin == nil && entry.UnboundRevision == ""
		if entry.UnboundOrigin != nil {
			validUnbound = entry.Phase == bindingRevoked && entry.ConfirmedOrigin != nil &&
				entry.UnboundOrigin.valid(entry.CertificateID, "bindings.unbind") && validDigest(entry.UnboundRevision)
		}
		scope := bindingScopeKey{CertificateID: entry.CertificateID, Consumer: entry.Consumer}
		if !validScope || !validIntent || !validPhase || !validConfirmed || !validUnbound || (entry.Phase == bindingConfirmed && entry.ConfirmedOrigin == nil) || seen[entry.ID] || scopes[scope] {
			return bindingLedger{}, "", fault.New("STATE_INVALID", "消费绑定登记的范围、来源或状态无效")
		}
		seen[entry.ID] = true
		scopes[scope] = true
	}
	return state, revision, nil
}

func sameBindingScope(entry bindingRegistration, certificateID string, consumer certificates.Consumer) bool {
	return entry.CertificateID == certificateID && entry.Consumer == consumer
}

func bindingIndex(state bindingLedger, id string) int {
	for index, entry := range state.Entries {
		if entry.ID == id {
			return index
		}
	}
	return -1
}

// policy revision 只描述精确授权范围与代际；配置确认不是扩大范围的许可。
func bindingPolicyRevision(entry bindingRegistration) (string, error) {
	raw, err := json.Marshal([]any{entry.ID, entry.CertificateID, entry.CertificateRevision, entry.Spec, entry.Consumer, entry.Version, entry.PluginVersion})
	if err != nil {
		return "", fault.New("STATE_INVALID", "消费绑定范围无法计算版本")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func reservationView(entry bindingRegistration) (BindingReservation, error) {
	revision, err := bindingPolicyRevision(entry)
	return BindingReservation{BindingRef: entry.ID, CertificateID: entry.CertificateID, Consumer: entry.Consumer, Revision: revision, Status: entry.Phase}, err
}

func (a *Authority) saveBindingLedger(ctx context.Context, state bindingLedger, expected string) error {
	key, err := a.bindingLedgerKey()
	if err != nil {
		return err
	}
	_, err = store.Save(ctx, a.repository, key, expected, state)
	return err
}

func validateBindingSpec(spec certificates.Spec, consumer certificates.Consumer) error {
	if spec.Purpose == tlsmgr.TestServerTLS && !consumer.Test {
		return fault.New("TEST_CERTIFICATE_DENIED", "普通消费者不能使用测试证书预留")
	}
	if spec.Purpose != tlsmgr.ServerTLS && spec.Purpose != tlsmgr.TestServerTLS {
		return fault.New("CERTIFICATE_PURPOSE_INVALID", "消费绑定需要服务端 TLS 证书用途")
	}
	return tlsmgr.Covers(tlsmgr.CertificateMetadata{SANs: spec.SANs}, consumer.SNI)
}

func (a *Authority) checkBindingRegistration(ctx context.Context, entry bindingRegistration) error {
	if entry.Phase == bindingRevoked {
		return fault.New("BINDING_REVOKED", "消费预留授权已撤销")
	}
	return a.checkBindingDependencies(ctx, entry)
}

// checkBindingDependencies复核原证书和确认主体，供普通步骤及已完成解绑的只读重放复用。
func (a *Authority) checkBindingDependencies(ctx context.Context, entry bindingRegistration) error {
	certificate, revision, found, err := a.loadCertificate(ctx, entry.CertificateID)
	if err != nil {
		return err
	}
	if !found || revision != entry.CertificateRevision || !sameCertificateSpec(certificate.Spec, entry.Spec) {
		return fault.New("BINDING_REVOKED", "消费绑定的证书或精确 SAN 登记已变化")
	}
	if err := validateBindingSpec(entry.Spec, entry.Consumer); err != nil {
		return err
	}
	permission := "system.certificates:manage"
	resource := authz.Resource{Name: "system.certificates", NodeID: a.nodeID, Action: entry.Origin.PluginID + "/" + entry.Origin.Operation,
		Subject: "plugins/tls.certificates/resources/certificates/" + entry.CertificateID}
	if err := a.authorizer.Authorize(ctx, entry.AuthorizedBy, permission, resource); err != nil {
		return err
	}
	if entry.ConfirmationActor != (actor.Actor{}) {
		return a.authorizer.Authorize(ctx, entry.ConfirmationActor, permission, resource)
	}
	return nil
}
