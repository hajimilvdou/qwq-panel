// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"math"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 原策略参数与公开状态；服务创建另走同步真人入口 ========================

// RenewalPolicyArgs 保留原已接受的确认参数；SAN与消费者从私有登记读取。
type RenewalPolicyArgs struct {
	PolicyID      string          `json:"policy_id"`
	CertificateID string          `json:"certificate_id"`
	ProviderID    string          `json:"provider_id,omitempty"`
	ZoneID        string          `json:"zone_id,omitempty"`
	ChallengeType string          `json:"challenge_type,omitempty"`
	CA            certificates.CA `json:"ca"`
	BindingRefs   []string        `json:"binding_refs"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

// RenewalServiceArgs 仅引用已经由同步真人入口创建的实际账号。
type RenewalServiceArgs struct {
	PolicyID         string `json:"policy_id"`
	ServiceAccountID string `json:"service_account_id"`
}

// RenewalPolicyView 不包含审批主体、私有范围或可恢复运行许可。
type RenewalPolicyView struct {
	ID               string    `json:"id"`
	CertificateID    string    `json:"certificate_id"`
	Revision         string    `json:"revision"`
	State            string    `json:"state"`
	ExpiresAt        time.Time `json:"expires_at"`
	ServiceAccountID string    `json:"service_account_id,omitempty"`
}

// RegisterRenewalPolicy 只登记真实Approved的人类确认范围，初始等待实际服务账号。
func (a *Authority) RegisterRenewalPolicy(ctx context.Context, policyID, expectedRevision string) (RenewalPolicyView, error) {
	bounded, cancel, err := a.renewalContext(ctx)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	defer cancel()
	input, err := DecodeArguments[RenewalPolicyArgs](bounded, a)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	if input.PolicyID != policyID || !a.clock.Now().Before(input.ExpiresAt) {
		return RenewalPolicyView{}, fault.New("POLICY_SCOPE_DENIED", "续期策略或原确认到期时间无效")
	}
	origin, authorized, confirmed, err := a.renewalDispatch(bounded, "renewal.configure", policyID, expectedRevision)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	dependencies, err := a.readRenewalScope(bounded, input.CertificateID, input.ProviderID, input.ZoneID, input.ChallengeType, input.CA, input.BindingRefs)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	state, revision, err := a.loadRenewalLedger(bounded)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	entry := renewalRegistration{Version: 1, ID: policyID, Dependencies: dependencies, ExpiresAt: input.ExpiresAt,
		CreatedBy: authorized, AuthorizedBy: authorized, ConfirmationActor: confirmed, Origin: origin,
		BaseRevision: expectedRevision, State: renewalAwaitingService}
	index := renewalIndex(state, policyID)
	if index >= 0 {
		previous := state.Entries[index]
		if previous.Origin.OperationID == origin.OperationID && previous.Origin.ArgsDigest == origin.ArgsDigest && previous.BaseRevision == expectedRevision {
			if err := a.checkRenewalRegistration(bounded, previous); err != nil {
				return RenewalPolicyView{}, err
			}
			return renewalView(previous)
		}
		actual, err := renewalRevision(previous)
		if err != nil {
			return RenewalPolicyView{}, err
		}
		if expectedRevision != actual {
			return RenewalPolicyView{}, fault.New("REVISION_CONFLICT", "续期策略版本已变化")
		}
		if previous.Version == math.MaxUint64 {
			return RenewalPolicyView{}, fault.New("RESOURCE_EXHAUSTED", "续期策略版本已达上限")
		}
		entry.Version, entry.CreatedBy = previous.Version+1, previous.CreatedBy
		state.Entries[index] = entry
	} else {
		if expectedRevision != certificates.MissingRevision {
			return RenewalPolicyView{}, fault.New("REVISION_CONFLICT", "续期策略不存在，请重新预演")
		}
		if len(state.Entries) >= maxRenewalRegistrations {
			return RenewalPolicyView{}, fault.New("RESOURCE_EXHAUSTED", "续期策略登记已经达到上限")
		}
		state.Entries = append(state.Entries, entry)
	}
	for _, other := range state.Entries {
		if other.ID != policyID && other.Dependencies.Scope.CertificateID == input.CertificateID && other.State != renewalRevoked {
			return RenewalPolicyView{}, fault.New("POLICY_SCOPE_DENIED", "同一证书已有续期授权策略")
		}
	}
	if err := a.checkRenewalRegistration(bounded, entry); err != nil {
		return RenewalPolicyView{}, err
	}
	if _, _, _, err := a.renewalDispatch(bounded, "renewal.configure", policyID, expectedRevision); err != nil {
		return RenewalPolicyView{}, err
	}
	if err := a.saveRenewalLedger(bounded, state, revision); err != nil {
		return RenewalPolicyView{}, err
	}
	if _, _, _, err := a.renewalDispatch(bounded, "renewal.configure", policyID, expectedRevision); err != nil {
		return RenewalPolicyView{}, err
	}
	if err := a.checkRenewalRegistration(bounded, entry); err != nil {
		return RenewalPolicyView{}, err
	}
	return renewalView(entry)
}

// PrepareRenewalService 只读已确认私有策略，不创建账号、job或session证明。
func (a *Authority) PrepareRenewalService(ctx context.Context, who actor.Actor, policyID, expectedRevision string) (RenewalServiceRequest, error) {
	bounded, cancel, err := a.renewalContext(ctx)
	if err != nil {
		return RenewalServiceRequest{}, err
	}
	defer cancel()
	if err := a.authorizeRenewalPolicy(bounded, who, policyID); err != nil {
		return RenewalServiceRequest{}, err
	}
	entry, err := a.loadRenewalPolicy(bounded, policyID, expectedRevision)
	if err != nil {
		return RenewalServiceRequest{}, err
	}
	if err := a.checkRenewalRegistration(bounded, entry); err != nil {
		return RenewalServiceRequest{}, err
	}
	// 当前同步bootstrap可能已持有写事务；以下只读，不Ensure、不重开原job。
	if _, err := a.loadRenewalPolicy(bounded, policyID, expectedRevision); err != nil {
		return RenewalServiceRequest{}, err
	}
	if err := a.authorizeRenewalPolicy(bounded, who, policyID); err != nil {
		return RenewalServiceRequest{}, err
	}
	scope, err := certificates.CanonicalRenewalScope(entry.Dependencies.Scope)
	if err != nil {
		return RenewalServiceRequest{}, err
	}
	return RenewalServiceRequest{PolicyID: entry.ID, Scope: scope, ExpiresAt: entry.ExpiresAt}, nil
}

// AttachRenewalService 只登记已经由Root真实真人事务创建且scope精确的账号。
func (a *Authority) AttachRenewalService(ctx context.Context, policyID, expectedRevision string) (RenewalPolicyView, error) {
	bounded, cancel, err := a.renewalContext(ctx)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	defer cancel()
	input, err := DecodeArguments[RenewalServiceArgs](bounded, a)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	if input.PolicyID != policyID {
		return RenewalPolicyView{}, fault.New("POLICY_SCOPE_DENIED", "服务登记不属于原策略意图")
	}
	origin, _, confirmed, err := a.renewalDispatch(bounded, "renewal.attach_service", policyID, expectedRevision)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	state, revision, err := a.loadRenewalLedger(bounded)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	index := renewalIndex(state, policyID)
	if index < 0 {
		return RenewalPolicyView{}, fault.New("POLICY_SCOPE_DENIED", "服务登记需要已确认的私有续期策略")
	}
	entry := state.Entries[index]
	actual, err := renewalRevision(entry)
	if err != nil {
		return RenewalPolicyView{}, err
	}
	if entry.AttachedOrigin != nil && entry.AttachedOrigin.OperationID == origin.OperationID && entry.AttachedOrigin.ArgsDigest == origin.ArgsDigest && entry.AttachedRevision == expectedRevision {
		if err := a.checkRenewalRegistration(bounded, entry); err != nil {
			return RenewalPolicyView{}, err
		}
		return renewalView(entry)
	}
	if expectedRevision != actual {
		return RenewalPolicyView{}, fault.New("REVISION_CONFLICT", "续期服务登记版本已变化")
	}
	if err := a.checkRenewalRegistration(bounded, entry); err != nil {
		return RenewalPolicyView{}, err
	}
	if err := a.checkRenewalAccount(bounded, entry, input.ServiceAccountID, confirmed); err != nil {
		return RenewalPolicyView{}, err
	}
	if entry.Version == math.MaxUint64 {
		return RenewalPolicyView{}, fault.New("RESOURCE_EXHAUSTED", "续期策略版本已达上限")
	}
	entry.Version++
	entry.State, entry.ServiceAccountID = renewalActive, input.ServiceAccountID
	entry.AttachedOrigin, entry.AttachedBy, entry.AttachedRevision = &origin, confirmed, expectedRevision
	state.Entries[index] = entry
	if _, _, _, err := a.renewalDispatch(bounded, "renewal.attach_service", policyID, expectedRevision); err != nil {
		return RenewalPolicyView{}, err
	}
	if err := a.checkRenewalRegistration(bounded, entry); err != nil {
		return RenewalPolicyView{}, err
	}
	if err := a.saveRenewalLedger(bounded, state, revision); err != nil {
		return RenewalPolicyView{}, err
	}
	if _, _, _, err := a.renewalDispatch(bounded, "renewal.attach_service", policyID, expectedRevision); err != nil {
		return RenewalPolicyView{}, err
	}
	if err := a.checkRenewalRegistration(bounded, entry); err != nil {
		return RenewalPolicyView{}, err
	}
	return renewalView(entry)
}
