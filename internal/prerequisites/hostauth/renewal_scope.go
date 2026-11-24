// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"slices"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 精确证书、DNS、当前消费者与实际账号的逐次复核 ========================

func (a *Authority) readRenewalScope(ctx context.Context, certificateID, providerID, zoneID, challengeType string, ca certificates.CA, refs []string) (renewalDependencies, error) {
	if len(refs) == 0 || len(refs) > 8 {
		return renewalDependencies{}, fault.New("POLICY_SCOPE_DENIED", "续期必须指定有界的已确认消费绑定")
	}
	isHTTP01 := challengeType == "http-01"
	if !isHTTP01 && challengeType != "" && challengeType != "dns-01" {
		return renewalDependencies{}, fault.New("VALIDATION_FAILED", "不支持的 ACME 续期验证方式")
	}
	certificate, certificateRevision, found, err := a.loadCertificate(ctx, certificateID)
	if err != nil {
		return renewalDependencies{}, err
	}
	if !found {
		return renewalDependencies{}, fault.New("POLICY_SCOPE_DENIED", "续期需要既有证书的私有SAN登记")
	}

	var (
		providerScope    dns.Scope
		providerRevision string
		zoneRevision     string
		provider         providerRegistration
		zone             zoneRegistration
	)
	if isHTTP01 {
		if providerID != "" || zoneID != "" {
			return renewalDependencies{}, fault.New("VALIDATION_FAILED", "HTTP-01 自动续期无需提供 DNS provider_id 或 zone_id")
		}
	} else {
		var rerr error
		providerScope, providerRevision, zoneRevision, rerr = a.resolveScope(ctx, providerID, zoneID)
		if rerr != nil {
			return renewalDependencies{}, rerr
		}
		var actualProvider string
		provider, actualProvider, found, err = a.loadProvider(ctx, providerID)
		if err != nil {
			return renewalDependencies{}, err
		}
		if !found || actualProvider != providerRevision {
			return renewalDependencies{}, fault.New("CREDENTIAL_REVOKED", "续期提供商授权发生变化")
		}
		var actualZone string
		zone, actualZone, found, err = a.loadZone(ctx, providerID, zoneID)
		if err != nil {
			return renewalDependencies{}, err
		}
		if !found || actualZone != zoneRevision {
			return renewalDependencies{}, fault.New("ZONE_DENIED", "续期zone授权发生变化")
		}
		if err := a.authorizeRenewalDNS(ctx, provider, zone); err != nil {
			return renewalDependencies{}, err
		}
		credentials, err := a.providerCredentials(ctx, provider)
		credentials.Clear()
		if err != nil {
			return renewalDependencies{}, err
		}
	}

	state, _, err := a.loadBindingLedger(ctx)
	if err != nil {
		return renewalDependencies{}, err
	}
	confirmedCount := 0
	for _, entry := range state.Entries {
		if entry.CertificateID == certificateID && entry.Phase == bindingConfirmed {
			confirmedCount++
		}
	}
	if confirmedCount != len(refs) {
		return renewalDependencies{}, fault.New("POLICY_SCOPE_DENIED", "续期消费范围必须等于全部当前已确认绑定")
	}
	dependencies := renewalDependencies{CertificateRevision: certificateRevision, ProviderRevision: providerRevision,
		ZoneRevision: zoneRevision, Bindings: make([]renewalBinding, 0, len(refs))}
	issuance := certificates.IssuanceScope{Spec: cloneCertificateSpec(certificate.Spec), CA: ca}
	if isHTTP01 {
		issuance.ChallengeType = "http-01"
	} else {
		issuance.Provider = providerScope
	}
	scope := certificates.RenewalScope{OwnerID: a.ownerID, CertificateID: certificateID,
		Issuance:  issuance,
		Consumers: make([]certificates.Consumer, 0, len(refs))}
	ordered := slices.Clone(refs)
	slices.Sort(ordered)
	for index, id := range ordered {
		position := bindingIndex(state, id)
		if position < 0 || (index > 0 && ordered[index-1] == id) {
			return renewalDependencies{}, fault.New("POLICY_SCOPE_DENIED", "续期消费绑定不存在或重复")
		}
		entry := state.Entries[position]
		if entry.Phase != bindingConfirmed || entry.CertificateID != certificateID || entry.ConfirmedOrigin == nil {
			return renewalDependencies{}, fault.New("POLICY_SCOPE_DENIED", "续期消费尚未实际确认或换用了证书")
		}
		if err := a.checkBindingRegistration(ctx, entry); err != nil {
			return renewalDependencies{}, err
		}
		facts, err := a.currentRegisteredConsumer(ctx, entry.ConfirmedOrigin.invocation(), entry.Consumer)
		if err != nil {
			return renewalDependencies{}, err
		}
		if !bindingFactsMatch(entry, facts) {
			return renewalDependencies{}, fault.New("BINDING_REVOKED", "续期消费者的真实绑定或安装版本变化")
		}
		revision, err := bindingPolicyRevision(entry)
		if err != nil {
			return renewalDependencies{}, err
		}
		dependencies.Bindings = append(dependencies.Bindings, renewalBinding{ID: id, Revision: revision})
		scope.Consumers = append(scope.Consumers, entry.Consumer)
	}
	dependencies.Scope, err = certificates.CanonicalRenewalScope(scope)
	if err != nil {
		return renewalDependencies{}, err
	}
	if !isHTTP01 {
		actual, latestProvider, latestZone, err := a.resolveScope(ctx, providerID, zoneID)
		if err != nil {
			return renewalDependencies{}, err
		}
		if actual != providerScope || latestProvider != providerRevision || latestZone != zoneRevision {
			return renewalDependencies{}, fault.New("CREDENTIAL_REVOKED", "续期范围读取期间DNS授权变化")
		}
	}
	latest, _, err := a.loadBindingLedger(ctx)
	if err != nil {
		return renewalDependencies{}, err
	}
	for _, binding := range dependencies.Bindings {
		position := bindingIndex(latest, binding.ID)
		if position < 0 || latest.Entries[position].Phase != bindingConfirmed {
			return renewalDependencies{}, fault.New("BINDING_REVOKED", "续期读取期间消费绑定已移除或撤销")
		}
		entry := latest.Entries[position]
		actualRevision, err := bindingPolicyRevision(entry)
		if err != nil {
			return renewalDependencies{}, err
		}
		if actualRevision != binding.Revision {
			return renewalDependencies{}, fault.New("BINDING_REVOKED", "续期读取期间消费绑定已换代")
		}
		if err := a.checkBindingRegistration(ctx, entry); err != nil {
			return renewalDependencies{}, err
		}
	}
	if !isHTTP01 {
		if err := a.authorizeRenewalDNS(ctx, provider, zone); err != nil {
			return renewalDependencies{}, err
		}
	}
	return dependencies, nil
}

func (a *Authority) authorizeRenewalDNS(ctx context.Context, provider providerRegistration, zone zoneRegistration) error {
	if err := a.authorizer.Authorize(ctx, provider.CreatedBy, "system.dns:manage", authz.Resource{Name: "system.dns", NodeID: a.nodeID,
		Action: "domain.dns/providers.register", Subject: "plugins/domain.dns/resources/providers/" + provider.ID}); err != nil {
		return err
	}
	return a.authorizer.Authorize(ctx, zone.ConfirmedBy, "system.dns:manage", authz.Resource{Name: "system.dns", NodeID: a.nodeID,
		Action: "domain.dns/zones.authorize", Subject: "plugins/domain.dns/resources/zones/" + provider.ID + "/" + zone.ID})
}

func (a *Authority) checkRenewalRegistration(ctx context.Context, entry renewalRegistration) error {
	if entry.State == renewalRevoked || !a.clock.Now().Before(entry.ExpiresAt) {
		return fault.New("POLICY_REVOKED", "续期策略已撤销或到期")
	}
	if err := a.authorizeRenewalPolicy(ctx, entry.AuthorizedBy, entry.ID); err != nil {
		return err
	}
	if err := a.authorizeRenewalPolicy(ctx, entry.ConfirmationActor, entry.ID); err != nil {
		return err
	}
	refs := make([]string, 0, len(entry.Dependencies.Bindings))
	for _, binding := range entry.Dependencies.Bindings {
		refs = append(refs, binding.ID)
	}
	wanted := entry.Dependencies
	scope := wanted.Scope
	actual, err := a.readRenewalScope(ctx, scope.CertificateID, scope.Issuance.Provider.ProviderID, scope.Issuance.Provider.ZoneID, scope.Issuance.ChallengeType, scope.Issuance.CA, refs)
	if err != nil {
		return err
	}
	if !sameRenewalScope(actual.Scope, wanted.Scope) || actual.CertificateRevision != wanted.CertificateRevision ||
		actual.ProviderRevision != wanted.ProviderRevision || actual.ZoneRevision != wanted.ZoneRevision || !slices.Equal(actual.Bindings, wanted.Bindings) {
		return fault.New("POLICY_REVOKED", "续期固定证书、DNS或消费授权已换代")
	}
	if entry.State == renewalActive {
		return a.checkRenewalAccount(ctx, entry, entry.ServiceAccountID, entry.AttachedBy)
	}
	if err := a.authorizeRenewalPolicy(ctx, entry.AuthorizedBy, entry.ID); err != nil {
		return err
	}
	if err := a.authorizeRenewalPolicy(ctx, entry.ConfirmationActor, entry.ID); err != nil {
		return err
	}
	if !a.clock.Now().Before(entry.ExpiresAt) {
		return fault.New("POLICY_REVOKED", "续期范围复核期间策略已经到期")
	}
	return ctx.Err()
}

func (a *Authority) checkRenewalAccount(ctx context.Context, entry renewalRegistration, id string, confirmed actor.Actor) error {
	account, err := a.authorizer.ServiceAccount(ctx, id)
	if err != nil {
		return err
	}
	scope := account.Scope
	if account.Disabled || account.Role != authz.RoleOperator || account.CreatedBy != confirmed.ID || scope == nil || scope.Validate() != nil ||
		!scope.ExpiresAt.Equal(entry.ExpiresAt) || !slices.Equal(scope.Actions, []string{"tls.certificates/renew_existing"}) ||
		!slices.Equal(scope.NodeIDs, []string{a.nodeID}) || !slices.Equal(scope.Subjects, []string{"plugins/tls.certificates/resources/certificates/" + entry.Dependencies.Scope.CertificateID}) ||
		confirmed.Kind != actor.Human || !validInitiator(confirmed) {
		return fault.New("POLICY_SCOPE_DENIED", "续期账号的角色、创建者或精确权限不符")
	}
	if err := a.authorizeRenewalPolicy(ctx, confirmed, entry.ID); err != nil {
		return err
	}
	return a.authorizer.Authorize(ctx, actor.Actor{Kind: actor.Service, ID: account.ID}, "system.certificates:manage",
		authz.Resource{Name: "system.certificates", NodeID: a.nodeID, Action: scope.Actions[0], Subject: scope.Subjects[0]})
}
