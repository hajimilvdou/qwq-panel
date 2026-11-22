// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"slices"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/provider"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 显式 zone 确认与不可扩大的 DNS 上下文 ========================

type ZoneArgs struct {
	ProviderID string `json:"provider_id"`
	ZoneID     string `json:"zone_id"`
}

type DNSArgs struct {
	ProviderID string         `json:"provider_id"`
	ZoneID     string         `json:"zone_id"`
	AttemptID  string         `json:"attempt_id,omitempty"`
	Change     *dns.Change    `json:"change,omitempty"`
	Name       string         `json:"name,omitempty"`
	Type       dns.RecordType `json:"type,omitempty"`
	Value      string         `json:"value,omitempty"`
}

func (a *Authority) AuthorizeZone(ctx context.Context, providerID, zoneID, expected string) (dns.Scope, string, error) {
	value, err := a.current(ctx)
	if err != nil {
		return dns.Scope{}, "", err
	}
	if value.invocation.PluginID != "domain.dns" || value.invocation.Operation != "zones.authorize" || value.snapshot.Actor.Kind == actor.Service {
		return dns.Scope{}, "", fault.New("PERMISSION_DENIED", "当前 operation 不能确认 zone")
	}
	input, err := DecodeArguments[ZoneArgs](ctx, a)
	if err != nil {
		return dns.Scope{}, "", err
	}
	if input.ProviderID != providerID || input.ZoneID != zoneID || !names.ID(providerID) || !names.ID(zoneID) || value.invocation.Subject != "plugins/domain.dns/resources/zones/"+providerID+"/"+zoneID {
		return dns.Scope{}, "", fault.New("PERMISSION_DENIED", "zone 不属于已接受的 operation")
	}
	if err := a.RequireRevision(ctx, expected); err != nil {
		return dns.Scope{}, "", err
	}
	registration, providerRevision, found, err := a.loadProvider(ctx, providerID)
	if err != nil {
		return dns.Scope{}, "", err
	}
	if !found || registration.Phase != providerActive {
		return dns.Scope{}, "", fault.New("ZONE_DENIED", "提供商尚未授权或已撤销")
	}
	credentials, err := a.providerCredentials(ctx, registration)
	credentials.Clear()
	if err != nil {
		return dns.Scope{}, "", err
	}
	index := slices.IndexFunc(registration.Zones, func(zone provider.Zone) bool { return zone.ID == zoneID })
	if index < 0 {
		return dns.Scope{}, "", fault.New("ZONE_DENIED", "zone 不属于实际提供商发现结果")
	}
	zone, revision, existing, err := a.loadZone(ctx, providerID, zoneID)
	if err != nil {
		return dns.Scope{}, "", err
	}
	if existing && zone.OperationID == value.invocation.OperationID && zone.ArgsDigest == value.snapshot.ArgsDigest && zone.BaseRevision == expected {
		if !zone.Enabled {
			return dns.Scope{}, "", fault.New("ZONE_DENIED", "原 zone 确认已撤销，不能重入激活")
		}
		scope, err := registeredScope(registration, providerRevision, zone, revision)
		return scope, revision, err
	}
	if (existing && revision != expected) || (!existing && expected != "absent") {
		return dns.Scope{}, "", fault.New("REVISION_CONFLICT", "zone 授权版本已变化")
	}
	actual := registration.Zones[index]
	zone = zoneRegistration{Version: 1, OwnerID: a.ownerID, NodeID: a.nodeID, ProviderID: providerID, ID: zoneID,
		Name: actual.Name, Kind: registration.Kind, ConfirmedBy: value.snapshot.Actor, Enabled: true, ProviderRevision: providerRevision,
		OperationID: value.invocation.OperationID, ArgsDigest: value.snapshot.ArgsDigest, BaseRevision: expected}
	if _, err := a.current(ctx); err != nil {
		return dns.Scope{}, "", err
	}
	_, latest, found, err := a.loadProvider(ctx, providerID)
	if err != nil {
		return dns.Scope{}, "", err
	}
	if !found || latest != providerRevision {
		return dns.Scope{}, "", fault.New("REVISION_CONFLICT", "确认期间提供商版本变化")
	}
	key, err := a.zoneKey(providerID, zoneID)
	if err != nil {
		return dns.Scope{}, "", err
	}
	revision, err = store.Save(ctx, a.repository, key, revision, zone)
	if err != nil {
		return dns.Scope{}, "", err
	}
	scope, latestProvider, latestZone, err := a.resolveScope(ctx, providerID, zoneID)
	if err != nil {
		return dns.Scope{}, "", err
	}
	if latestProvider != providerRevision || latestZone != revision {
		return dns.Scope{}, "", fault.New("REVISION_CONFLICT", "zone 确认提交后授权版本变化")
	}
	return scope, revision, nil
}

func (a *Authority) resolveScope(ctx context.Context, providerID, zoneID string) (dns.Scope, string, string, error) {
	registration, providerRevision, found, err := a.loadProvider(ctx, providerID)
	if err != nil {
		return dns.Scope{}, "", "", err
	}
	if !found {
		return dns.Scope{}, "", "", fault.New("ZONE_DENIED", "提供商登记不存在")
	}
	zone, zoneRevision, found, err := a.loadZone(ctx, providerID, zoneID)
	if err != nil {
		return dns.Scope{}, "", "", err
	}
	if !found {
		return dns.Scope{}, "", "", fault.New("ZONE_DENIED", "zone 尚未明确授权")
	}
	scope, err := registeredScope(registration, providerRevision, zone, zoneRevision)
	return scope, providerRevision, zoneRevision, err
}

type dnsExecutionKey struct{}
type dnsExecution struct {
	parent           *execution
	scope            dns.Scope
	providerRevision string
	zoneRevision     string
	challenge        bool
	certificate      *certificateExecution
}

// DNSContext 仅按当前已接受 DNS operation 的 provider/zone 建立私有范围。
func (a *Authority) DNSContext(ctx context.Context, providerID, zoneID string) (context.Context, dns.Caller, dns.Scope, error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, dns.Caller{}, dns.Scope{}, err
	}
	if value.invocation.PluginID != "domain.dns" || (value.invocation.Operation != "records.list" && value.invocation.Operation != "records.apply" && value.invocation.Operation != "records.reconcile" && value.invocation.Operation != "dns.check") {
		return nil, dns.Caller{}, dns.Scope{}, fault.New("PERMISSION_DENIED", "当前 operation 不能建立 DNS 范围")
	}
	input, err := DecodeArguments[DNSArgs](ctx, a)
	if err != nil {
		return nil, dns.Caller{}, dns.Scope{}, err
	}
	if input.ProviderID != providerID || input.ZoneID != zoneID || value.invocation.Subject != "plugins/domain.dns/resources/zones/"+providerID+"/"+zoneID {
		return nil, dns.Caller{}, dns.Scope{}, fault.New("PERMISSION_DENIED", "DNS 参数不属于已接受的 zone")
	}
	if err := validateDNSIntent(value.invocation.Operation, input); err != nil {
		return nil, dns.Caller{}, dns.Scope{}, err
	}
	scope, providerRevision, zoneRevision, err := a.resolveScope(ctx, providerID, zoneID)
	if err != nil {
		return nil, dns.Caller{}, dns.Scope{}, err
	}
	grant := &dnsExecution{parent: value, scope: scope, providerRevision: providerRevision, zoneRevision: zoneRevision}
	return context.WithValue(ctx, dnsExecutionKey{}, grant), dns.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}, scope, nil
}

func (a *Authority) checkDNS(ctx context.Context, caller dns.Caller, scope dns.Scope, access dns.Access) error {
	value, err := a.current(ctx)
	if err != nil {
		return err
	}
	grant, ok := ctx.Value(dnsExecutionKey{}).(*dnsExecution)
	if !ok || grant == nil || grant.parent != value || caller.OwnerID != a.ownerID || caller.OperationID != value.invocation.OperationID || grant.scope != scope {
		return fault.New("PERMISSION_DENIED", "DNS 调用缺少精确宿主 scope")
	}
	if grant.certificate != nil {
		if err := a.checkCertificateDNS(ctx, caller, grant, access); err != nil {
			return err
		}
	}
	switch access {
	case dns.Read:
	case dns.Manage:
		if value.invocation.Operation != "records.apply" {
			return fault.New("PERMISSION_DENIED", "当前 DNS operation 不能写记录")
		}
	case dns.Reconcile:
		if value.invocation.Operation != "records.reconcile" {
			return fault.New("PERMISSION_DENIED", "当前 DNS operation 不能对账原记录意图")
		}
	case dns.Challenge:
		if !grant.challenge {
			return fault.New("PERMISSION_DENIED", "当前上下文不能提交 certificate challenge")
		}
	case dns.Cleanup:
		return fault.New("PERMISSION_DENIED", "当前上下文不能提交或清理 certificate challenge")
	default:
		return fault.New("PERMISSION_DENIED", "DNS 访问类型未知")
	}
	actual, providerRevision, zoneRevision, err := a.resolveScope(ctx, scope.ProviderID, scope.ZoneID)
	if err != nil {
		return err
	}
	if actual != scope || providerRevision != grant.providerRevision || zoneRevision != grant.zoneRevision {
		return fault.New("CREDENTIAL_REVOKED", "DNS owner、zone 或凭据版本变化")
	}
	return nil
}

type DNSAuthorizer struct{ Authority *Authority }

func (p DNSAuthorizer) Authorize(ctx context.Context, caller dns.Caller, scope dns.Scope, access dns.Access) error {
	if p.Authority == nil {
		return fault.New("BACKEND_REQUIRED", "DNS 需要真实宿主权限后端")
	}
	return p.Authority.checkDNS(ctx, caller, scope, access)
}

// AuthorizeRecoveryAttempt 核验原已接受的唯一 attempt，再复核精确只读对账范围。
func (p DNSAuthorizer) AuthorizeRecoveryAttempt(ctx context.Context, caller dns.Caller, scope dns.Scope, attemptID string) error {
	if p.Authority == nil {
		return fault.New("BACKEND_REQUIRED", "DNS 对账需要真实宿主授权来源")
	}
	input, err := DecodeArguments[DNSArgs](ctx, p.Authority)
	if err != nil {
		return err
	}
	if !names.ID(attemptID) || input.AttemptID != attemptID || input.ProviderID != scope.ProviderID || input.ZoneID != scope.ZoneID {
		return fault.New("PERMISSION_DENIED", "DNS 对账替换了原 attempt 或 zone")
	}
	return p.Authority.checkDNS(ctx, caller, scope, dns.Reconcile)
}

// Read 实现受控 provider.CredentialSource，凭据只供该精确网络请求代用。
func (a *Authority) Read(ctx context.Context, scope dns.Scope) (provider.Credentials, error) {
	value, err := a.current(ctx)
	if err != nil {
		return provider.Credentials{}, err
	}
	caller := dns.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	if err := a.checkDNS(ctx, caller, scope, dns.Read); err != nil {
		return provider.Credentials{}, err
	}
	registration, revision, found, err := a.loadProvider(ctx, scope.ProviderID)
	if err != nil {
		return provider.Credentials{}, err
	}
	grant, _ := ctx.Value(dnsExecutionKey{}).(*dnsExecution)
	if !found || grant == nil || revision != grant.providerRevision || registration.Phase != providerActive {
		return provider.Credentials{}, fault.New("CREDENTIAL_REVOKED", "提供商私有凭据登记不存在")
	}
	credentials, err := a.providerCredentials(ctx, registration)
	if err != nil {
		return provider.Credentials{}, err
	}
	if err := a.checkDNS(ctx, caller, scope, dns.Read); err != nil {
		credentials.Clear()
		return provider.Credentials{}, err
	}
	return credentials, nil
}

var _ dns.Authorizer = DNSAuthorizer{}
var _ dns.RecoveryAuthorizations = DNSAuthorizer{}
var _ provider.CredentialSource = (*Authority)(nil)
