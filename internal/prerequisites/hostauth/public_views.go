// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 目录只提供候选，公开数据始终重读私有登记 ========================

type CollectionArgs struct{}

type ProviderPublic struct {
	ID        string
	Kind      string
	Name      string
	Revision  string
	Enabled   bool
	ZoneCount uint32
	LastError string
}

type ZonePublic struct {
	ProviderID string
	ZoneID     string
	Name       string
	Revision   string
	Authorized bool
}

func (a *Authority) providerViewIntent(ctx context.Context, id string) error {
	value, err := a.current(ctx)
	if err != nil {
		return err
	}
	if value.invocation.PluginID != "domain.dns" || !names.ID(id) {
		return fault.New("PERMISSION_DENIED", "公开提供商不属于当前模块")
	}
	subject := "plugins/domain.dns/resources/providers/" + id
	switch value.invocation.Operation {
	case "providers.list":
		if value.invocation.Subject != "plugins/domain.dns/resources/providers" {
			return fault.New("PERMISSION_DENIED", "提供商集合目标不符")
		}
		if _, err := DecodeArguments[CollectionArgs](ctx, a); err != nil {
			return err
		}
		return a.AuthorizeCurrent(ctx, "system.dns:read", authz.Resource{Name: "system.dns", NodeID: a.nodeID,
			Action: value.target.ActionID, Subject: subject})
	case "providers.register":
		input, err := DecodeArguments[RegisterProviderArgs](ctx, a)
		if err != nil {
			return err
		}
		if input.ProviderID == id && value.invocation.Subject == subject {
			return nil
		}
	case "providers.zones", "providers.revoke":
		input, err := DecodeArguments[ProviderArgs](ctx, a)
		if err != nil {
			return err
		}
		if input.ProviderID == id && value.invocation.Subject == subject {
			return nil
		}
	}
	return fault.New("PERMISSION_DENIED", "公开提供商替换了原资源或动作")
}

func (a *Authority) zonePublic(ctx context.Context, provider providerRegistration, providerRevision, zoneID, name string) (ZonePublic, error) {
	zone, revision, found, err := a.loadZone(ctx, provider.ID, zoneID)
	if err != nil {
		return ZonePublic{}, err
	}
	view := ZonePublic{ProviderID: provider.ID, ZoneID: zoneID, Name: name, Revision: certificates.MissingRevision}
	if found {
		view.Name, view.Revision = zone.Name, revision
		view.Authorized = zone.Enabled && provider.Phase == providerActive && zone.ProviderRevision == providerRevision
	}
	return view, nil
}

// PublicProvider 读取真实登记及注册时已核验的zone快照，不揭示凭据或主体。
func (a *Authority) PublicProvider(ctx context.Context, id string) (ProviderPublic, []ZonePublic, error) {
	if err := a.providerViewIntent(ctx, id); err != nil {
		return ProviderPublic{}, nil, err
	}
	entry, revision, found, err := a.loadProvider(ctx, id)
	if err != nil {
		return ProviderPublic{}, nil, err
	}
	if !found {
		return ProviderPublic{}, nil, fault.New("NOT_FOUND", "提供商私有登记不存在")
	}
	view := ProviderPublic{ID: id, Kind: string(entry.Kind), Name: entry.Name, Revision: revision,
		Enabled: entry.Phase == providerActive, ZoneCount: uint32(len(entry.Zones))}
	switch entry.Phase {
	case providerPending:
		view.LastError = "PROVIDER_PENDING"
	case providerRevoked:
		view.LastError = "CREDENTIAL_REVOKED"
	}
	zones := make([]ZonePublic, 0, len(entry.Zones))
	for _, discovered := range entry.Zones {
		zone, err := a.zonePublic(ctx, entry, revision, discovered.ID, discovered.Name)
		if err != nil {
			return ProviderPublic{}, nil, err
		}
		zones = append(zones, zone)
	}
	if err := a.providerViewIntent(ctx, id); err != nil {
		return ProviderPublic{}, nil, err
	}
	return view, zones, nil
}

// PublicZone 只输出当前授权/撤销operation已接受的那一个zone。
func (a *Authority) PublicZone(ctx context.Context, providerID, zoneID string) (ZonePublic, error) {
	value, err := a.current(ctx)
	if err != nil {
		return ZonePublic{}, err
	}
	input, err := DecodeArguments[ZoneArgs](ctx, a)
	if err != nil {
		return ZonePublic{}, err
	}
	if value.invocation.PluginID != "domain.dns" || (value.invocation.Operation != "zones.authorize" && value.invocation.Operation != "zones.revoke") ||
		input.ProviderID != providerID || input.ZoneID != zoneID || !names.ID(providerID) || !names.ID(zoneID) ||
		value.invocation.Subject != "plugins/domain.dns/resources/zones/"+providerID+"/"+zoneID {
		return ZonePublic{}, fault.New("PERMISSION_DENIED", "公开zone不属于原授权目标")
	}
	entry, revision, found, err := a.loadProvider(ctx, providerID)
	if err != nil {
		return ZonePublic{}, err
	}
	if !found {
		return ZonePublic{}, fault.New("NOT_FOUND", "zone的提供商私有登记不存在")
	}
	view, err := a.zonePublic(ctx, entry, revision, zoneID, "")
	if err != nil {
		return ZonePublic{}, err
	}
	if _, err := a.current(ctx); err != nil {
		return ZonePublic{}, err
	}
	return view, nil
}

func (a *Authority) certificateReadContext(ctx context.Context, value *execution, id string) (context.Context, certificates.Caller, error) {
	if !names.ID(id) {
		return nil, certificates.Caller{}, fault.New("PERMISSION_DENIED", "证书只读范围的标识无效")
	}
	entry, revision, found, err := a.loadCertificate(ctx, id)
	if err != nil {
		return nil, certificates.Caller{}, err
	}
	if !found {
		return nil, certificates.Caller{}, fault.New("NOT_FOUND", "证书私有登记不存在")
	}
	grant := &certificateExecution{parent: value, certificateID: id, registryRevision: revision,
		spec: cloneCertificateSpec(entry.Spec), access: certificates.Read}
	caller := certificates.Caller{OwnerID: a.ownerID, OperationID: value.invocation.OperationID}
	bound := context.WithValue(ctx, certificateExecutionKey{}, grant)
	if _, err := a.certificateGrant(bound, caller); err != nil {
		return nil, certificates.Caller{}, err
	}
	return bound, caller, nil
}

// PublicCertificateContext 目录只能选择候选ID，每项仍重查实际登记与当前主体权限。
func (a *Authority) PublicCertificateContext(ctx context.Context, id string) (context.Context, certificates.Caller, error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, certificates.Caller{}, err
	}
	if value.invocation.PluginID != "tls.certificates" || value.invocation.Operation != "certificates.list" ||
		value.invocation.Subject != "plugins/tls.certificates/resources/certificates" {
		return nil, certificates.Caller{}, fault.New("PERMISSION_DENIED", "证书集合不属于当前原意图")
	}
	if _, err := DecodeArguments[CollectionArgs](ctx, a); err != nil {
		return nil, certificates.Caller{}, err
	}
	if err := validateCertificateAction(value.snapshot.Action, certificates.Read); err != nil {
		return nil, certificates.Caller{}, err
	}
	if err := a.AuthorizeCurrent(ctx, "system.certificates:read", authz.Resource{Name: "system.certificates", NodeID: a.nodeID,
		Action: value.target.ActionID, Subject: "plugins/tls.certificates/resources/certificates/" + id}); err != nil {
		return nil, certificates.Caller{}, err
	}
	return a.certificateReadContext(ctx, value, id)
}
