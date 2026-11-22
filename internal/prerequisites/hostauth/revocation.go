// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 明确撤权与原意图证据保留 ========================

type ProviderArgs struct {
	ProviderID string `json:"provider_id"`
}

func revocationFor(value *execution, expected string) *authorizationRevocation {
	return &authorizationRevocation{Actor: value.snapshot.Actor, OperationID: value.invocation.OperationID,
		ArgsDigest: value.snapshot.ArgsDigest, ExpectedRevision: expected}
}

func sameRevocation(revoked *authorizationRevocation, value *execution, expected string) bool {
	return revoked != nil && revoked.OperationID == value.invocation.OperationID && revoked.Actor == value.snapshot.Actor && revoked.ArgsDigest == value.snapshot.ArgsDigest && revoked.ExpectedRevision == expected
}

// RevokeProvider 只撤销宿主授权，不删除未知 DNS 记录或覆盖旧意图。
func (a *Authority) RevokeProvider(ctx context.Context, providerID, expected string) (string, error) {
	value, err := a.current(ctx)
	if err != nil {
		return "", err
	}
	input, err := DecodeArguments[ProviderArgs](ctx, a)
	if err != nil {
		return "", err
	}
	if value.invocation.PluginID != "domain.dns" || value.invocation.Operation != "providers.revoke" || input.ProviderID != providerID || value.invocation.Subject != "plugins/domain.dns/resources/providers/"+providerID {
		return "", fault.New("PERMISSION_DENIED", "当前 operation 不能撤销该提供商")
	}
	if err := a.RequireRevision(ctx, expected); err != nil {
		return "", err
	}
	registration, revision, found, err := a.loadProvider(ctx, providerID)
	if err != nil {
		return "", err
	}
	if found && registration.Phase == providerRevoked && sameRevocation(registration.Revocation, value, expected) {
		return revision, nil
	}
	if !found || revision != expected {
		return "", fault.New("REVISION_CONFLICT", "提供商授权版本已变化")
	}
	if registration.Phase == providerRevoked {
		return revision, nil
	}
	if _, err := a.current(ctx); err != nil {
		return "", err
	}
	registration.Phase, registration.Revocation = providerRevoked, revocationFor(value, expected)
	key, err := a.providerKey(providerID)
	if err != nil {
		return "", err
	}
	return store.Save(ctx, a.repository, key, revision, registration)
}

// RevokeZone 即时使旧 scope 和续期策略失效，保留已登记自有记录的对账证据。
func (a *Authority) RevokeZone(ctx context.Context, providerID, zoneID, expected string) (string, error) {
	value, err := a.current(ctx)
	if err != nil {
		return "", err
	}
	input, err := DecodeArguments[ZoneArgs](ctx, a)
	if err != nil {
		return "", err
	}
	if value.invocation.PluginID != "domain.dns" || value.invocation.Operation != "zones.revoke" || input.ProviderID != providerID || input.ZoneID != zoneID || value.invocation.Subject != "plugins/domain.dns/resources/zones/"+providerID+"/"+zoneID {
		return "", fault.New("PERMISSION_DENIED", "当前 operation 不能撤销该 zone")
	}
	if err := a.RequireRevision(ctx, expected); err != nil {
		return "", err
	}
	registration, revision, found, err := a.loadZone(ctx, providerID, zoneID)
	if err != nil {
		return "", err
	}
	if found && !registration.Enabled && sameRevocation(registration.Revocation, value, expected) {
		return revision, nil
	}
	if !found || revision != expected {
		return "", fault.New("REVISION_CONFLICT", "zone 授权版本已变化")
	}
	if !registration.Enabled {
		return revision, nil
	}
	if _, err := a.current(ctx); err != nil {
		return "", err
	}
	registration.Enabled, registration.Revocation = false, revocationFor(value, expected)
	key, err := a.zoneKey(providerID, zoneID)
	if err != nil {
		return "", err
	}
	return store.Save(ctx, a.repository, key, revision, registration)
}
