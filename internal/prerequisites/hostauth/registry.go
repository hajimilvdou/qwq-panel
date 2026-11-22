// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/provider"
	"github.com/qwq-panel/qwq/internal/secrets"
)

// ======================== 宿主私有提供商、zone 与凭据登记 ========================

type providerPhase string

const (
	providerPending providerPhase = "pending"
	providerActive  providerPhase = "active"
	providerRevoked providerPhase = "revoked"
)

type authorizationRevocation struct {
	Actor            actor.Actor `json:"actor"`
	OperationID      string      `json:"operation_id"`
	ArgsDigest       string      `json:"args_digest"`
	ExpectedRevision string      `json:"expected_revision"`
}

func (r *authorizationRevocation) valid() bool {
	return r != nil && validInitiator(r.Actor) && ids.Valid(r.OperationID, ids.Operation) && operations.ValidArgumentDigest(r.ArgsDigest) && validDigest(r.ExpectedRevision)
}

type providerRegistration struct {
	Version            uint32                   `json:"version"`
	OwnerID            string                   `json:"owner_id"`
	NodeID             string                   `json:"node_id"`
	ID                 string                   `json:"id"`
	Kind               dns.ProviderKind         `json:"kind"`
	Name               string                   `json:"name"`
	CreatedBy          actor.Actor              `json:"created_by"`
	OperationID        string                   `json:"operation_id"`
	ArgsDigest         string                   `json:"args_digest"`
	InputCredentialRef secrets.Ref              `json:"input_credential_ref"`
	CredentialRef      secrets.Ref              `json:"credential_ref,omitempty"`
	Phase              providerPhase            `json:"phase"`
	Zones              []provider.Zone          `json:"zones"`
	Revocation         *authorizationRevocation `json:"revocation,omitempty"`
}

type zoneRegistration struct {
	Version          uint32                   `json:"version"`
	OwnerID          string                   `json:"owner_id"`
	NodeID           string                   `json:"node_id"`
	ProviderID       string                   `json:"provider_id"`
	ProviderRevision string                   `json:"provider_revision"`
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Kind             dns.ProviderKind         `json:"kind"`
	ConfirmedBy      actor.Actor              `json:"confirmed_by"`
	OperationID      string                   `json:"operation_id"`
	ArgsDigest       string                   `json:"args_digest"`
	BaseRevision     string                   `json:"base_revision"`
	Enabled          bool                     `json:"enabled"`
	Revocation       *authorizationRevocation `json:"revocation,omitempty"`
}

func (providerRegistration) String() string   { return "hostauth.providerRegistration{[REDACTED]}" }
func (providerRegistration) GoString() string { return "hostauth.providerRegistration{[REDACTED]}" }

func registryKey(kind string, identifiers ...string) (string, error) {
	for _, id := range identifiers {
		if !names.ID(id) {
			return "", fault.New("SCOPE_INVALID", "宿主登记的资源 ID 无效")
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(identifiers, "\x00")))
	return kind + "/" + hex.EncodeToString(sum[:]), nil
}

func (a *Authority) providerKey(id string) (string, error) {
	return registryKey("provider", a.ownerID, a.nodeID, id)
}

func (a *Authority) zoneKey(providerID, zoneID string) (string, error) {
	return registryKey("zone", a.ownerID, a.nodeID, providerID, zoneID)
}

func loadPrivate[T any](ctx context.Context, authority *Authority, key string, destination *T) (string, bool, error) {
	entry, found, err := authority.repository.Get(ctx, key)
	if err != nil || !found {
		return "", found, err
	}
	defer clear(entry.Value)
	if !validDigest(entry.Revision) || !strictObject(entry.Value, destination, 1<<20) {
		return "", false, fault.New("STATE_INVALID", "宿主授权登记的持久文档无效")
	}
	return entry.Revision, true, nil
}

func (a *Authority) loadProvider(ctx context.Context, id string) (providerRegistration, string, bool, error) {
	key, err := a.providerKey(id)
	if err != nil {
		return providerRegistration{}, "", false, err
	}
	var result providerRegistration
	revision, found, err := loadPrivate(ctx, a, key, &result)
	if err != nil || !found {
		return result, revision, found, err
	}
	validResource := result.Version == 1 && result.OwnerID == a.ownerID && result.NodeID == a.nodeID && result.ID == id
	validKind := result.Kind == dns.Cloudflare || result.Kind == dns.Aliyun
	validIntent := validInitiator(result.CreatedBy) && ids.Valid(result.OperationID, ids.Operation) && operations.ValidArgumentDigest(result.ArgsDigest)
	if !validResource || !validKind || !validIntent || !validProviderName(result.Name) || len(result.Zones) > 256 || !result.InputCredentialRef.Valid() {
		return providerRegistration{}, "", false, fault.New("STATE_INVALID", "提供商登记的 owner、节点或类型无效")
	}
	if (result.CredentialRef != "" && (!result.CredentialRef.Valid() || result.CredentialRef == result.InputCredentialRef)) || (result.Phase == providerActive && result.CredentialRef == "") {
		return providerRegistration{}, "", false, fault.New("STATE_INVALID", "提供商私有凭据登记无效")
	}
	switch result.Phase {
	case providerPending:
		if len(result.Zones) != 0 || result.Revocation != nil {
			return providerRegistration{}, "", false, fault.New("STATE_INVALID", "待发现提供商混入了已授权或撤权状态")
		}
	case providerActive:
		if result.Revocation != nil {
			return providerRegistration{}, "", false, fault.New("STATE_INVALID", "提供商授权与撤权状态矛盾")
		}
	case providerRevoked:
		if !result.Revocation.valid() {
			return providerRegistration{}, "", false, fault.New("STATE_INVALID", "提供商撤权缺少真实意图证据")
		}
	default:
		return providerRegistration{}, "", false, fault.New("STATE_INVALID", "提供商登记阶段未知")
	}
	seen := make(map[string]bool, len(result.Zones))
	for _, zone := range result.Zones {
		scope := dns.Scope{ProviderID: id, Kind: result.Kind, ZoneID: zone.ID, ZoneName: zone.Name, Revision: revision}
		if dns.ValidateScope(scope) != nil || seen[zone.ID] {
			return providerRegistration{}, "", false, fault.New("STATE_INVALID", "提供商发现的 zone 无效或重复")
		}
		seen[zone.ID] = true
	}
	return result, revision, true, nil
}

func (a *Authority) loadZone(ctx context.Context, providerID, zoneID string) (zoneRegistration, string, bool, error) {
	key, err := a.zoneKey(providerID, zoneID)
	if err != nil {
		return zoneRegistration{}, "", false, err
	}
	var result zoneRegistration
	revision, found, err := loadPrivate(ctx, a, key, &result)
	if err != nil || !found {
		return result, revision, found, err
	}
	canonical, nameErr := names.DNS(result.Name, false)
	validResource := result.Version == 1 && result.OwnerID == a.ownerID && result.NodeID == a.nodeID && result.ProviderID == providerID && result.ID == zoneID
	validKind := result.Kind == dns.Cloudflare || result.Kind == dns.Aliyun
	validIntent := validInitiator(result.ConfirmedBy) && ids.Valid(result.OperationID, ids.Operation) && operations.ValidArgumentDigest(result.ArgsDigest)
	validState := (result.Enabled && result.Revocation == nil) || (!result.Enabled && result.Revocation.valid())
	if nameErr != nil || canonical != result.Name || !validResource || !validKind || !validIntent || !validState || !validDigest(result.ProviderRevision) || !validRevision(result.BaseRevision) {
		return zoneRegistration{}, "", false, fault.New("STATE_INVALID", "zone 登记的 owner、节点或域名无效")
	}
	return result, revision, true, nil
}

func registeredScope(registration providerRegistration, providerRevision string, zone zoneRegistration, zoneRevision string) (dns.Scope, error) {
	if registration.Phase != providerActive || !zone.Enabled || registration.ID != zone.ProviderID || registration.Kind != zone.Kind || registration.OwnerID != zone.OwnerID || registration.NodeID != zone.NodeID || zone.ProviderRevision != providerRevision {
		return dns.Scope{}, fault.New("ZONE_DENIED", "提供商或精确 zone 已撤销")
	}
	if !slices.ContainsFunc(registration.Zones, func(actual provider.Zone) bool { return actual.ID == zone.ID && actual.Name == zone.Name }) {
		return dns.Scope{}, fault.New("STATE_INVALID", "已确认 zone 不属于提供商发现事实")
	}
	sum := sha256.Sum256([]byte(providerRevision + "\x00" + zoneRevision))
	scope := dns.Scope{ProviderID: registration.ID, Kind: registration.Kind, ZoneID: zone.ID, ZoneName: zone.Name, Revision: hex.EncodeToString(sum[:])}
	if err := dns.ValidateScope(scope); err != nil {
		return dns.Scope{}, err
	}
	return scope, nil
}
