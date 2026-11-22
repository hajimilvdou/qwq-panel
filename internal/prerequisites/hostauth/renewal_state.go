// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 单一有界账本与不可持久化的真实审批边界 ========================

const maxRenewalRegistrations = 128

const (
	renewalAwaitingService = "awaiting_service"
	renewalActive          = "active"
	renewalRevoked         = "revoked"
)

type renewalBinding struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

type renewalDependencies struct {
	Scope               certificates.RenewalScope `json:"scope"`
	CertificateRevision string                    `json:"certificate_revision"`
	ProviderRevision    string                    `json:"provider_revision"`
	ZoneRevision        string                    `json:"zone_revision"`
	Bindings            []renewalBinding          `json:"bindings"`
}

type renewalRegistration struct {
	Version           uint64              `json:"version"`
	ID                string              `json:"id"`
	Dependencies      renewalDependencies `json:"dependencies"`
	ExpiresAt         time.Time           `json:"expires_at"`
	CreatedBy         actor.Actor         `json:"created_by"`
	AuthorizedBy      actor.Actor         `json:"authorized_by"`
	ConfirmationActor actor.Actor         `json:"confirmation_actor"`
	Origin            bindingOrigin       `json:"origin"`
	BaseRevision      string              `json:"base_revision"`
	State             string              `json:"state"`
	ServiceAccountID  string              `json:"service_account_id,omitempty"`
	AttachedOrigin    *bindingOrigin      `json:"attached_origin,omitempty"`
	AttachedBy        actor.Actor         `json:"attached_by"`
	AttachedRevision  string              `json:"attached_revision,omitempty"`
	RevokedOrigin     *bindingOrigin      `json:"revoked_origin,omitempty"`
	RevokedBy         actor.Actor         `json:"revoked_by"`
	RevokedRevision   string              `json:"revoked_revision,omitempty"`
}

type renewalAuthorizationLedger struct {
	Version uint32                `json:"version"`
	OwnerID string                `json:"owner_id"`
	NodeID  string                `json:"node_id"`
	Entries []renewalRegistration `json:"entries"`
}

func (renewalRegistration) String() string   { return "hostauth.renewalRegistration{[REDACTED]}" }
func (renewalRegistration) GoString() string { return "hostauth.renewalRegistration{[REDACTED]}" }

func renewalPolicySubject(id string) string {
	return "plugins/tls.certificates/resources/policies/" + id
}

func validRenewalOrigin(origin bindingOrigin, policyID, operation string) bool {
	return origin.PluginID == "tls.certificates" && origin.InstanceID == operations.ControllerDispatchInstance &&
		ids.Valid(origin.OperationID, ids.Operation) && origin.Operation == operation &&
		origin.Subject == renewalPolicySubject(policyID) && operations.ValidArgumentDigest(origin.ArgsDigest)
}

func (a *Authority) renewalContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if a == nil || ctx == nil || a.clock == nil || a.repository == nil || a.authorizer == nil {
		return nil, nil, fault.New("BACKEND_REQUIRED", "续期登记需要真实宿主私有状态与当前权限")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	return bounded, cancel, nil
}

func (a *Authority) authorizeRenewalPolicy(ctx context.Context, who actor.Actor, policyID string) error {
	if who.Valid() != nil || who.Kind == actor.System || who.Kind == actor.Service || !names.ID(policyID) {
		return fault.New("PERMISSION_DENIED", "续期策略需要当前真实主体与固定策略范围")
	}
	return a.authorizer.Authorize(ctx, who, "system.certificates:manage", authz.Resource{Name: "system.certificates",
		NodeID: a.nodeID, Action: "tls.certificates/renewal.configure", Subject: renewalPolicySubject(policyID)})
}

func (a *Authority) renewalDispatch(ctx context.Context, operation, policyID, expected string) (bindingOrigin, actor.Actor, actor.Actor, error) {
	value, err := a.current(ctx)
	if err != nil {
		return bindingOrigin{}, actor.Actor{}, actor.Actor{}, err
	}
	value.mu.RLock()
	defer value.mu.RUnlock()
	if value.released || ctx.Err() != nil || value.invocation.PluginID != "tls.certificates" ||
		value.invocation.Operation != operation || value.invocation.Subject != renewalPolicySubject(policyID) ||
		!names.ID(policyID) || expected == "" || value.snapshot.ExpectedRevision != expected ||
		value.snapshot.Action.Source != operations.PluginSource || value.snapshot.Action.Effect != operations.EffectWrite ||
		value.snapshot.Action.EffectiveRisk() != operations.RiskHigh {
		return bindingOrigin{}, actor.Actor{}, actor.Actor{}, fault.New("PERMISSION_DENIED", "续期登记不是原operation的策略和版本")
	}
	if !value.snapshot.Approved || value.snapshot.ConfirmationActor.Kind != actor.Human || !validInitiator(value.snapshot.ConfirmationActor) {
		return bindingOrigin{}, actor.Actor{}, actor.Actor{}, fault.New("APPROVAL_REQUIRED", "续期授权需要实际批准的人类确认，完全模式不能替代")
	}
	return bindingOriginFrom(value), value.snapshot.Actor, value.snapshot.ConfirmationActor, nil
}

func (a *Authority) renewalLedgerKey() (string, error) {
	return registryKey("renewal-authorizations", a.ownerID, a.nodeID)
}

func (a *Authority) loadRenewalLedger(ctx context.Context) (renewalAuthorizationLedger, string, error) {
	key, err := a.renewalLedgerKey()
	if err != nil {
		return renewalAuthorizationLedger{}, "", err
	}
	state := renewalAuthorizationLedger{Version: 1, OwnerID: a.ownerID, NodeID: a.nodeID, Entries: []renewalRegistration{}}
	revision, found, err := loadPrivate(ctx, a, key, &state)
	if err != nil || !found {
		return state, revision, err
	}
	if state.Version != 1 || state.OwnerID != a.ownerID || state.NodeID != a.nodeID || state.Entries == nil || len(state.Entries) > maxRenewalRegistrations {
		return renewalAuthorizationLedger{}, "", fault.New("STATE_INVALID", "续期账本的作用域或容量无效")
	}
	seen, certificatesSeen := map[string]bool{}, map[string]bool{}
	for _, entry := range state.Entries {
		canonical, canonicalErr := certificates.CanonicalRenewalScope(entry.Dependencies.Scope)
		validScope := canonicalErr == nil && sameRenewalScope(canonical, entry.Dependencies.Scope) && canonical.OwnerID == a.ownerID &&
			validDigest(entry.Dependencies.CertificateRevision) && validDigest(entry.Dependencies.ProviderRevision) && validDigest(entry.Dependencies.ZoneRevision) &&
			len(entry.Dependencies.Bindings) > 0 && len(entry.Dependencies.Bindings) <= 8 && len(canonical.Consumers) == len(entry.Dependencies.Bindings)
		previous := ""
		for _, binding := range entry.Dependencies.Bindings {
			validScope = validScope && ids.Valid(binding.ID, "certbind") && binding.ID > previous && validDigest(binding.Revision)
			previous = binding.ID
		}
		for _, consumer := range canonical.Consumers {
			validScope = validScope && consumer.NodeID == a.nodeID
		}
		validActors := validInitiator(entry.CreatedBy) && validInitiator(entry.AuthorizedBy) &&
			entry.ConfirmationActor.Kind == actor.Human && validInitiator(entry.ConfirmationActor)
		validAttachment := entry.ServiceAccountID == "" && entry.AttachedOrigin == nil && entry.AttachedBy == (actor.Actor{}) && entry.AttachedRevision == ""
		if entry.State == renewalActive || (entry.State == renewalRevoked && entry.ServiceAccountID != "") {
			validAttachment = ids.Valid(entry.ServiceAccountID, ids.Service) && entry.AttachedOrigin != nil &&
				validRenewalOrigin(*entry.AttachedOrigin, entry.ID, "renewal.attach_service") && validDigest(entry.AttachedRevision) &&
				entry.AttachedBy.Kind == actor.Human && validInitiator(entry.AttachedBy)
		}
		validState := entry.State == renewalAwaitingService || entry.State == renewalActive || entry.State == renewalRevoked
		validRevocation := entry.RevokedOrigin == nil && entry.RevokedBy == (actor.Actor{}) && entry.RevokedRevision == ""
		if entry.RevokedOrigin != nil {
			validRevocation = entry.State == renewalRevoked && validRenewalOrigin(*entry.RevokedOrigin, entry.ID, "renewal.revoke") &&
				validInitiator(entry.RevokedBy) && validDigest(entry.RevokedRevision)
		}
		if entry.Version == 0 || !names.ID(entry.ID) || entry.ExpiresAt.IsZero() || !validActors || !validScope || !validState || !validAttachment || !validRevocation ||
			!validRenewalOrigin(entry.Origin, entry.ID, "renewal.configure") || !validRevision(entry.BaseRevision) || seen[entry.ID] ||
			(entry.State != renewalRevoked && certificatesSeen[canonical.CertificateID]) {
			return renewalAuthorizationLedger{}, "", fault.New("STATE_INVALID", "续期登记的固定范围、审批来源或状态无效")
		}
		seen[entry.ID] = true
		if entry.State != renewalRevoked {
			certificatesSeen[canonical.CertificateID] = true
		}
	}
	return state, revision, nil
}

func renewalIndex(state renewalAuthorizationLedger, id string) int {
	for index, entry := range state.Entries {
		if entry.ID == id {
			return index
		}
	}
	return -1
}

func sameRenewalScope(one, two certificates.RenewalScope) bool {
	return one.OwnerID == two.OwnerID && one.CertificateID == two.CertificateID &&
		sameCertificateIssuance(&one.Issuance, &two.Issuance) && slices.Equal(one.Consumers, two.Consumers)
}

func renewalRevision(entry renewalRegistration) (string, error) {
	raw, err := json.Marshal(entry)
	if err != nil {
		return "", fault.New("STATE_INVALID", "续期策略不能计算固定版本")
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func renewalView(entry renewalRegistration) (RenewalPolicyView, error) {
	revision, err := renewalRevision(entry)
	return RenewalPolicyView{ID: entry.ID, CertificateID: entry.Dependencies.Scope.CertificateID, Revision: revision,
		State: entry.State, ExpiresAt: entry.ExpiresAt, ServiceAccountID: entry.ServiceAccountID}, err
}

func (a *Authority) loadRenewalPolicy(ctx context.Context, id, expected string) (renewalRegistration, error) {
	state, _, err := a.loadRenewalLedger(ctx)
	if err != nil {
		return renewalRegistration{}, err
	}
	index := renewalIndex(state, id)
	if index < 0 {
		return renewalRegistration{}, fault.New("POLICY_SCOPE_DENIED", "续期策略尚未实际确认")
	}
	entry := state.Entries[index]
	revision, err := renewalRevision(entry)
	if err != nil {
		return renewalRegistration{}, err
	}
	if expected != revision {
		return renewalRegistration{}, fault.New("REVISION_CONFLICT", "续期策略版本已变化")
	}
	return entry, nil
}

func (a *Authority) saveRenewalLedger(ctx context.Context, state renewalAuthorizationLedger, expected string) error {
	key, err := a.renewalLedgerKey()
	if err != nil {
		return err
	}
	_, err = store.Save(ctx, a.repository, key, expected, state)
	return err
}
