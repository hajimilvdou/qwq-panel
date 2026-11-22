// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/provider"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 原 operation 的凭据导入和提供商发现 ========================

type RegisterProviderArgs struct {
	ProviderID string           `json:"provider_id"`
	Kind       dns.ProviderKind `json:"kind"`
	Name       string           `json:"name"`
	Credential json.RawMessage  `json:"credential"`
}

type credentialDocument struct {
	Token           string `json:"token,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
}

func credentialOwner(ownerID, nodeID, providerID string) string {
	return "host/prerequisites/providers/" + ownerID + "/" + nodeID + "/" + providerID
}

func credentialPurpose(operationID string) string {
	sum := sha256.Sum256([]byte(operationID))
	return "dns.credentials." + hex.EncodeToString(sum[:])
}

func decodeCredentials(raw []byte, kind dns.ProviderKind) (provider.Credentials, error) {
	var document credentialDocument
	if !strictObject(raw, &document, 16<<10) {
		return provider.Credentials{}, fault.New("VALIDATION_FAILED", "提供商凭据不是受控 JSON 对象")
	}
	result := provider.Credentials{Kind: kind, Token: []byte(document.Token), AccessKeyID: document.AccessKeyID, AccessKeySecret: []byte(document.AccessKeySecret)}
	if result.Validate(kind) != nil {
		result.Clear()
		return provider.Credentials{}, fault.New("VALIDATION_FAILED", "提供商类型与凭据字段不匹配")
	}
	return result, nil
}

func (credentialDocument) String() string   { return "hostauth.credentialDocument{[REDACTED]}" }
func (credentialDocument) GoString() string { return "hostauth.credentialDocument{[REDACTED]}" }

func validProviderName(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

// RegisterProvider 从当前已接受 Args 读取唯一凭据引用，持久复制到宿主 purpose。
// 先保存本地意图再读 API；读取失败可恢复原意图，不产生 DNS 写入或另一个凭据。
func (a *Authority) RegisterProvider(ctx context.Context, providerID, expected string) ([]provider.Zone, string, error) {
	value, err := a.current(ctx)
	if err != nil {
		return nil, "", err
	}
	if value.invocation.PluginID != "domain.dns" || value.invocation.Operation != "providers.register" || value.snapshot.Actor.Kind == actor.Service {
		return nil, "", fault.New("PERMISSION_DENIED", "当前 operation 不能登记提供商")
	}
	input, err := DecodeArguments[RegisterProviderArgs](ctx, a)
	if err != nil {
		return nil, "", err
	}
	if input.ProviderID != providerID || !names.ID(providerID) || !validProviderName(input.Name) || (input.Kind != dns.Cloudflare && input.Kind != dns.Aliyun) || value.invocation.Subject != "plugins/domain.dns/resources/providers/"+providerID {
		return nil, "", fault.New("PERMISSION_DENIED", "提供商资源不属于原 operation")
	}
	if err := a.RequireRevision(ctx, expected); err != nil {
		return nil, "", err
	}
	inputRef, valid := operationSecret(input.Credential)
	if !valid {
		return nil, "", fault.New("VALIDATION_FAILED", "原 operation 的凭据引用对象无效")
	}
	state, revision, found, err := a.loadProvider(ctx, providerID)
	if err != nil {
		return nil, "", err
	}
	if found {
		if state.OperationID != value.invocation.OperationID || state.ArgsDigest != value.snapshot.ArgsDigest || state.Kind != input.Kind || state.Name != input.Name || state.InputCredentialRef != inputRef || expected != "absent" {
			return nil, "", fault.New("REVISION_CONFLICT", "提供商 ID 已用于其他登记意图")
		}
		if state.Phase == providerRevoked {
			return nil, "", fault.New("CREDENTIAL_REVOKED", "原提供商登记已明确撤销，不能重新激活")
		}
		if state.Phase == providerActive {
			credentials, err := a.providerCredentials(ctx, state)
			credentials.Clear()
			if err != nil {
				return nil, "", err
			}
			return slices.Clone(state.Zones), revision, nil
		}
	} else {
		if expected != "absent" {
			return nil, "", fault.New("REVISION_CONFLICT", "提供商不存在，请重新预演")
		}
		state = providerRegistration{Version: 1, OwnerID: a.ownerID, NodeID: a.nodeID, ID: providerID, Kind: input.Kind, Name: input.Name,
			CreatedBy: value.snapshot.Actor, OperationID: value.invocation.OperationID, ArgsDigest: value.snapshot.ArgsDigest,
			InputCredentialRef: inputRef, Phase: providerPending, Zones: []provider.Zone{}}
	}
	key, err := a.providerKey(providerID)
	if err != nil {
		return nil, "", err
	}
	if state.CredentialRef == "" {
		raw, credentials, err := a.readCredentials(ctx, inputRef, "plugins/domain.dns", "plugin.operation", state.Kind)
		if err != nil {
			return nil, "", err
		}
		defer clear(raw)
		credentials.Clear()
		// 先占用有界私有登记，再复制凭据。CAS 失败只留下同一原意图的
		// 至多一个宿主 purpose，不能用大量失败登记绕过共享状态预算。
		if !found {
			revision, err = store.Save(ctx, a.repository, key, "", state)
			if err != nil {
				return nil, "", err
			}
		}
		if _, err := a.current(ctx); err != nil {
			return nil, "", err
		}
		current, latest, present, err := a.loadProvider(ctx, providerID)
		if err != nil {
			return nil, "", err
		}
		if !present || latest != revision || current.Phase != providerPending {
			return nil, "", fault.New("CREDENTIAL_REVOKED", "复制凭据前提供商登记已变化")
		}
		var owned secrets.Ref
		if err := a.db.Update(ctx, func(tx *storage.Tx) error {
			var err error
			owned, err = a.secrets.EnsureOwned(ctx, tx, credentialOwner(a.ownerID, a.nodeID, providerID), credentialPurpose(value.invocation.OperationID), raw)
			return err
		}); err != nil {
			return nil, "", fault.New("CREDENTIAL_UNAVAILABLE", "提供商凭据复制未确认")
		}
		state.CredentialRef = owned
		revision, err = store.Save(ctx, a.repository, key, revision, state)
		if err != nil {
			return nil, "", err
		}
	}
	credentials, err := a.providerCredentials(ctx, state)
	if err != nil {
		return nil, "", err
	}
	client, err := a.discoveryClient(ctx, state, revision)
	if err != nil {
		credentials.Clear()
		return nil, "", err
	}
	defer client.CloseIdleConnections()
	zones, err := provider.Discover(ctx, credentials, provider.Options{Client: client})
	if err != nil {
		return nil, "", err
	}
	if _, err := a.current(ctx); err != nil {
		return nil, "", err
	}
	state.Zones, state.Phase = slices.Clone(zones), providerActive
	revision, err = store.Save(ctx, a.repository, key, revision, state)
	if err != nil {
		return nil, "", err
	}
	return slices.Clone(zones), revision, nil
}

func (a *Authority) readCredentials(ctx context.Context, ref secrets.Ref, owner, purpose string, kind dns.ProviderKind) ([]byte, provider.Credentials, error) {
	secret, err := a.secrets.RevealOwned(ctx, ref, owner, purpose)
	if err != nil {
		return nil, provider.Credentials{}, fault.New("CREDENTIAL_REVOKED", "宿主确认的提供商凭据不可用")
	}
	defer secret.Clear()
	raw := secret.Bytes()
	credentials, err := decodeCredentials(raw, kind)
	if err != nil {
		clear(raw)
		return nil, provider.Credentials{}, err
	}
	return raw, credentials, nil
}

func (a *Authority) providerCredentials(ctx context.Context, registration providerRegistration) (provider.Credentials, error) {
	raw, credentials, err := a.readCredentials(ctx, registration.CredentialRef,
		credentialOwner(a.ownerID, a.nodeID, registration.ID), credentialPurpose(registration.OperationID), registration.Kind)
	clear(raw)
	return credentials, err
}

type discoveryTransport struct {
	authority *Authority
	base      http.RoundTripper
	provider  providerRegistration
	revision  string
}

func (t discoveryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if _, err := t.authority.current(request.Context()); err != nil {
		return nil, err
	}
	current, revision, found, err := t.authority.loadProvider(request.Context(), t.provider.ID)
	if err != nil {
		return nil, err
	}
	if !found || revision != t.revision || current.Phase != providerPending || current.CredentialRef != t.provider.CredentialRef || current.OperationID != t.provider.OperationID {
		return nil, fault.New("CREDENTIAL_REVOKED", "提供商发现期间授权或凭据版本变化")
	}
	credentials, err := t.authority.providerCredentials(request.Context(), current)
	credentials.Clear()
	if err != nil {
		return nil, err
	}
	return t.base.RoundTrip(request)
}

func (t discoveryTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (a *Authority) discoveryClient(ctx context.Context, registration providerRegistration, revision string) (*http.Client, error) {
	if _, err := a.current(ctx); err != nil {
		return nil, err
	}
	client := http.Client{Timeout: 15 * time.Second}
	if a.httpClient != nil {
		client = *a.httpClient
	}
	base := client.Transport
	if base == nil {
		standard := http.DefaultTransport.(*http.Transport).Clone()
		standard.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		base = standard
	}
	if standard, ok := base.(*http.Transport); ok && standard.TLSClientConfig != nil && standard.TLSClientConfig.InsecureSkipVerify {
		return nil, fault.New("VALIDATION_FAILED", "提供商发现必须校验 TLS")
	}
	client.Timeout, client.Jar = 15*time.Second, nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Transport = discoveryTransport{authority: a, base: base, provider: registration, revision: revision}
	return &client, nil
}
