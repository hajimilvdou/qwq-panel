// SPDX-License-Identifier: AGPL-3.0-only

// Package provider 实现固定 Cloudflare/阿里云 API；凭据与 zone 来自宿主授权注册表。
package provider

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 凭据与固定端点 ========================

const (
	cloudflareEndpoint = "https://api.cloudflare.com/client/v4"
	aliyunEndpoint     = "https://alidns.aliyuncs.com/"
	dnspodEndpoint     = "https://dnspod.tencentcloudapi.com"
	maxResponseBytes   = 1 << 20
	maxProviderRecords = 4096
	maxProviderZones   = 256
)

// Credentials 的字节缓冲归调用者所有；每次网络调用完成后清零。
type Credentials struct {
	Kind            dns.ProviderKind
	Token           []byte
	AccessKeyID     string
	AccessKeySecret []byte
}

func (Credentials) String() string               { return "provider.Credentials{[REDACTED]}" }
func (Credentials) GoString() string             { return "provider.Credentials{[REDACTED]}" }
func (Credentials) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (c *Credentials) Clear() {
	clear(c.Token)
	clear(c.AccessKeySecret)
	c.Token, c.AccessKeySecret, c.AccessKeyID = nil, nil, ""
}

// CredentialSource 每个 API 请求重新核验 owner/派发/凭据 revision 与授权 zone。
// 返回独立缓冲，不能把插件自报的引用或 owner 当作授权事实。
type CredentialSource interface {
	Read(context.Context, dns.Scope) (Credentials, error)
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Options struct {
	Source CredentialSource
	Client *http.Client
	Clock  clock.Clock
	Random io.Reader
}

// Registry 仅返回已确认 scope 的适配器；没有自定义 URL 或请求模板入口。
type Registry struct{ client *apiClient }

func New(options Options) (*Registry, error) {
	client, err := newAPIClient(options)
	if err != nil {
		return nil, err
	}
	if options.Source == nil {
		return nil, fault.New("BACKEND_REQUIRED", "DNS 适配器需要宿主凭据授权")
	}
	return &Registry{client: client}, nil
}

func (r *Registry) For(ctx context.Context, scope dns.Scope) (dns.Provider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.client == nil || dns.ValidateScope(scope) != nil {
		return nil, fault.New("SCOPE_INVALID", "DNS 提供商范围无效")
	}
	switch scope.Kind {
	case dns.Cloudflare:
		if !cloudflareID(scope.ZoneID) {
			return nil, fault.New("SCOPE_INVALID", "Cloudflare zone 标识无效")
		}
		return &cloudflareProvider{scope: scope, client: r.client}, nil
	case dns.Aliyun:
		if !aliyunZoneID(scope.ZoneID) {
			return nil, fault.New("SCOPE_INVALID", "阿里云 zone 标识无效")
		}
		return &aliyunProvider{scope: scope, client: r.client}, nil
	case dns.DNSPod:
		if !dnspodID(scope.ZoneID) {
			return nil, fault.New("SCOPE_INVALID", "腾讯云 DNSPod zone 标识无效")
		}
		return &dnspodProvider{scope: scope, client: r.client}, nil
	default:
		return nil, fault.New("SCOPE_INVALID", "DNS 提供商不受支持")
	}
}

// Discover 只供宿主在已授权添加提供商 operation 中检验最小权限凭据。
// 凭据不持久化在适配器，不返回引用；选择 zone 仍由后续精确授权确认。
func Discover(ctx context.Context, credentials Credentials, options Options) ([]Zone, error) {
	defer credentials.Clear()
	if err := credentials.Validate(credentials.Kind); err != nil {
		return nil, err
	}
	options.Source = discoveryCredentials{credentials: credentials}
	client, err := newAPIClient(options)
	if err != nil {
		return nil, err
	}
	switch credentials.Kind {
	case dns.Cloudflare:
		return cloudflareZones(ctx, client)
	case dns.Aliyun:
		return aliyunZones(ctx, client)
	case dns.DNSPod:
		return dnspodZones(ctx, client)
	default:
		return nil, fault.New("SCOPE_INVALID", "DNS 提供商不受支持")
	}
}

type discoveryCredentials struct{ credentials Credentials }

func (d discoveryCredentials) Read(ctx context.Context, scope dns.Scope) (Credentials, error) {
	if err := ctx.Err(); err != nil {
		return Credentials{}, err
	}
	if scope.ProviderID != "" || scope.ZoneID != "" || scope.Kind != d.credentials.Kind {
		return Credentials{}, fault.New("SCOPE_INVALID", "提供商发现不能执行 zone 操作")
	}
	return Credentials{Kind: d.credentials.Kind, Token: append([]byte(nil), d.credentials.Token...), AccessKeyID: d.credentials.AccessKeyID, AccessKeySecret: append([]byte(nil), d.credentials.AccessKeySecret...)}, nil
}

// Validate 共享导入与网络代用的凭据校验；拒绝控制字节、空白和非 ASCII 数据。
func (c Credentials) Validate(kind dns.ProviderKind) error {
	validSecret := func(value []byte) bool {
		if len(value) == 0 || len(value) > 4096 {
			return false
		}
		for _, char := range value {
			if char < '!' || char > '~' {
				return false
			}
		}
		return true
	}
	if c.Kind != kind {
		return fault.New("CREDENTIAL_REVOKED", "提供商凭据类型与授权不符")
	}
	switch kind {
	case dns.Cloudflare:
		if !validSecret(c.Token) || c.AccessKeyID != "" || len(c.AccessKeySecret) != 0 {
			return fault.New("CREDENTIAL_REVOKED", "Cloudflare 凭据格式无效")
		}
	case dns.Aliyun:
		if !names.ID(c.AccessKeyID) || !validSecret(c.AccessKeySecret) || len(c.Token) != 0 {
			return fault.New("CREDENTIAL_REVOKED", "阿里云凭据格式无效")
		}
	case dns.DNSPod:
		if !names.ID(c.AccessKeyID) || !validSecret(c.AccessKeySecret) || len(c.Token) != 0 {
			return fault.New("CREDENTIAL_REVOKED", "腾讯云 DNSPod 凭据格式无效")
		}
	default:
		return fault.New("CREDENTIAL_REVOKED", "提供商凭据类型无效")
	}
	return nil
}

func defaultOptions(options *Options) {
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
}

var _ dns.Providers = (*Registry)(nil)
