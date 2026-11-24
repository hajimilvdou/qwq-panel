// SPDX-License-Identifier: AGPL-3.0-only

// Package acme 实现受控 Let's Encrypt DNS-01 与持久订单对账。
package acme

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 宿主授权与实际后端依赖 ========================

type CAA interface {
	CheckCAA(context.Context, dns.Scope, []string, string) error
}

type TermsAcceptance interface {
	Accept(context.Context, certificates.Caller, certificates.CA, string) error
}

// DNSContexts 在宿主身份链中建立精确 DNS 委托；cleanup 只允许原 attempt 清理。
// 插件不能构造此上下文，缺失实现不能用自报 owner 或无 operation 代替。
type DNSContexts interface {
	Context(context.Context, certificates.Caller, string, string, certificates.IssuanceScope, bool) (context.Context, error)
}

// CleanupContexts 在读原 journal 前开启同 executor 硬预算，再逐已确认 TXT 建许可。
// 初始 Source 不提供凭据或 DNS 请求权限，ForChallenge 必须固定真实记录事实。
type CleanupContexts interface {
	Source(context.Context, certificates.Caller, string, string, certificates.IssuanceScope) (context.Context, context.CancelFunc, error)
	ForChallenge(context.Context, certificates.Caller, string, string, certificates.IssuanceScope, dns.OwnedChallenge) (context.Context, context.CancelFunc, error)
}

// HTTP01Presenter 负责向本机内置反向代理（web.ingress :80）注入或清理 /.well-known/acme-challenge/<token> 临时响应。
type HTTP01Presenter interface {
	Present(ctx context.Context, token, keyAuth string, ttl time.Duration) error
	CleanUp(ctx context.Context, token string) error
}

type Options struct {
	DB              *storage.DB
	Secrets         *secrets.Store
	Repository      store.Repository
	Vault           *certificates.Vault
	DNS             *dns.Manager
	Checker         *dns.Checker
	CAA             CAA
	Authorizer      certificates.Authorizer
	DNSContexts     DNSContexts
	CleanupContexts CleanupContexts
	Terms           TermsAcceptance
	HTTP01          HTTP01Presenter
	Client          *http.Client
	Clock           clock.Clock
	Random          io.Reader
	Timeout         time.Duration
	CleanupTimeout  time.Duration
}

type Authority struct {
	db                      *storage.DB
	secrets                 *secrets.Store
	repository              store.Repository
	vault                   *certificates.Vault
	dns                     *dns.Manager
	checker                 *dns.Checker
	caa                     CAA
	authorizer              certificates.Authorizer
	dnsContexts             DNSContexts
	cleanupContexts         CleanupContexts
	terms                   TermsAcceptance
	http01                  HTTP01Presenter
	client                  *http.Client
	clock                   clock.Clock
	random                  io.Reader
	timeout, cleanupTimeout time.Duration
}

// ======================== 私有订单、CSR 与 challenge 日志 ========================

type challenge struct {
	AuthorizationURI string `json:"authorization_uri"`
	SAN              string `json:"san"`
	URI              string `json:"uri"`
	Token            string `json:"token"`
	Value            string `json:"value"`
	DNSAttempt       string `json:"dns_attempt,omitempty"`
	DNSRevision      string `json:"dns_revision,omitempty"`
	DNSRound         uint32 `json:"dns_round"`
	DNSSubmitted     bool   `json:"dns_submitted"`
	Presented        bool   `json:"presented"`
	Accepted         bool   `json:"accepted"`
	Validated        bool   `json:"validated"`
	Cleaned          bool   `json:"cleaned"`
}

type journal struct {
	Version        uint32                     `json:"version"`
	OwnerID        string                     `json:"owner_id"`
	CertificateID  string                     `json:"certificate_id"`
	AttemptID      string                     `json:"attempt_id"`
	Scope          certificates.IssuanceScope `json:"scope"`
	KeyRef         secrets.Ref                `json:"key_ref"`
	CSR            []byte                     `json:"csr"`
	AccountURI     string                     `json:"account_uri,omitempty"`
	OrderURI       string                     `json:"order_uri,omitempty"`
	FinalizeURI    string                     `json:"finalize_uri,omitempty"`
	CertificateURI string                     `json:"certificate_uri,omitempty"`
	Challenges     []challenge                `json:"challenges"`
	Phase          string                     `json:"phase"`
	Material       certificates.MaterialRef   `json:"material_ref,omitempty"`
	LeaseToken     string                     `json:"lease_token,omitempty"`
	LeaseUntil     time.Time                  `json:"lease_until,omitempty"`
	CreatedAt      time.Time                  `json:"created_at"`
	ErrorCode      string                     `json:"error_code,omitempty"`
	RetryAt        time.Time                  `json:"retry_at,omitempty"`
}

func (journal) String() string     { return "acme.journal{[REDACTED]}" }
func (journal) GoString() string   { return "acme.journal{[REDACTED]}" }
func (challenge) String() string   { return "acme.challenge{[REDACTED]}" }
func (challenge) GoString() string { return "acme.challenge{[REDACTED]}" }
