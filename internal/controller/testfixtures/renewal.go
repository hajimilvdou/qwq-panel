// SPDX-License-Identifier: AGPL-3.0-only

// Package testfixtures 共享宿主与 HTTP 集成测试的固定续期范围，不参与生产装配。
package testfixtures

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 仅替代私有事实源；身份、审批和 SQLite 保持真实 ========================

// PolicySource 让两个集成测试包复用同一只读策略接口。
type PolicySource func(context.Context, actor.Actor, string, string) (hostauth.RenewalServiceRequest, error)

func (source PolicySource) PrepareRenewalService(ctx context.Context, who actor.Actor, policyID, revision string) (hostauth.RenewalServiceRequest, error) {
	return source(ctx, who, policyID, revision)
}

// RenewalRequest 返回独立切片与固定 staging 范围，不访问实际 DNS 或 CA。
func RenewalRequest() hostauth.RenewalServiceRequest {
	return hostauth.RenewalServiceRequest{PolicyID: "renewal_fixture", ExpiresAt: time.Now().UTC().Add(time.Hour),
		Scope: certificates.RenewalScope{OwnerID: "tls.certificates", CertificateID: "certificate_fixture",
			Issuance: certificates.IssuanceScope{CA: certificates.LetsEncryptStaging,
				Spec:     certificates.Spec{SANs: []string{"proxy.example.test"}, Purpose: tlsmgr.ServerTLS},
				Provider: dns.Scope{ProviderID: "provider_fixture", Kind: dns.Cloudflare, ZoneID: "zone_fixture", ZoneName: "example.test", Revision: "scope1"}},
			Consumers: []certificates.Consumer{{PluginID: "core.xray", ProfileID: "h2_fixture", NodeID: "local",
				SNI: "proxy.example.test", Purpose: "proxy.hysteria2", Test: true}}}}
}
