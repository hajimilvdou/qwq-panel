// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/prerequisites/acme"
	prereqcap "github.com/qwq-panel/qwq/internal/prerequisites/capability"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/deployment"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/provider"
	"github.com/qwq-panel/qwq/internal/prerequisites/resolve"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

const (
	prerequisiteOwnerID       = "tls.certificates"
	prerequisiteNodeID        = "local"
	prerequisitesCloseTimeout = 5 * time.Second
)

// ======================== 宿主准备能力装配栈与受控出站 HTTP 客户端 ========================

// prerequisiteStack 持有控制面启动期间装配完成的域名、证书、自动续期与能力转发栈。
type prerequisiteStack struct {
	Authority  *hostauth.Authority
	Forwarder  *prereqcap.Forwarder
	Renewals   *certificates.RenewalService
	RenewalOps *controller.RenewalOperations
}

// Close 在宿主数据库关闭前安全收尾后台证书任务与监听协程。
func (s *prerequisiteStack) Close(ctx context.Context) error {
	if s == nil || s.Forwarder == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.Forwarder.Close(ctx)
}

func closePrerequisites(prereqs *prerequisiteStack, timeout time.Duration, logger *slog.Logger) {
	if prereqs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := prereqs.Close(ctx); err != nil && logger != nil {
		logger.Warn("prerequisites services closed with an error", "error", err)
	}
}

var blockedPrerequisitePrefixes = []netip.Prefix{
	// IPv4 特殊用途与非公网地址段
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// IPv6 特殊用途、转换与保留地址段
	netip.MustParsePrefix("::/8"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// isBlockedPrerequisiteIP 拒绝所有非公网、回环、私网、链路本地、CGNAT、保留与特殊转换地址。
func isBlockedPrerequisiteIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return true
	}
	ip = ip.Unmap()
	if ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		!ip.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range blockedPrerequisitePrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// newPrerequisiteEgressClient 构造带 SSRF 拨号拦截、TLS>=1.2 且禁重定向的受控外部 API 客户端。
func newPrerequisiteEgressClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		MaxConnsPerHost:       8,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || host == "" || port == "" {
				return nil, errors.New("prerequisite egress: invalid target address")
			}
			var addrs []netip.Addr
			if parsed, parseErr := netip.ParseAddr(host); parseErr == nil {
				addrs = []netip.Addr{parsed}
			} else {
				resolved, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if lookupErr != nil || len(resolved) == 0 {
					return nil, errors.New("prerequisite egress: dns resolution failed")
				}
				addrs = resolved
			}
			verified := make([]netip.Addr, 0, len(addrs))
			for _, addr := range addrs {
				if isBlockedPrerequisiteIP(addr) {
					return nil, errors.New("prerequisite egress: blocked non-public target address")
				}
				verified = append(verified, addr.Unmap())
			}
			var lastErr error
			for _, addr := range verified {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
				if ctx.Err() != nil {
					break
				}
			}
			if lastErr == nil {
				lastErr = errors.New("prerequisite egress: no reachable public address")
			}
			return nil, lastErr
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		Jar:       nil,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ======================== 控制面完整域名与证书准备能力装配 ========================

// wirePrerequisites 装配加密私有仓库、宿主授权、DNS/ACME/Vault/Deployer、续期与插件能力转发。
func wirePrerequisites(
	c *controller.Controller,
	rt *controller.PluginRuntime,
	helper *sandbox.HelperClient,
	logger *slog.Logger,
) (*prerequisiteStack, error) {
	if c == nil {
		return nil, errors.New("controller is required to wire prerequisites")
	}

	// authorizations 命名空间由 hostauth.New 内部创建，其余三个命名空间在此固定装配。
	dnsRepo, err := store.NewEncrypted(store.EncryptedOptions{
		DB:        c.DB(),
		Secrets:   c.Secrets(),
		Namespace: "dns",
	})
	if err != nil {
		return nil, fmt.Errorf("build encrypted dns repository: %w", err)
	}
	certRepo, err := store.NewEncrypted(store.EncryptedOptions{
		DB:        c.DB(),
		Secrets:   c.Secrets(),
		Namespace: "certificates",
	})
	if err != nil {
		return nil, fmt.Errorf("build encrypted certificates repository: %w", err)
	}
	taskRepo, err := store.NewEncrypted(store.EncryptedOptions{
		DB:        c.DB(),
		Secrets:   c.Secrets(),
		Namespace: "tasks",
	})
	if err != nil {
		return nil, fmt.Errorf("build encrypted tasks repository: %w", err)
	}

	egressHTTP := newPrerequisiteEgressClient()

	challengeSource, err := acme.NewChallengeSource(acme.ChallengeSourceOptions{
		Repository: certRepo,
		Clock:      c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build acme challenge source: %w", err)
	}

	authority, err := hostauth.New(hostauth.Options{
		DB:              c.DB(),
		Secrets:         c.Secrets(),
		Operations:      c.Operations(),
		Authorizer:      c.Authorizer(),
		NodeID:          prerequisiteNodeID,
		OwnerID:         prerequisiteOwnerID,
		HTTPClient:      egressHTTP,
		Challenges:      challengeSource,
		Consumers:       c.PrerequisiteConsumerSource(),
		Reservations:    c.PrerequisiteReservationSource(),
		RenewalServices: c.RenewalServiceSource(),
		Clock:           c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build prerequisite authority: %w", err)
	}
	if err := c.SetPrerequisiteAuthority(authority); err != nil {
		return nil, fmt.Errorf("bind prerequisite authority: %w", err)
	}
	if err := c.SetRenewalPolicySource(authority); err != nil {
		return nil, fmt.Errorf("bind renewal policy source: %w", err)
	}
	if rt != nil {
		rt.SetCertRevisionLookup(func(ctx context.Context, certID string) (string, bool, error) {
			entry, found, err := certRepo.Get(ctx, certificates.ResourceKey(prerequisiteOwnerID, certID))
			if err != nil || !found {
				return "", found, err
			}
			clear(entry.Value)
			return entry.Revision, true, nil
		})
	}

	providers, err := provider.New(provider.Options{
		Source: hostauth.CredentialSource{Authority: authority},
		Client: egressHTTP,
		Clock:  c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build dns provider registry: %w", err)
	}

	dnsAuth := hostauth.RequestDNSAuthorizer{
		DNSAuthorizer: hostauth.DNSAuthorizer{Authority: authority},
	}
	dnsMgr, err := dns.New(dns.Options{
		Repository: dnsRepo,
		Providers:  providers,
		Authorizer: dnsAuth,
		Clock:      c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build dns manager: %w", err)
	}

	resolver, err := resolve.New(resolve.Options{
		Clock: c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build dns resolver: %w", err)
	}
	checker, err := dns.NewChecker(dns.CheckerOptions{
		Resolver:   resolver,
		Authorizer: dnsAuth,
		Clock:      c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build dns propagation checker: %w", err)
	}

	trustRoots, err := certificates.NewHostTrustRoots(certificates.HostTrustRootsOptions{})
	if err != nil {
		return nil, fmt.Errorf("load host trust roots: %w", err)
	}
	vault, err := certificates.NewVault(certificates.VaultOptions{
		DB:      c.DB(),
		Secrets: c.Secrets(),
		Imports: authority,
		Roots:   trustRoots,
		Clock:   c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build certificate vault: %w", err)
	}

	deployer, err := deployment.New(deployment.Options{
		Repository: certRepo,
		Authority:  authority,
		Materials:  vault,
		Files:      &deployment.HelperFileBackend{Client: helper},
		Runtime:    &controller.PluginConsumerRuntime{Controller: c},
		Prober:     &deployment.TLSHandshakeProber{Clock: c.Clock()},
		Clock:      c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build certificate deployer: %w", err)
	}

	acmeAuth, err := acme.New(acme.Options{
		DB:              c.DB(),
		Secrets:         c.Secrets(),
		Repository:      certRepo,
		Vault:           vault,
		DNS:             dnsMgr,
		Checker:         checker,
		CAA:             resolver,
		Authorizer:      hostauth.CertificateAuthorizer{Authority: authority},
		DNSContexts:     hostauth.CertificateDNSContexts{Authority: authority},
		CleanupContexts: hostauth.CertificateCleanupContexts{Authority: authority, DNS: dnsMgr},
		Terms:           hostauth.CertificateTerms{Authority: authority},
		HTTP01:          &controller.IngressHTTP01Presenter{Controller: c},
		Client:          egressHTTP,
		Clock:           c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build acme authority: %w", err)
	}

	certMgr, err := certificates.New(certificates.Options{
		Repository: certRepo,
		Materials:  vault,
		Authority:  acmeAuth,
		Bindings:   deployer,
		Authorizer: hostauth.CertificateAuthorizer{Authority: authority},
		Clock:      c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build certificate manager: %w", err)
	}

	renewalRuns, err := certificates.NewPrivateRenewalRuns(certificates.RenewalRunOptions{
		Repository: certRepo,
		Clock:      c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build private renewal runs: %w", err)
	}
	renewalOps, err := controller.NewRenewalOperations(controller.RenewalOperationsOptions{
		Operations: c.Operations(),
		Authority:  authority,
		Runs:       renewalRuns,
		NodeID:     prerequisiteNodeID,
		OwnerID:    prerequisiteOwnerID,
	})
	if err != nil {
		return nil, fmt.Errorf("build renewal operations: %w", err)
	}
	renewals, err := certificates.NewRenewalService(certificates.RenewalOptions{
		Repository:    certRepo,
		Manager:       certMgr,
		Confirmations: hostauth.RenewalConfirmations{Authority: authority},
		Operations:    renewalOps,
		Contexts:      hostauth.RenewalContexts{Authority: authority, Runs: renewalRuns},
		Clock:         c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build certificate renewal service: %w", err)
	}

	forwarder, err := prereqcap.NewForwarder(prereqcap.ForwardOptions{
		Authority:      authority,
		DNS:            dnsMgr,
		Checker:        checker,
		Certificates:   certMgr,
		Renewals:       renewals,
		Views:          prereqcap.NewRepositoryViews(taskRepo),
		TaskRepository: taskRepo,
		Clock:          c.Clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("build prerequisite capability forwarder: %w", err)
	}

	if rt != nil {
		if err := rt.SetCapabilityService("dns", forwarder); err != nil {
			_ = forwarder.Close(context.Background())
			return nil, fmt.Errorf("register dns capability service: %w", err)
		}
		if err := rt.SetCapabilityService("certificates", forwarder); err != nil {
			_ = forwarder.Close(context.Background())
			return nil, fmt.Errorf("register certificates capability service: %w", err)
		}
		rt.SetRenewalJobHandler(renewalOps.HandleJob)
	}

	if logger != nil {
		logger.Info("prerequisites host services wired",
			"plugin_runtime", rt != nil,
			"privileged_helper", helper != nil)
	}
	return &prerequisiteStack{
		Authority:  authority,
		Forwarder:  forwarder,
		Renewals:   renewals,
		RenewalOps: renewalOps,
	}, nil
}
