// SPDX-License-Identifier: AGPL-3.0-only

// Package resolve 实现宿主固定 DNS 查询、权威/递归采样与 CAA 前置检查。
package resolve

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"golang.org/x/net/dns/dnsmessage"
)

// ======================== 受控解析器与来源 ========================

type Discovery interface {
	NameServers(context.Context, string) ([]string, error)
	Addresses(context.Context, string) ([]netip.Addr, error)
}

// Exchange 只接收固定 53 端口的 DNS 问题，不是任意网络请求入口。
type Exchange interface {
	Query(context.Context, netip.Addr, dnsmessage.Question, bool) (dnsmessage.Message, error)
}

type Options struct {
	Discovery Discovery
	Exchange  Exchange
	Recursive []netip.Addr
	Clock     clock.Clock
}

type Resolver struct {
	discovery Discovery
	exchange  Exchange
	recursive []netip.Addr
	clock     clock.Clock
}

func New(options Options) (*Resolver, error) {
	if options.Discovery == nil {
		options.Discovery = SystemDiscovery{Resolver: &net.Resolver{PreferGo: true}}
	}
	if options.Exchange == nil {
		options.Exchange = &SystemExchange{}
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if len(options.Recursive) == 0 {
		options.Recursive = []netip.Addr{
			netip.MustParseAddr("223.5.5.5"),
			netip.MustParseAddr("119.29.29.29"),
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("2606:4700:4700::1111"),
			netip.MustParseAddr("2400:3200::1"),
		}
	}
	if len(options.Recursive) < 1 || len(options.Recursive) > 8 {
		return nil, fault.New("VALIDATION_FAILED", "递归 DNS 来源数量无效")
	}
	seen := map[netip.Addr]bool{}
	for _, server := range options.Recursive {
		if !publicServer(server) || seen[server] {
			return nil, fault.New("VALIDATION_FAILED", "递归 DNS 来源必须为独立公网地址")
		}
		seen[server] = true
	}
	return &Resolver{discovery: options.Discovery, exchange: options.Exchange, recursive: slices.Clone(options.Recursive), clock: options.Clock}, nil
}

type SystemDiscovery struct{ Resolver *net.Resolver }

func (s SystemDiscovery) NameServers(ctx context.Context, name string) ([]string, error) {
	resolver := s.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	servers, err := resolver.LookupNS(ctx, name)
	if err != nil {
		return nil, fault.New("DNS_UNAVAILABLE", "无法读取授权 zone 的权威 DNS")
	}
	if len(servers) > 16 {
		return nil, fault.New("RESOURCE_EXHAUSTED", "权威 DNS 数量超过上限")
	}
	names := make([]string, 0, len(servers))
	for _, server := range servers {
		names = append(names, strings.TrimSuffix(strings.ToLower(server.Host), "."))
	}
	return names, nil
}

func (s SystemDiscovery) Addresses(ctx context.Context, name string) ([]netip.Addr, error) {
	resolver := s.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, fault.New("DNS_UNAVAILABLE", "无法解析权威 DNS 服务地址")
	}
	return addresses, nil
}

func publicServer(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && !address.Is4In6() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func recordType(kind dns.RecordType) (dnsmessage.Type, error) {
	switch kind {
	case dns.A:
		return dnsmessage.TypeA, nil
	case dns.AAAA:
		return dnsmessage.TypeAAAA, nil
	case dns.CNAME:
		return dnsmessage.TypeCNAME, nil
	case dns.TXT:
		return dnsmessage.TypeTXT, nil
	default:
		return 0, fault.New("VALIDATION_FAILED", "不支持该解析采样类型")
	}
}

func question(name string, kind dnsmessage.Type) (dnsmessage.Question, error) {
	normalized, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return dnsmessage.Question{}, fault.New("VALIDATION_FAILED", "DNS 问题名称无效")
	}
	return dnsmessage.Question{Name: normalized, Type: kind, Class: dnsmessage.ClassINET}, nil
}

func (r *Resolver) query(ctx context.Context, server netip.Addr, name string, kind dnsmessage.Type, recursive bool) (dnsmessage.Message, error) {
	q, err := question(name, kind)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	response, err := r.exchange.Query(ctx, server, q, recursive)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	if !response.Response || response.OpCode != 0 || response.Truncated || len(response.Questions) != 1 || response.Questions[0] != q || len(response.Answers) > 128 || len(response.Authorities) > 64 || len(response.Additionals) > 64 {
		return dnsmessage.Message{}, fault.New("DNS_INVALID_RESPONSE", "DNS 响应头或问题不匹配")
	}
	if (recursive && !response.RecursionAvailable) || (!recursive && !response.Authoritative) {
		return dnsmessage.Message{}, fault.New("DNS_INVALID_RESPONSE", "DNS 响应没有确认所需来源")
	}
	if response.RCode != dnsmessage.RCodeSuccess && response.RCode != dnsmessage.RCodeNameError {
		return dnsmessage.Message{}, fault.New("DNS_UNAVAILABLE", "DNS 来源返回查询失败")
	}
	if response.RCode == dnsmessage.RCodeNameError {
		for _, answer := range response.Answers {
			if answer.Header.Name == q.Name && answer.Header.Type == q.Type {
				return dnsmessage.Message{}, fault.New("DNS_INVALID_RESPONSE", "NXDOMAIN 与所请求的记录回答矛盾")
			}
		}
	}
	return response, nil
}

func values(response dnsmessage.Message, q dnsmessage.Question) ([]string, error) {
	result := []string{}
	for _, answer := range response.Answers {
		if answer.Header.Name != q.Name || answer.Header.Class != dnsmessage.ClassINET || answer.Header.Type != q.Type {
			continue
		}
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			result = append(result, netip.AddrFrom4(body.A).String())
		case *dnsmessage.AAAAResource:
			result = append(result, netip.AddrFrom16(body.AAAA).String())
		case *dnsmessage.CNAMEResource:
			result = append(result, strings.TrimSuffix(strings.ToLower(body.CNAME.String()), "."))
		case *dnsmessage.TXTResource:
			result = append(result, strings.Join(body.TXT, ""))
		default:
			return nil, fault.New("DNS_INVALID_RESPONSE", "DNS 响应记录类型不匹配")
		}
	}
	if len(result) > 128 {
		return nil, fault.New("RESOURCE_EXHAUSTED", "DNS 响应值超过上限")
	}
	return result, nil
}

// Observe 必须包含真实权威和递归来源，不把来源失败解释为已传播。
func (r *Resolver) Observe(ctx context.Context, scope dns.Scope, name string, kind dns.RecordType) ([]dns.Observation, error) {
	if dns.ValidateScope(scope) != nil {
		return nil, fault.New("SCOPE_INVALID", "DNS 采样范围无效")
	}
	canonical, err := names.DNS(name, true)
	if err != nil || canonical != name || !names.InZone(name, scope.ZoneName) {
		return nil, fault.New("ZONE_DENIED", "DNS 采样名称不在授权 zone 内")
	}
	dnsType, err := recordType(kind)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx = bounded
	hosts, err := r.discovery.NameServers(ctx, scope.ZoneName)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 || len(hosts) > 16 {
		return nil, fault.New("DNS_NO_SOURCES", "缺少有效权威 DNS")
	}
	slices.Sort(hosts)
	hosts = slices.Compact(hosts)
	if len(hosts) > 4 {
		hosts = hosts[:4]
	}
	observations := make([]dns.Observation, 0, len(hosts)+len(r.recursive))
	sample := func(server netip.Addr, source string, sourceKind dns.SourceKind) error {
		response, err := r.query(ctx, server, name, dnsType, sourceKind == dns.Recursive)
		if err != nil {
			return err
		}
		q, _ := question(name, dnsType)
		data, err := values(response, q)
		if err != nil {
			return err
		}
		observations = append(observations, dns.Observation{Source: source, Kind: sourceKind, Values: data, CollectedAt: r.clock.Now().UTC()})
		return nil
	}
	for _, host := range hosts {
		canonical, err := names.DNS(host, false)
		if err != nil || canonical != host {
			return nil, fault.New("DNS_INVALID_RESPONSE", "权威 DNS 主机名无效")
		}
		addresses, err := r.discovery.Addresses(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 || len(addresses) > 16 {
			return nil, fault.New("DNS_INVALID_RESPONSE", "权威 DNS 地址数量无效")
		}
		for _, address := range addresses {
			if !publicServer(address) {
				return nil, fault.New("DNS_UNSAFE_SERVER", "权威 DNS 地址不是允许的公网服务")
			}
		}
		slices.SortFunc(addresses, func(a, b netip.Addr) int {
			if a.Is4() != b.Is4() {
				if a.Is4() {
					return -1
				}
				return 1
			}
			return a.Compare(b)
		})
		var lastAuthErr error
		authOK := false
		for _, address := range addresses {
			if err := sample(address, host, dns.Authoritative); err == nil {
				authOK = true
				break
			} else {
				if fault.Code(err) == "DNS_INVALID_RESPONSE" {
					return nil, err
				}
				lastAuthErr = err
			}
		}
		if !authOK {
			return nil, lastAuthErr
		}
	}
	var lastRecErr error
	recOK := 0
	for _, server := range r.recursive {
		if err := sample(server, "recursive/"+server.String(), dns.Recursive); err == nil {
			recOK++
		} else {
			if fault.Code(err) == "DNS_INVALID_RESPONSE" {
				return nil, err
			}
			lastRecErr = err
		}
	}
	if recOK == 0 {
		return nil, lastRecErr
	}
	return observations, nil
}

var _ dns.Resolver = (*Resolver)(nil)
