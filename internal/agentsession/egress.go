// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// 模型端点出站控制（AGT-03）
//
// base_url 由会话 owner 填写，而 owner 可以是低权限用户：宿主不能替 TA 访问内网。
// 判定放在 DNS 解析之后的拨号点，因此 DNS rebinding 绕不过去；放行只能来自管理员
// 的配置文件（agent.model_egress_allow）。
// ---------------------------------------------------------------------------

// errEgressDenied is the dial error of an address outside the egress policy.
var errEgressDenied = errors.New("agentsession: model endpoint outside the egress policy")

// egressDeniedDetail is the fixed answer of a refused endpoint: it never echoes
// the address, so the session owner cannot use it as a network probe.
const egressDeniedDetail = "模型端点不在允许的出站范围内"

// modelDialTimeout bounds connecting to a model endpoint.
const modelDialTimeout = 10 * time.Second

// reservedPrefixes are the ranges the netip predicates do not cover. The NAT64
// and 6to4 prefixes are listed because they embed an IPv4 destination.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// --- IPv6保留/转换/丢弃/隧道地址：默认拒绝可能绕到其他真实目的地的范围 ---
	netip.MustParsePrefix("0000::/8"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fec0::/10"),
}

// defaultEgressAllow admits public unicast destinations only.
func defaultEgressAllow(dst netip.AddrPort) bool {
	ip := dst.Addr().Unmap().WithZone("")
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reservedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// egressPolicy is the default policy widened by the administrator's list.
func egressPolicy(prefixes []netip.Prefix, addrs []netip.AddrPort) func(netip.AddrPort) bool {
	return func(dst netip.AddrPort) bool {
		ip := dst.Addr().Unmap().WithZone("")
		for _, p := range prefixes {
			if p.Contains(ip) {
				return true
			}
		}
		for _, a := range addrs {
			if a.Addr().Unmap() == ip && a.Port() == dst.Port() {
				return true
			}
		}
		return defaultEgressAllow(dst)
	}
}

// newModelClient builds the outbound-controlled model client: the destination
// is judged after DNS resolution, redirects are not followed and the
// environment's proxy is ignored. The request deadline stays with the caller;
// the header timeout is only a backstop, so it must not undercut the longest
// timeout_seconds a session may configure.
func newModelClient(allow func(netip.AddrPort) bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   modelDialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			dst, err := parseDialAddress(address)
			if err != nil || !allow(dst) {
				return errEgressDenied
			}
			return nil
		},
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	transport.ResponseHeaderTimeout = maxModelTimeout
	transport.MaxResponseHeaderBytes = 64 << 10
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// parseDialAddress reads the resolved "ip:port" the dialer is about to connect
// to; an IPv6 link-local address may carry a zone, which ParseAddr accepts.
func parseDialAddress(address string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}
