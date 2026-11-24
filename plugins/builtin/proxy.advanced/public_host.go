// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net"
	"net/netip"
	"strings"
)

var (
	cgnatPrefix      = netip.MustParsePrefix("100.64.0.0/10")
	benchmarkPrefix  = netip.MustParsePrefix("198.18.0.0/15") // RFC 2544 / Clash & sing-box TUN fake-IP
	thisNetPrefix    = netip.MustParsePrefix("0.0.0.0/8")
	reservedV4Prefix = netip.MustParsePrefix("240.0.0.0/4")
	docV6Prefix      = netip.MustParsePrefix("2001:db8::/32")
)

var virtualIfacePrefixes = []string{
	"docker", "br-", "veth", "cni", "virbr",
	"tun", "tap", "utun", "wg", "tailscale", "zt",
	"podman", "kube", "flannel", "cali", "cilium", "dummy", "lo",
}

func isVirtualInterfaceName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, pfx := range virtualIfacePrefixes {
		if strings.HasPrefix(lower, pfx) {
			return true
		}
	}
	return false
}

func isGenuinePublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() || addr.IsPrivate() {
		return false
	}
	if addr.Is4() {
		return !cgnatPrefix.Contains(addr) &&
			!benchmarkPrefix.Contains(addr) &&
			!thisNetPrefix.Contains(addr) &&
			!reservedV4Prefix.Contains(addr)
	}
	if addr.Is6() {
		return !docV6Prefix.Contains(addr)
	}
	return false
}

// detectPrimaryPublicHost resolves the client-facing connection address for
// managed nodes and subscriptions: explicit node server -> configured
// public_host -> genuine global unicast public IPv4 -> public IPv6.
// Never returns virtual/TUN/fake-IP or RFC1918 private addresses so NAT VPS
// nodes and subscriptions are never poisoned with unreachable LAN IPs.
func detectPrimaryPublicHost(configuredPublicHost, explicitNodeServer string) string {
	if s := strings.TrimSpace(explicitNodeServer); s != "" {
		return s
	}
	if s := strings.TrimSpace(configuredPublicHost); s != "" {
		return s
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var bestV4, bestV6 string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtualInterfaceName(iface.Name) {
			continue
		}
		addrs, aerr := iface.Addrs()
		if aerr != nil {
			continue
		}
		for _, raw := range addrs {
			ipNet, ok := raw.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !isGenuinePublicAddr(addr) {
				continue
			}
			if addr.Is4() && bestV4 == "" {
				bestV4 = addr.String()
			} else if addr.Is6() && bestV6 == "" {
				bestV6 = addr.String()
			}
		}
	}
	if bestV4 != "" {
		return bestV4
	}
	return bestV6
}
