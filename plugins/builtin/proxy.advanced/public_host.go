// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net"
	"net/netip"
	"strings"
)

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// detectPrimaryPublicHost resolves the client-facing connection address for
// managed nodes and subscriptions: explicit node server -> configured
// public_host -> global unicast public IPv4 -> public IPv6 -> non-virtual
// private IPv4 fallback (for NAT VPS instances). Never emits YOUR_SERVER_IP
// when any usable host interface exists.
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
	var bestV4, bestV6, fallbackPrivateV4 string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "cni") ||
			strings.HasPrefix(name, "virbr") {
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
			if !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() {
				continue
			}
			if addr.Is4() {
				if !addr.IsPrivate() && !cgnatPrefix.Contains(addr) {
					if bestV4 == "" {
						bestV4 = addr.String()
					}
				} else if fallbackPrivateV4 == "" {
					fallbackPrivateV4 = addr.String()
				}
			} else if addr.Is6() && !addr.IsPrivate() && bestV6 == "" {
				bestV6 = addr.String()
			}
		}
	}
	if bestV4 != "" {
		return bestV4
	}
	if bestV6 != "" {
		return bestV6
	}
	return fallbackPrivateV4
}
