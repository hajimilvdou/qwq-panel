// SPDX-License-Identifier: AGPL-3.0-only

package netfacts

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ======================== /proc/net 路由解析、网卡过滤与私网归类验证 ========================

func writeTempRouteFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCollectProcRoutesAndInterfaceFiltering(t *testing.T) {
	routeV4 := writeTempRouteFile(t, "route", strings.Join([]string{
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
		"docker0\t00000000\t010011AC\t0003\t0\t0\t10\t00000000\t0\t0\t0",
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0",
		"eth1\t00000000\t0101000A\t0003\t0\t0\t200\t00000000\t0\t0\t0",
	}, "\n")+"\n")

	routeV6 := writeTempRouteFile(t, "ipv6_route", strings.Join([]string{
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000100 00000000 00000000 00000003 eth0",
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0",
	}, "\n")+"\n")

	ifaces := []ifaceSnapshot{
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}},
		{Name: "docker0", Flags: net.FlagUp, Addrs: []netip.Addr{netip.MustParseAddr("172.17.0.1")}},
		{Name: "veth1234", Flags: net.FlagUp, Addrs: []netip.Addr{netip.MustParseAddr("10.88.0.2")}},
		{Name: "tailscale0", Flags: net.FlagUp, Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
		{Name: "wg0", Flags: net.FlagUp, Addrs: []netip.Addr{netip.MustParseAddr("10.99.0.1")}},
		{Name: "ifb0", Flags: net.FlagUp, Addrs: []netip.Addr{netip.MustParseAddr("192.168.99.1")}},
		{
			Name:  "eth0",
			Flags: net.FlagUp,
			Addrs: []netip.Addr{
				netip.MustParseAddr("10.0.0.5"),     // RFC1918 -> private_or_nat
				netip.MustParseAddr("100.64.10.2"),  // CGNAT -> private_or_nat
				netip.MustParseAddr("fe80::1"),      // link-local -> filtered
				netip.MustParseAddr("fd00::12"),     // ULA -> private_or_nat
				netip.MustParseAddr("2001:db8::42"), // global_public
			},
		},
	}

	facts, err := collectFrom(ifaces, routeV4, routeV6)
	if err != nil {
		t.Fatal(err)
	}
	if !facts.HasDefaultRouteV4 || facts.DefaultIfV4 != "eth0" {
		t.Fatalf("IPv4 默认路由解析不符: has=%v if=%q", facts.HasDefaultRouteV4, facts.DefaultIfV4)
	}
	if !facts.HasDefaultRouteV6 || facts.DefaultIfV6 != "eth0" {
		t.Fatalf("IPv6 默认路由解析不符: has=%v if=%q", facts.HasDefaultRouteV6, facts.DefaultIfV6)
	}
	if facts.HasPublicIPv4 {
		t.Fatalf("仅有 RFC1918/CGNAT 时不应误判 HasPublicIPv4=true: %+v", facts)
	}
	if !facts.HasPublicIPv6 {
		t.Fatalf("存在 2001:db8::42 时应识别 HasPublicIPv6=true: %+v", facts)
	}
	if len(facts.Addresses) != 4 {
		t.Fatalf("虚拟网卡与 link-local 应被过滤，期望剩 4 个地址，实际: %+v", facts.Addresses)
	}
	hasNATWarn := false
	for _, w := range facts.Warnings {
		if strings.Contains(w, "VPC NAT") {
			hasNATWarn = true
		}
	}
	if !hasNATWarn {
		t.Fatalf("无公网 v4 但有默认路由时应生成 VPC NAT 提示，实际 warnings=%v", facts.Warnings)
	}
}

func TestValidateOutboundAgainstFacts(t *testing.T) {
	v4OnlyFacts := HostNetworkFacts{
		Addresses: []AddressFact{
			{Interface: "eth0", Address: "203.0.113.10", Family: "ipv4", Scope: "global_public"},
		},
		HasPublicIPv4:     true,
		HasDefaultRouteV4: true,
		HasDefaultRouteV6: false,
	}

	if err := ValidateOutboundAgainstFacts(ModeIPv6Only, "", "", v4OnlyFacts); err == nil || !strings.Contains(err.Error(), "PRECONDITION_FAILED") {
		t.Fatalf("无 IPv6 默认路由必须拒绝 ipv6_only 并包含 PRECONDITION_FAILED，实际: %v", err)
	}
	if err := ValidateOutboundAgainstFacts(ModeIPv4Only, "203.0.113.10", "", v4OnlyFacts); err != nil {
		t.Fatalf("合法的 ipv4_only + 本机 bindV4 应通过: %v", err)
	}
	if err := ValidateOutboundAgainstFacts(ModePreferIPv4, "203.0.113.99", "", v4OnlyFacts); err == nil || !strings.Contains(err.Error(), "PRECONDITION_FAILED") {
		t.Fatalf("不存在于本机网卡的 bindV4 必须拒绝，实际: %v", err)
	}

	v6OnlyFacts := HostNetworkFacts{
		Addresses: []AddressFact{
			{Interface: "eth0", Address: "2001:db8::5", Family: "ipv6", Scope: "global_public"},
		},
		HasPublicIPv6:     true,
		HasDefaultRouteV4: false,
		HasDefaultRouteV6: true,
	}
	if err := ValidateOutboundAgainstFacts(ModeIPv4Only, "", "", v6OnlyFacts); err == nil || !strings.Contains(err.Error(), "PRECONDITION_FAILED") {
		t.Fatalf("无 IPv4 默认路由必须拒绝 ipv4_only，实际: %v", err)
	}
	if err := ValidateOutboundAgainstFacts(ModeIPv6Only, "", "2001:db8::5", v6OnlyFacts); err != nil {
		t.Fatalf("合法的 ipv6_only + 本机 bindV6 应通过: %v", err)
	}
}

// ======================== 第一跳候选排序、单栈隔离与指数退避冷却验证 ========================

func TestCandidateSelectorModesBackoffAndDeadlockGuard(t *testing.T) {
	sel := NewCandidateSelector()
	if sel.FallbackDelay != 250*time.Millisecond {
		t.Fatalf("默认 FallbackDelay=%v，期望 250ms", sel.FallbackDelay)
	}

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	cands := []EndpointCandidate{
		{ID: "v6-p1", Host: "2001:db8::1", Port: 443, Priority: 1},
		{ID: "v4-p2", Host: "203.0.113.2", Port: 443, Priority: 2},
		{ID: "v4-p1", Host: "203.0.113.1", Port: 443, Priority: 1},
		{ID: "v6-p2", Host: "2001:db8::2", Port: 443, Priority: 2},
	}

	// 1. 单栈绝不越界回退。
	onlyV4 := sel.PlanOrder(ModeIPv4Only, cands, now)
	if len(onlyV4) != 2 || onlyV4[0].ID != "v4-p1" || onlyV4[1].ID != "v4-p2" {
		t.Fatalf("ipv4_only 必须严格剔除 IPv6 并按优先级排序: %+v", onlyV4)
	}
	onlyV6 := sel.PlanOrder(ModeIPv6Only, cands, now)
	if len(onlyV6) != 2 || onlyV6[0].ID != "v6-p1" || onlyV6[1].ID != "v6-p2" {
		t.Fatalf("ipv6_only 必须严格剔除 IPv4 并按优先级排序: %+v", onlyV6)
	}

	// 2. 双栈优先排序。
	prefV4 := sel.PlanOrder(ModePreferIPv4, cands, now)
	if len(prefV4) != 4 || prefV4[0].ID != "v4-p1" || prefV4[1].ID != "v4-p2" || prefV4[2].ID != "v6-p1" || prefV4[3].ID != "v6-p2" {
		t.Fatalf("prefer_ipv4 排序不符: %+v", prefV4)
	}
	prefV6 := sel.PlanOrder(ModePreferIPv6, cands, now)
	if len(prefV6) != 4 || prefV6[0].ID != "v6-p1" || prefV6[1].ID != "v6-p2" || prefV6[2].ID != "v4-p1" || prefV6[3].ID != "v4-p2" {
		t.Fatalf("prefer_ipv6 排序不符: %+v", prefV6)
	}

	// 3. 指数退避冷却：30s -> 60s -> 120s -> 240s -> 300s 上限。
	for i, wantSec := range []int{30, 60, 120, 240, 300, 300} {
		sel.RecordFailure("v4-p1", now)
		if got := failureCooldownDuration(i + 1); got != time.Duration(wantSec)*time.Second {
			t.Fatalf("第 %d 次失败退避=%v，期望=%ds", i+1, got, wantSec)
		}
	}
	// v4-p1 正在冷却，应被跳过。
	afterFail := sel.PlanOrder(ModeIPv4Only, cands, now.Add(10*time.Second))
	if len(afterFail) != 1 || afterFail[0].ID != "v4-p2" {
		t.Fatalf("冷却中候选应被跳过，实际: %+v", afterFail)
	}

	// 4. 全部冷却时放行最早到期的 1 个候选防止永久死锁。
	sel.RecordFailure("v4-p2", now.Add(5*time.Second)) // 冷却至 +35s，早于 v4-p1 的 +300s。
	allCooled := sel.PlanOrder(ModeIPv4Only, cands, now.Add(10*time.Second))
	if len(allCooled) != 1 || allCooled[0].ID != "v4-p2" {
		t.Fatalf("全冷却时应放行最早到期的 v4-p2，实际: %+v", allCooled)
	}

	// 5. RecordSuccess 立即解除冷却。
	sel.RecordSuccess("v4-p1")
	recovered := sel.PlanOrder(ModeIPv4Only, cands, now.Add(10*time.Second))
	if len(recovered) != 1 || recovered[0].ID != "v4-p1" {
		t.Fatalf("RecordSuccess 后 v4-p1 应立即恢复可用: %+v", recovered)
	}
}
