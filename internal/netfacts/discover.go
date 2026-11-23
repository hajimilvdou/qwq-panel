// SPDX-License-Identifier: AGPL-3.0-only

// Package netfacts 提供零外部命令的宿主双栈网络探测、出站策略预检与第一跳候选排序器。
package netfacts

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ======================== 地址族策略与宿主网络事实结构 ========================

// FamilyMode 描述单栈或双栈优先连接策略。
type FamilyMode string

const (
	ModeIPv4Only   FamilyMode = "ipv4_only"
	ModeIPv6Only   FamilyMode = "ipv6_only"
	ModePreferIPv4 FamilyMode = "prefer_ipv4"
	ModePreferIPv6 FamilyMode = "prefer_ipv6"
)

// ValidFamilyMode 判断地址族模式是否属于受支持的 4 种常量之一。
func ValidFamilyMode(m FamilyMode) bool {
	switch m {
	case ModeIPv4Only, ModeIPv6Only, ModePreferIPv4, ModePreferIPv6:
		return true
	default:
		return false
	}
}

// AddressFact 描述单张活跃物理网卡上的一个有效单播 IP 地址。
type AddressFact struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	Family    string `json:"family"`
	Scope     string `json:"scope"`
}

// HostNetworkFacts 汇总宿主机的双栈地址、默认路由与诚实能力告警。
type HostNetworkFacts struct {
	Addresses         []AddressFact `json:"addresses"`
	HasPublicIPv4     bool          `json:"has_public_ipv4"`
	HasPublicIPv6     bool          `json:"has_public_ipv6"`
	HasDefaultRouteV4 bool          `json:"has_default_route_v4"`
	HasDefaultRouteV6 bool          `json:"has_default_route_v6"`
	DefaultIfV4       string        `json:"default_if_v4,omitempty"`
	DefaultIfV6       string        `json:"default_if_v6,omitempty"`
	Warnings          []string      `json:"warnings,omitempty"`
}

const (
	defaultProcRouteV4 = "/proc/net/route"
	defaultProcRouteV6 = "/proc/net/ipv6_route"
)

var (
	cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
	zeroPrefix  = netip.MustParsePrefix("0.0.0.0/8")
	futureV4    = netip.MustParsePrefix("240.0.0.0/4")
)

type ifaceSnapshot struct {
	Name  string
	Flags net.Flags
	Addrs []netip.Addr
}

// Collect 零 shell 调用地读取本机网卡与 /proc/net/{route,ipv6_route}，生成双栈网络事实。
func Collect(procRouteV4, procRouteV6 string) (HostNetworkFacts, error) {
	if strings.TrimSpace(procRouteV4) == "" {
		procRouteV4 = defaultProcRouteV4
	}
	if strings.TrimSpace(procRouteV6) == "" {
		procRouteV6 = defaultProcRouteV6
	}
	ifaces, err := readSystemInterfaces()
	if err != nil {
		return HostNetworkFacts{}, fmt.Errorf("netfacts: read interfaces: %w", err)
	}
	return collectFrom(ifaces, procRouteV4, procRouteV6)
}

func readSystemInterfaces() ([]ifaceSnapshot, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]ifaceSnapshot, 0, len(list))
	for _, iface := range list {
		rawAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		addrs := make([]netip.Addr, 0, len(rawAddrs))
		for _, a := range rawAddrs {
			if addr, ok := parseNetAddr(a); ok {
				addrs = append(addrs, addr)
			}
		}
		out = append(out, ifaceSnapshot{
			Name:  iface.Name,
			Flags: iface.Flags,
			Addrs: addrs,
		})
	}
	return out, nil
}

func collectFrom(ifaces []ifaceSnapshot, procRouteV4, procRouteV6 string) (HostNetworkFacts, error) {
	facts := HostNetworkFacts{
		Addresses: make([]AddressFact, 0),
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isIgnoredInterface(iface.Name) {
			continue
		}
		for _, raw := range iface.Addrs {
			addr := raw.Unmap()
			if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
				addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
				continue
			}
			family := "ipv4"
			if addr.Is6() {
				family = "ipv6"
			}
			scope := classifyAddressScope(addr)
			if scope == "global_public" {
				if family == "ipv4" {
					facts.HasPublicIPv4 = true
				} else {
					facts.HasPublicIPv6 = true
				}
			}
			facts.Addresses = append(facts.Addresses, AddressFact{
				Interface: iface.Name,
				Address:   addr.String(),
				Family:    family,
				Scope:     scope,
			})
		}
	}

	slices.SortFunc(facts.Addresses, func(a, b AddressFact) int {
		if c := cmp.Compare(a.Interface, b.Interface); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Family, b.Family); c != 0 {
			return c
		}
		return cmp.Compare(a.Address, b.Address)
	})

	if ifaceV4, ok, err := parseProcRouteV4(procRouteV4); err != nil && !errors.Is(err, os.ErrNotExist) {
		return facts, fmt.Errorf("netfacts: parse ipv4 route: %w", err)
	} else if ok {
		facts.HasDefaultRouteV4 = true
		facts.DefaultIfV4 = ifaceV4
	}

	if ifaceV6, ok, err := parseProcRouteV6(procRouteV6); err != nil && !errors.Is(err, os.ErrNotExist) {
		return facts, fmt.Errorf("netfacts: parse ipv6 route: %w", err)
	} else if ok {
		facts.HasDefaultRouteV6 = true
		facts.DefaultIfV6 = ifaceV6
	}

	if !facts.HasPublicIPv4 && facts.HasDefaultRouteV4 {
		facts.Warnings = append(facts.Warnings, "未检测到本机公网 IPv4 地址，但存在 IPv4 默认路由（可能处于云厂商 VPC NAT / EIP 映射环境）")
	}
	if !facts.HasDefaultRouteV6 {
		facts.Warnings = append(facts.Warnings, "未检测到 IPv6 默认路由，禁止配置 ipv6_only 出站策略")
	}
	if !facts.HasDefaultRouteV4 {
		facts.Warnings = append(facts.Warnings, "未检测到 IPv4 默认路由，禁止配置 ipv4_only 出站策略")
	}
	if !facts.HasPublicIPv6 && facts.HasDefaultRouteV6 {
		facts.Warnings = append(facts.Warnings, "检测到 IPv6 默认路由但未发现公网 IPv6 地址（可能使用 ULA 或 NAT66）")
	}
	return facts, nil
}

// ValidateOutboundAgainstFacts 根据宿主机真实网络事实校验出站地址族与绑定源 IP。
func ValidateOutboundAgainstFacts(mode FamilyMode, bindV4, bindV6 string, facts HostNetworkFacts) error {
	if !ValidFamilyMode(mode) {
		return fmt.Errorf("VALIDATION_FAILED: 不支持的地址族模式 %q", mode)
	}
	if mode == ModeIPv6Only && !facts.HasDefaultRouteV6 {
		return errors.New("PRECONDITION_FAILED: 当前宿主机无 IPv6 默认路由，拒绝启用 ipv6_only")
	}
	if mode == ModeIPv4Only && !facts.HasDefaultRouteV4 {
		return errors.New("PRECONDITION_FAILED: 当前宿主机无 IPv4 默认路由，拒绝启用 ipv4_only")
	}
	if trimmed := strings.TrimSpace(bindV4); trimmed != "" {
		addr, err := netip.ParseAddr(trimmed)
		if err != nil || !addr.Is4() || addr.Zone() != "" {
			return fmt.Errorf("VALIDATION_FAILED: 无效的 IPv4 绑定地址 %q", trimmed)
		}
		if !hasHostAddress(facts.Addresses, "ipv4", addr.String()) {
			return fmt.Errorf("PRECONDITION_FAILED: IPv4 绑定地址 %s 不存在于本机活跃网卡", addr.String())
		}
	}
	if trimmed := strings.TrimSpace(bindV6); trimmed != "" {
		addr, err := netip.ParseAddr(strings.Trim(trimmed, "[]"))
		if err != nil || !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
			return fmt.Errorf("VALIDATION_FAILED: 无效的 IPv6 绑定地址 %q", trimmed)
		}
		if !hasHostAddress(facts.Addresses, "ipv6", addr.String()) {
			return fmt.Errorf("PRECONDITION_FAILED: IPv6 绑定地址 %s 不存在于本机活跃网卡", addr.String())
		}
	}
	return nil
}

// ======================== 第一跳端点候选排序与指数退避冷却器 ========================

// EndpointCandidate 表示一个待排序连接的第一跳入口端点。
type EndpointCandidate struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Priority int    `json:"priority"`
}

type cooldownEntry struct {
	failures int
	until    time.Time
}

// CandidateSelector 依据地址族模式、优先级与失败冷却窗口规划连接顺序。
type CandidateSelector struct {
	FallbackDelay time.Duration

	mu        sync.Mutex
	cooldowns map[string]cooldownEntry
}

// NewCandidateSelector 创建默认回退延迟 250ms 的第一跳候选选择器。
func NewCandidateSelector() *CandidateSelector {
	return &CandidateSelector{
		FallbackDelay: 250 * time.Millisecond,
		cooldowns:     make(map[string]cooldownEntry),
	}
}

// PlanOrder 按模式过滤地址族、按首选族与优先级排序并跳过冷却中候选。
// 若所有候选均在冷却期内，放行最早到期的 1 个候选防止永久死锁。
func (s *CandidateSelector) PlanOrder(mode FamilyMode, candidates []EndpointCandidate, now time.Time) []EndpointCandidate {
	filtered := make([]EndpointCandidate, 0, len(candidates))
	for _, c := range candidates {
		fam := candidateHostFamily(c.Host)
		if mode == ModeIPv4Only && fam == "ipv6" {
			continue
		}
		if mode == ModeIPv6Only && fam == "ipv4" {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) == 0 {
		return make([]EndpointCandidate, 0)
	}

	s.mu.Lock()
	ready := make([]EndpointCandidate, 0, len(filtered))
	type cooledItem struct {
		cand  EndpointCandidate
		until time.Time
	}
	cooling := make([]cooledItem, 0)
	for _, c := range filtered {
		st, has := s.cooldowns[c.ID]
		if has && now.Before(st.until) {
			cooling = append(cooling, cooledItem{cand: c, until: st.until})
			continue
		}
		ready = append(ready, c)
	}
	s.mu.Unlock()

	if len(ready) == 0 && len(cooling) > 0 {
		slices.SortFunc(cooling, func(a, b cooledItem) int {
			if a.until.Before(b.until) {
				return -1
			}
			if a.until.After(b.until) {
				return 1
			}
			if c := cmp.Compare(a.cand.Priority, b.cand.Priority); c != 0 {
				return c
			}
			return cmp.Compare(a.cand.ID, b.cand.ID)
		})
		return []EndpointCandidate{cooling[0].cand}
	}

	slices.SortFunc(ready, func(a, b EndpointCandidate) int {
		if c := cmp.Compare(familyRank(mode, candidateHostFamily(a.Host)), familyRank(mode, candidateHostFamily(b.Host))); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Priority, b.Priority); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return ready
}

// RecordFailure 对指定候选累加失败次数并设置指数退避冷却（30s -> 60s -> 120s -> 240s -> 300s）。
func (s *CandidateSelector) RecordFailure(id string, now time.Time) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cooldowns == nil {
		s.cooldowns = make(map[string]cooldownEntry)
	}
	if _, exists := s.cooldowns[id]; !exists && len(s.cooldowns) >= 1024 {
		for k, v := range s.cooldowns {
			if !now.Before(v.until) {
				delete(s.cooldowns, k)
			}
		}
		if len(s.cooldowns) >= 1024 {
			return
		}
	}
	st := s.cooldowns[id]
	st.failures++
	delay := failureCooldownDuration(st.failures)
	st.until = now.Add(delay)
	s.cooldowns[id] = st
}

// RecordSuccess 清除指定候选的失败冷却状态。
func (s *CandidateSelector) RecordSuccess(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	delete(s.cooldowns, id)
	s.mu.Unlock()
}

// ======================== /proc/net 路由解析与地址分类辅助 ========================

func failureCooldownDuration(failures int) time.Duration {
	if failures <= 1 {
		return 30 * time.Second
	}
	sec := 30
	for i := 1; i < failures && sec < 300; i++ {
		sec *= 2
	}
	if sec > 300 {
		sec = 300
	}
	return time.Duration(sec) * time.Second
}

func candidateHostFamily(host string) string {
	trimmed := strings.Trim(strings.TrimSpace(host), "[]")
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return "dual"
	}
	if addr.Unmap().Is4() {
		return "ipv4"
	}
	return "ipv6"
}

func familyRank(mode FamilyMode, fam string) int {
	switch mode {
	case ModePreferIPv4:
		switch fam {
		case "ipv4":
			return 0
		case "dual":
			return 1
		default:
			return 2
		}
	case ModePreferIPv6:
		switch fam {
		case "ipv6":
			return 0
		case "dual":
			return 1
		default:
			return 2
		}
	default:
		return 0
	}
}

func isIgnoredInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, prefix := range []string{"docker", "veth", "br-", "virbr", "tun", "tap", "wg", "tailscale", "ifb"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// isIgnoredRouteInterface 允许 wg* / tun* 作为出站默认路由接口（如 Cloudflare WARP IPv6 隧道），
// 同时仍排除 lo、docker、veth、网桥等非出站虚拟接口。
func isIgnoredRouteInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, prefix := range []string{"docker", "veth", "br-", "virbr", "tap", "tailscale", "ifb"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func classifyAddressScope(addr netip.Addr) string {
	if addr.IsPrivate() {
		return "private_or_nat"
	}
	if addr.Is4() && (cgnatPrefix.Contains(addr) || zeroPrefix.Contains(addr) || futureV4.Contains(addr)) {
		return "private_or_nat"
	}
	return "global_public"
}

func parseNetAddr(a net.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *net.IPNet:
		if addr, ok := netip.AddrFromSlice(v.IP); ok {
			return addr.Unmap(), true
		}
	case *net.IPAddr:
		if addr, ok := netip.AddrFromSlice(v.IP); ok {
			return addr.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func hasHostAddress(addrs []AddressFact, family, target string) bool {
	for _, a := range addrs {
		if a.Family == family && a.Address == target {
			return true
		}
	}
	return false
}

func parseProcRouteV4(path string) (string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	first := true
	bestIface := ""
	bestMetric := int64(1<<62 - 1)
	found := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if first {
			first = false
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		iface, dest, flagsHex, metricStr, mask := fields[0], fields[1], fields[3], fields[6], fields[7]
		if dest != "00000000" || mask != "00000000" || isIgnoredRouteInterface(iface) {
			continue
		}
		flags, err := strconv.ParseUint(flagsHex, 16, 32)
		// 过滤非 RTF_UP 或 RTF_REJECT (0x0200) 路由
		if err != nil || flags&0x1 == 0 || flags&0x0200 != 0 {
			continue
		}
		metric, err := strconv.ParseInt(metricStr, 10, 64)
		if err != nil {
			metric = 0
		}
		if !found || metric < bestMetric {
			found = true
			bestMetric = metric
			bestIface = iface
		}
	}
	return bestIface, found, scanner.Err()
}

func parseProcRouteV6(path string) (string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	bestIface := ""
	bestMetric := uint64(1<<63 - 1)
	found := false
	zeroDest := strings.Repeat("0", 32)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		dest, prefixHex, metricHex, flagsHex, iface := fields[0], fields[1], fields[5], fields[8], fields[9]
		if dest != zeroDest || prefixHex != "00" || isIgnoredRouteInterface(iface) {
			continue
		}
		flags, err := strconv.ParseUint(flagsHex, 16, 32)
		// 过滤非 RTF_UP 或 RTF_REJECT (0x0200) 不可达默认路由
		if err != nil || flags&0x1 == 0 || flags&0x0200 != 0 {
			continue
		}
		metric, err := strconv.ParseUint(metricHex, 16, 64)
		if err != nil {
			metric = 0
		}
		if !found || metric < bestMetric {
			found = true
			bestMetric = metric
			bestIface = iface
		}
	}
	return bestIface, found, scanner.Err()
}
