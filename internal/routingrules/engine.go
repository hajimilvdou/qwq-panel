// SPDX-License-Identifier: AGPL-3.0-only

// Package routingrules 实现纯本地零 DNS 依赖的五级国内分流规则引擎、防污染 DNS 模板与两跳路径预演。
package routingrules

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
)

// ======================== 规则动作、分流模式与数据结构 ========================

// Action 描述路由匹配后的转发决策。
type Action string

const (
	ActionDirect Action = "DIRECT"
	ActionProxy  Action = "PROXY"
	ActionBlock  Action = "BLOCK"
)

// ProfileMode 描述客户端全局分流模式。
type ProfileMode string

const (
	ModeRuleCNSplit ProfileMode = "rule_cn_split"
	ModeGlobalProxy ProfileMode = "global_proxy"
	ModeDirectAll   ProfileMode = "direct_all"
)

// ValidProfileMode 校验分流模式是否为受支持的枚举值。
func ValidProfileMode(m ProfileMode) bool {
	switch m {
	case ModeRuleCNSplit, ModeGlobalProxy, ModeDirectAll:
		return true
	default:
		return false
	}
}

// CustomRule 表示用户自定义的高优先级覆盖规则。
type CustomRule struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action Action `json:"action"`
}

// CompiledBundle 是已校验并编译到内存的不可变规则包快照（零指针域名池 + O(log N) 合并 IP 区间）。
type CompiledBundle struct {
	Version      string
	SHA256       string
	CNDomains    CompactDomainSet
	NonCNDomains CompactDomainSet
	AdDomains    CompactDomainSet
	CNRangesV4   []AddrRange
	CNRangesV6   []AddrRange
}

// MatchDecision 描述单个目标经过五级分流引擎后的确定性决策与 DNS 通道。
type MatchDecision struct {
	Target      string `json:"target"`
	Host        string `json:"host"`
	Action      Action `json:"action"`
	MatchedRule string `json:"matched_rule"`
	DNSChannel  string `json:"dns_channel"`
}

// OutboundDomainOverride 描述 VPS 第二跳按目标域名后缀覆盖地址族的策略。
type OutboundDomainOverride struct {
	DomainSuffix string `json:"domain_suffix"`
	Mode         string `json:"mode"`
}

// TwoHopPreview 完整呈现第一跳（客户端->VPS）与第二跳（VPS->目标站）的诊断预演结果。
type TwoHopPreview struct {
	ClientDecision    MatchDecision `json:"client_decision"`
	FirstHopStrategy  string        `json:"first_hop_strategy,omitempty"`
	FirstHopEndpoints []string      `json:"first_hop_endpoints,omitempty"`
	SecondHopMode     string        `json:"second_hop_mode,omitempty"`
	SecondHopBindIP   string        `json:"second_hop_bind_ip,omitempty"`
}

const (
	maxBundleBytes = 16 << 20 // 16 MiB
	maxCustomRules = 4096
)

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// ValidateCustomRules 严格校验自定义规则的动作、类型、值及 CIDR 语法。
func ValidateCustomRules(rules []CustomRule) error {
	if len(rules) > maxCustomRules {
		return fmt.Errorf("custom rules exceed limit %d", maxCustomRules)
	}
	for idx, r := range rules {
		switch r.Action {
		case ActionDirect, ActionProxy, ActionBlock:
		default:
			return fmt.Errorf("custom rule #%d: unsupported action %q", idx, r.Action)
		}
		val := strings.TrimSpace(r.Value)
		if val == "" || len(val) > 253 || strings.ContainsAny(val, " \t\r\n") {
			return fmt.Errorf("custom rule #%d: invalid value", idx)
		}
		switch r.Kind {
		case "domain_exact", "domain_suffix", "domain_keyword":
		case "ip_cidr":
			if strings.Contains(val, "/") {
				if _, err := netip.ParsePrefix(val); err != nil {
					return fmt.Errorf("custom rule #%d: invalid cidr %q", idx, val)
				}
			} else {
				if _, err := netip.ParseAddr(strings.Trim(val, "[]")); err != nil {
					return fmt.Errorf("custom rule #%d: invalid ip %q", idx, val)
				}
			}
		default:
			return fmt.Errorf("custom rule #%d: unsupported kind %q", idx, r.Kind)
		}
	}
	return nil
}

// ======================== 规则引擎、内置 MIT 基线与原子热替换 ========================

// Engine 持有通过 atomic.Pointer 发布的不可变规则包，支持高并发无锁评估与原子热替换。
type Engine struct {
	bundle atomic.Pointer[CompiledBundle]
}

// NewEngine 创建路由引擎；initial 为 nil 时自动加载内置最小 MIT 基线规则包。
func NewEngine(initial *CompiledBundle) *Engine {
	e := &Engine{}
	if initial == nil {
		initial = builtinBaselineBundle()
	}
	e.bundle.Store(initial)
	return e
}

// BundleInfo 返回当前生效规则包的版本、SHA-256 摘要及总规则条目数。
func (e *Engine) BundleInfo() (version string, sha256Hex string, ruleCount int) {
	b := e.bundle.Load()
	if b == nil {
		return "", "", 0
	}
	count := b.CNDomains.Len() + b.NonCNDomains.Len() + b.AdDomains.Len() + len(b.CNRangesV4) + len(b.CNRangesV6)
	return b.Version, b.SHA256, count
}

// ParseBundleBytes 校验上限（16 MiB）、SHA-256 摘要并编译文本规则包为紧凑域名池与无重叠合并 IP 区间。
func ParseBundleBytes(version string, raw []byte, expectedSHA256 string) (*CompiledBundle, error) {
	if len(raw) == 0 {
		return nil, errors.New("routingrules: bundle content is empty")
	}
	if len(raw) > maxBundleBytes {
		return nil, fmt.Errorf("routingrules: bundle size %d exceeds %d bytes", len(raw), maxBundleBytes)
	}
	wantHex := normalizeSHA256(expectedSHA256)
	if wantHex == "" {
		return nil, errors.New("routingrules: expected sha256 is required")
	}
	sum := sha256.Sum256(raw)
	actualHex := hex.EncodeToString(sum[:])
	if actualHex != wantHex {
		return nil, errors.New("routingrules: bundle sha256 mismatch")
	}

	var (
		cnDomains    []string
		nonCNDomains []string
		adDomains    []string
		v4Prefixes   []netip.Prefix
		v6Prefixes   []netip.Prefix
	)

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, val, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("routingrules: invalid rule syntax at line %d", lineNo)
		}
		val = strings.TrimSpace(val)
		if val == "" {
			return nil, fmt.Errorf("routingrules: empty rule value at line %d", lineNo)
		}
		switch strings.TrimSpace(prefix) {
		case "cn_domain":
			cnDomains = append(cnDomains, normalizeDomain(val))
		case "proxy_domain":
			nonCNDomains = append(nonCNDomains, normalizeDomain(val))
		case "ad_domain":
			adDomains = append(adDomains, normalizeDomain(val))
		case "cn_cidr":
			pfx, err := netip.ParsePrefix(val)
			if err != nil {
				return nil, fmt.Errorf("routingrules: invalid cidr at line %d: %w", lineNo, err)
			}
			masked := pfx.Masked()
			if masked.Addr().Is4() {
				v4Prefixes = append(v4Prefixes, masked)
			} else {
				v6Prefixes = append(v6Prefixes, masked)
			}
		default:
			return nil, fmt.Errorf("routingrules: unknown rule prefix %q at line %d", prefix, lineNo)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	b := &CompiledBundle{
		Version:      strings.TrimSpace(version),
		SHA256:       "sha256:" + actualHex,
		CNDomains:    NewCompactDomainSet(cnDomains),
		NonCNDomains: NewCompactDomainSet(nonCNDomains),
		AdDomains:    NewCompactDomainSet(adDomains),
		CNRangesV4:   BuildMergedRanges(v4Prefixes),
		CNRangesV6:   BuildMergedRanges(v6Prefixes),
	}
	if b.Version == "" {
		b.Version = actualHex[:12]
	}
	total := b.CNDomains.Len() + b.NonCNDomains.Len() + b.AdDomains.Len() + len(b.CNRangesV4) + len(b.CNRangesV6)
	if total == 0 {
		return nil, errors.New("routingrules: bundle contains no valid rules")
	}
	return b, nil
}

// AtomicSwapBundle 严格校验规则包，写入 .tmp -> fsync -> 保留 .prev 备份 -> 原子重命名并切换内存快照。
func (e *Engine) AtomicSwapBundle(bundlePath, version string, raw []byte, expectedSHA256 string) (*CompiledBundle, error) {
	compiled, err := ParseBundleBytes(version, raw, expectedSHA256)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(bundlePath) == "" {
		return nil, errors.New("routingrules: bundle path is empty")
	}
	dir := filepath.Dir(bundlePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("routingrules: create bundle dir: %w", err)
	}

	tmpPath := bundlePath + ".tmp"
	if err := writeFileSynced(tmpPath, raw); err != nil {
		return nil, err
	}

	// 若旧规则文件存在，落盘保留 .prev 备份便于失败回滚。
	if existing, err := os.ReadFile(bundlePath); err == nil {
		prevPath := bundlePath + ".prev"
		if err := writeFileSynced(prevPath, existing); err != nil {
			_ = os.Remove(tmpPath)
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmpPath)
		return nil, err
	}

	if err := os.Rename(tmpPath, bundlePath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("routingrules: atomic rename bundle: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	e.bundle.Store(compiled)
	return compiled, nil
}

// ======================== 五级确定性路由评估（绝不触发公网 DNS） ========================

// Evaluate 按五级确定性优先级评估目标地址：
// 1. 内网/回环保护 -> 2. 自定义规则 -> 3. 广告拦截 -> 4. 域名优先（geolocation-!cn > cn）-> 5. IP CIDR + 默认兜底。
func (e *Engine) Evaluate(target string, mode ProfileMode, blockAds bool, custom []CustomRule) MatchDecision {
	host := extractTargetHost(target)
	decision := MatchDecision{
		Target: target,
		Host:   host,
	}
	if host == "" {
		decision.Action = ActionDirect
		decision.MatchedRule = "invalid_empty_target"
		decision.DNSChannel = "local"
		return decision
	}

	addr, isIP := parseHostIP(host)

	// 第 1 级：内网、回环、链路本地及本地域名始终直连保护。
	if isPrivateOrLocal(host, addr, isIP) {
		decision.Action = ActionDirect
		decision.MatchedRule = "private_or_loopback"
		decision.DNSChannel = "local"
		return decision
	}

	// 第 2 级：用户自定义规则（顺序优先）。
	for _, r := range custom {
		if matchCustomRule(r, host, addr, isIP) {
			decision.Action = r.Action
			decision.MatchedRule = "custom:" + r.Kind + ":" + strings.TrimSpace(r.Value)
			decision.DNSChannel = dnsChannelForAction(r.Action)
			return decision
		}
	}

	b := e.bundle.Load()

	// 第 3 级：广告域名拦截（仅域名，零 DNS 解析）。
	if blockAds && !isIP && b != nil && b.AdDomains.MatchDomainOrParent(host) {
		decision.Action = ActionBlock
		decision.MatchedRule = "geosite:category-ads"
		decision.DNSChannel = "blocked"
		return decision
	}

	// 全局代理 / 全局直连模式在完成内网保护、自定义规则与去广告后生效。
	if mode == ModeGlobalProxy {
		decision.Action = ActionProxy
		decision.MatchedRule = "mode:global_proxy"
		decision.DNSChannel = "remote_doh"
		return decision
	}
	if mode == ModeDirectAll {
		decision.Action = ActionDirect
		decision.MatchedRule = "mode:direct_all"
		decision.DNSChannel = "domestic_doh"
		return decision
	}

	// 第 4 级：rule_cn_split 域名优先匹配（geolocation-!cn 优先级高于 cn，绝不触发公网 DNS）。
	if !isIP {
		if b != nil && b.NonCNDomains.MatchDomainOrParent(host) {
			decision.Action = ActionProxy
			decision.MatchedRule = "geosite:geolocation-!cn"
			decision.DNSChannel = "remote_doh"
			return decision
		}
		if b != nil && b.CNDomains.MatchDomainOrParent(host) {
			decision.Action = ActionDirect
			decision.MatchedRule = "geosite:cn"
			decision.DNSChannel = "domestic_doh"
			return decision
		}
		decision.Action = ActionProxy
		decision.MatchedRule = "default:proxy"
		decision.DNSChannel = "remote_doh"
		return decision
	}

	// 第 5 级：IP 字面量 O(log N) 匹配无重叠合并 CN 区间表 + 默认代理兜底。
	if b != nil {
		if addr.Is4() && MatchMergedRanges(addr, b.CNRangesV4) {
			decision.Action = ActionDirect
			decision.MatchedRule = "geoip:cn"
			decision.DNSChannel = "domestic_doh"
			return decision
		}
		if addr.Is6() && MatchMergedRanges(addr, b.CNRangesV6) {
			decision.Action = ActionDirect
			decision.MatchedRule = "geoip:cn"
			decision.DNSChannel = "domestic_doh"
			return decision
		}
	}

	decision.Action = ActionProxy
	decision.MatchedRule = "default:proxy"
	decision.DNSChannel = "remote_doh"
	return decision
}

// PreviewTwoHop 结合客户端分流决策、第一跳排序与第二跳域名地址族覆盖，输出完整两跳路径预演。
func (e *Engine) PreviewTwoHop(
	target string,
	mode ProfileMode,
	blockAds bool,
	custom []CustomRule,
	firstHopMode string,
	orderedEndpoints []string,
	secondHopDefaultMode, bindV4, bindV6 string,
	overrides []OutboundDomainOverride,
) TwoHopPreview {
	decision := e.Evaluate(target, mode, blockAds, custom)
	preview := TwoHopPreview{ClientDecision: decision}
	if decision.Action != ActionProxy {
		return preview
	}

	preview.FirstHopStrategy = firstHopMode
	if len(orderedEndpoints) > 0 {
		preview.FirstHopEndpoints = append([]string(nil), orderedEndpoints...)
	}

	secondMode := secondHopDefaultMode
	bestLen := -1
	for _, ov := range overrides {
		suffix := normalizeDomain(strings.TrimPrefix(strings.TrimSpace(ov.DomainSuffix), "."))
		if suffix == "" || strings.TrimSpace(ov.Mode) == "" {
			continue
		}
		if decision.Host == suffix || strings.HasSuffix(decision.Host, "."+suffix) {
			if len(suffix) > bestLen {
				bestLen = len(suffix)
				secondMode = strings.TrimSpace(ov.Mode)
			}
		}
	}
	preview.SecondHopMode = secondMode
	preview.SecondHopBindIP = selectBindIPForMode(secondMode, bindV4, bindV6)
	return preview
}

// BuildAntiPoisonDNSConfig 生成防 DNS 污染与 VPS 自身域名直连防死锁的标准 DNS 模板。
func BuildAntiPoisonDNSConfig(vpsHost string, directDomains []string) map[string]any {
	bootstrap := []string{"223.5.5.5", "119.29.29.29"}
	domesticDoH := []string{"https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"}
	remoteDoH := []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}

	vpsBypass := make([]string, 0, 1)
	cleanVPS := normalizeDomain(extractTargetHost(vpsHost))
	if cleanVPS != "" {
		if _, isIP := parseHostIP(cleanVPS); !isIP {
			vpsBypass = append(vpsBypass, cleanVPS)
		}
	}

	directSet := make(map[string]struct{}, len(directDomains)+len(vpsBypass))
	for _, d := range directDomains {
		if norm := normalizeDomain(d); norm != "" {
			directSet[norm] = struct{}{}
		}
	}
	for _, d := range vpsBypass {
		directSet[d] = struct{}{}
	}
	mergedDirect := make([]string, 0, len(directSet))
	for d := range directSet {
		mergedDirect = append(mergedDirect, d)
	}
	slices.Sort(mergedDirect)

	return map[string]any{
		"strategy":           "anti_poison_split",
		"bootstrap_dns":      bootstrap,
		"domestic_doh":       domesticDoH,
		"remote_doh":         remoteDoH,
		"vps_bypass_domains": vpsBypass,
		"direct_domains":     mergedDirect,
		"rules": []map[string]any{
			{"match": "vps_bypass_domains", "domains": vpsBypass, "server": "bootstrap_dns"},
			{"match": "direct_domains", "domains": mergedDirect, "server": "domestic_doh"},
			{"match": "geosite:cn", "server": "domestic_doh"},
			{"match": "geosite:geolocation-!cn", "server": "remote_doh"},
			{"match": "default", "server": "remote_doh"},
		},
	}
}

// ======================== 内置基线与内部辅助函数 ========================

const builtinBaselineText = `# Builtin MIT minimal CN/Non-CN/Ad baseline
cn_domain:cn
cn_domain:baidu.com
cn_domain:qq.com
cn_domain:weixin.qq.com
cn_domain:wechat.com
cn_domain:taobao.com
cn_domain:tmall.com
cn_domain:alipay.com
cn_domain:aliyun.com
cn_domain:bilibili.com
cn_domain:jd.com
cn_domain:zhihu.com
cn_domain:weibo.com
cn_domain:163.com
cn_domain:douyin.com
cn_domain:tencent.com
cn_domain:mi.com
cn_domain:huawei.com
proxy_domain:google.com
proxy_domain:googleapis.com
proxy_domain:gstatic.com
proxy_domain:youtube.com
proxy_domain:github.com
proxy_domain:githubusercontent.com
proxy_domain:openai.com
proxy_domain:chatgpt.com
proxy_domain:anthropic.com
proxy_domain:claude.ai
proxy_domain:cloudflare.com
proxy_domain:telegram.org
proxy_domain:twitter.com
proxy_domain:x.com
proxy_domain:netflix.com
proxy_domain:wikipedia.org
ad_domain:doubleclick.net
ad_domain:googlesyndication.com
ad_domain:adservice.google.com
ad_domain:pos.baidu.com
ad_domain:cpro.baidu.com
cn_cidr:1.0.1.0/24
cn_cidr:1.2.4.0/24
cn_cidr:36.96.0.0/11
cn_cidr:110.242.68.0/24
cn_cidr:114.114.114.0/24
cn_cidr:119.29.29.0/24
cn_cidr:223.5.5.0/24
cn_cidr:2400:3200::/32
cn_cidr:2402:4e00::/32
`

func builtinBaselineBundle() *CompiledBundle {
	raw := []byte(builtinBaselineText)
	sum := sha256.Sum256(raw)
	b, err := ParseBundleBytes("builtin-mit-v1", raw, hex.EncodeToString(sum[:]))
	if err != nil {
		panic("routingrules: invalid builtin baseline: " + err.Error())
	}
	return b
}

func normalizeSHA256(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) != 64 {
		return ""
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ""
		}
	}
	return s
}

func normalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Trim(s, "[]")
	return strings.TrimSuffix(s, ".")
}

func extractTargetHost(target string) string {
	s := strings.TrimSpace(target)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return normalizeDomain(u.Hostname())
		}
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		return normalizeDomain(host)
	}
	if addr, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return addr.Unmap().String()
	}
	return normalizeDomain(s)
}

func parseHostIP(host string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func isPrivateOrLocal(host string, addr netip.Addr, isIP bool) bool {
	if isIP {
		return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() || addr.IsUnspecified() || (addr.Is4() && cgnatPrefix.Contains(addr))
	}
	if host == "localhost" {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".lan", ".internal"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func matchCustomRule(r CustomRule, host string, addr netip.Addr, isIP bool) bool {
	val := strings.TrimSpace(r.Value)
	switch r.Kind {
	case "domain_exact":
		return !isIP && host == normalizeDomain(val)
	case "domain_suffix":
		suffix := normalizeDomain(strings.TrimPrefix(val, "."))
		return !isIP && (host == suffix || strings.HasSuffix(host, "."+suffix))
	case "domain_keyword":
		return !isIP && strings.Contains(host, strings.ToLower(val))
	case "ip_cidr":
		if !isIP {
			return false
		}
		if strings.Contains(val, "/") {
			pfx, err := netip.ParsePrefix(val)
			return err == nil && pfx.Contains(addr)
		}
		targetAddr, err := netip.ParseAddr(strings.Trim(val, "[]"))
		return err == nil && targetAddr.Unmap() == addr
	default:
		return false
	}
}

func dnsChannelForAction(act Action) string {
	switch act {
	case ActionDirect:
		return "domestic_doh"
	case ActionBlock:
		return "blocked"
	default:
		return "remote_doh"
	}
}

func selectBindIPForMode(mode, bindV4, bindV6 string) string {
	v4 := strings.TrimSpace(bindV4)
	v6 := strings.TrimSpace(bindV6)
	switch mode {
	case "ipv4_only":
		return v4
	case "ipv6_only":
		return v6
	case "prefer_ipv6":
		if v6 != "" {
			return v6
		}
		return v4
	case "prefer_ipv4":
		if v4 != "" {
			return v4
		}
		return v6
	default:
		if v4 != "" {
			return v4
		}
		return v6
	}
}

func writeFileSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
