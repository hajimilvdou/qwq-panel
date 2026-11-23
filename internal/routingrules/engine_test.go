// SPDX-License-Identifier: AGPL-3.0-only

package routingrules

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ======================== 五级分流优先级、零 DNS 解析与自定义规则覆盖验证 ========================

func TestEngineFiveStagePriorityAndZeroDNS(t *testing.T) {
	eng := NewEngine(nil)
	ver, sum, count := eng.BundleInfo()
	if ver != "builtin-mit-v1" || !strings.HasPrefix(sum, "sha256:") || count < 30 {
		t.Fatalf("内置基线元数据异常: ver=%q sum=%q count=%d", ver, sum, count)
	}

	// 1. 内网/回环保护最高优先级（即便处于 global_proxy 也不代理）。
	for _, target := range []string{"127.0.0.1:8080", "192.168.1.1", "10.0.0.8", "100.64.1.2", "[fd00::1]:443", "localhost:3000", "nas.local"} {
		d := eng.Evaluate(target, ModeGlobalProxy, true, nil)
		if d.Action != ActionDirect || d.MatchedRule != "private_or_loopback" {
			t.Fatalf("内网目标 %q 应强制 DIRECT，实际: %+v", target, d)
		}
	}

	// 2. 自定义规则覆盖内置广告与分流规则。
	custom := []CustomRule{
		{Kind: "domain_exact", Value: "doubleclick.net", Action: ActionDirect},
		{Kind: "domain_suffix", Value: "corp.example", Action: ActionProxy},
		{Kind: "domain_keyword", Value: "secret-api", Action: ActionBlock},
		{Kind: "ip_cidr", Value: "223.5.5.0/24", Action: ActionProxy},
	}
	if err := ValidateCustomRules(custom); err != nil {
		t.Fatalf("合法自定义规则校验失败: %v", err)
	}
	if d := eng.Evaluate("doubleclick.net", ModeRuleCNSplit, true, custom); d.Action != ActionDirect {
		t.Fatalf("自定义规则应优先于广告拦截: %+v", d)
	}
	if d := eng.Evaluate("git.corp.example", ModeDirectAll, true, custom); d.Action != ActionProxy {
		t.Fatalf("自定义规则应优先于 direct_all: %+v", d)
	}
	if d := eng.Evaluate("my-secret-api.cn", ModeRuleCNSplit, true, custom); d.Action != ActionBlock {
		t.Fatalf("自定义 keyword 规则应命中 BLOCK: %+v", d)
	}
	if d := eng.Evaluate("223.5.5.5", ModeRuleCNSplit, true, custom); d.Action != ActionProxy {
		t.Fatalf("自定义 CIDR 规则应覆盖 geoip:cn: %+v", d)
	}

	// 3. 广告拦截。
	if d := eng.Evaluate("ads.doubleclick.net", ModeRuleCNSplit, true, nil); d.Action != ActionBlock || d.MatchedRule != "geosite:category-ads" {
		t.Fatalf("开启去广告时应拦截 doubleclick.net: %+v", d)
	}
	if d := eng.Evaluate("ads.doubleclick.net", ModeRuleCNSplit, false, nil); d.Action == ActionBlock {
		t.Fatalf("关闭去广告时不应拦截: %+v", d)
	}

	// 4. 域名优先（geolocation-!cn > cn），且使用不存在的虚构域名验证零公网 DNS 依赖。
	if d := eng.Evaluate("api.github.com:443", ModeRuleCNSplit, true, nil); d.Action != ActionProxy || d.MatchedRule != "geosite:geolocation-!cn" || d.DNSChannel != "remote_doh" {
		t.Fatalf("非国内域名应走代理与远端 DoH: %+v", d)
	}
	if d := eng.Evaluate("https://www.bilibili.com/video/1", ModeRuleCNSplit, true, nil); d.Action != ActionDirect || d.MatchedRule != "geosite:cn" || d.DNSChannel != "domestic_doh" {
		t.Fatalf("国内域名应直连并走国内 DoH: %+v", d)
	}
	if d := eng.Evaluate("nonexistent.invalid.tld.example", ModeRuleCNSplit, true, nil); d.Action != ActionProxy || d.MatchedRule != "default:proxy" {
		t.Fatalf("未命中未知域名应在零 DNS 解析下直接兜底 PROXY: %+v", d)
	}

	// 5. IP CIDR 匹配（IPv4 与 IPv6 CN 段直连，海外 IP 默认代理）。
	if d := eng.Evaluate("114.114.114.114", ModeRuleCNSplit, true, nil); d.Action != ActionDirect || d.MatchedRule != "geoip:cn" {
		t.Fatalf("国内 IPv4 应命中 geoip:cn: %+v", d)
	}
	if d := eng.Evaluate("[2400:3200::1]:443", ModeRuleCNSplit, true, nil); d.Action != ActionDirect || d.MatchedRule != "geoip:cn" {
		t.Fatalf("国内 IPv6 应命中 geoip:cn: %+v", d)
	}
	if d := eng.Evaluate("8.8.8.8", ModeRuleCNSplit, true, nil); d.Action != ActionProxy || d.MatchedRule != "default:proxy" {
		t.Fatalf("海外 IP 应默认 PROXY: %+v", d)
	}
}

// ======================== 规则包 SHA-256 校验、原子替换与 .prev 备份验证 ========================

func TestParseAndAtomicSwapBundle(t *testing.T) {
	v1Raw := []byte("cn_domain:example.cn\nproxy_domain:override.cn\nad_domain:ads.test\ncn_cidr:114.114.114.0/24\n")
	v1Hash := sha256.Sum256(v1Raw)
	v1Hex := hex.EncodeToString(v1Hash[:])

	if _, err := ParseBundleBytes("v1", v1Raw, strings.Repeat("0", 64)); err == nil {
		t.Fatal("SHA-256 不匹配必须拒绝")
	}
	if _, err := ParseBundleBytes("v1", v1Raw, ""); err == nil {
		t.Fatal("空 expectedSHA256 必须拒绝")
	}

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "rules.bundle")
	eng := NewEngine(nil)

	if _, err := eng.AtomicSwapBundle(bundlePath, "v1", v1Raw, "sha256:"+v1Hex); err != nil {
		t.Fatalf("首次 AtomicSwapBundle 失败: %v", err)
	}
	// 验证 geolocation-!cn（proxy_domain:override.cn）优先于 cn_domain（若同时命中）。
	if d := eng.Evaluate("override.cn", ModeRuleCNSplit, true, nil); d.Action != ActionProxy || d.MatchedRule != "geosite:geolocation-!cn" {
		t.Fatalf("proxy_domain 优先级应高于 cn_domain: %+v", d)
	}

	v2Raw := []byte("cn_domain:new-cn.org\nproxy_domain:openai.com\ncn_cidr:223.5.5.0/24\n")
	v2Hash := sha256.Sum256(v2Raw)
	v2Hex := hex.EncodeToString(v2Hash[:])

	if _, err := eng.AtomicSwapBundle(bundlePath, "v2", v2Raw, v2Hex); err != nil {
		t.Fatalf("第二次 AtomicSwapBundle 失败: %v", err)
	}
	prevBytes, err := os.ReadFile(bundlePath + ".prev")
	if err != nil || string(prevBytes) != string(v1Raw) {
		t.Fatalf(".prev 备份文件未保留旧规则包: err=%v got=%q", err, string(prevBytes))
	}
	ver, _, _ := eng.BundleInfo()
	if ver != "v2" {
		t.Fatalf("内存规则版本未切换至 v2: %q", ver)
	}
	if d := eng.Evaluate("sub.new-cn.org", ModeRuleCNSplit, true, nil); d.Action != ActionDirect {
		t.Fatalf("切换后新国内规则应生效: %+v", d)
	}
}

// ======================== 两跳路径预演、防污染 DNS 模板与并发读写安全 ========================

func TestPreviewTwoHopAndAntiPoisonDNS(t *testing.T) {
	eng := NewEngine(nil)
	overrides := []OutboundDomainOverride{
		{DomainSuffix: "openai.com", Mode: "ipv4_only"},
		{DomainSuffix: "google.com", Mode: "prefer_ipv6"},
	}

	// 代理目标命中第二跳域名覆盖（openai.com -> ipv4_only + bindV4）。
	prevProxy := eng.PreviewTwoHop(
		"api.openai.com:443",
		ModeRuleCNSplit,
		true,
		nil,
		"prefer_ipv6",
		[]string{"[2001:db8::1]:443", "203.0.113.1:443"},
		"prefer_ipv6",
		"203.0.113.10",
		"2001:db8::10",
		overrides,
	)
	if prevProxy.ClientDecision.Action != ActionProxy ||
		prevProxy.FirstHopStrategy != "prefer_ipv6" ||
		len(prevProxy.FirstHopEndpoints) != 2 ||
		prevProxy.SecondHopMode != "ipv4_only" ||
		prevProxy.SecondHopBindIP != "203.0.113.10" {
		t.Fatalf("两跳预演结果不符: %+v", prevProxy)
	}

	// 直连目标不应输出代理第一/第二跳信息。
	prevDirect := eng.PreviewTwoHop(
		"www.baidu.com",
		ModeRuleCNSplit,
		true,
		nil,
		"prefer_ipv4",
		[]string{"203.0.113.1:443"},
		"prefer_ipv4",
		"203.0.113.10",
		"2001:db8::10",
		overrides,
	)
	if prevDirect.ClientDecision.Action != ActionDirect || prevDirect.FirstHopStrategy != "" || prevDirect.SecondHopMode != "" {
		t.Fatalf("直连目标不应填充代理两跳信息: %+v", prevDirect)
	}

	// 防污染 DNS 模板必须把 VPS 自身域名纳入直连旁路防死锁。
	dnsCfg := BuildAntiPoisonDNSConfig("vps.example.net:443", []string{"corp.cn"})
	vpsBypass, _ := dnsCfg["vps_bypass_domains"].([]string)
	if len(vpsBypass) != 1 || vpsBypass[0] != "vps.example.net" {
		t.Fatalf("防污染 DNS 模板未包含 VPS 自身域名直连旁路: %+v", dnsCfg)
	}
}

func TestEngineConcurrentEvaluateAndSwap(t *testing.T) {
	eng := NewEngine(nil)
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "concurrent.bundle")
	raw := []byte("cn_domain:concurrent.cn\nproxy_domain:google.com\ncn_cidr:114.114.114.0/24\n")
	sum := sha256.Sum256(raw)
	sumHex := hex.EncodeToString(sum[:])

	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = eng.Evaluate("api.google.com", ModeRuleCNSplit, true, nil)
				_ = eng.Evaluate("114.114.114.114", ModeRuleCNSplit, true, nil)
				_, _, _ = eng.BundleInfo()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if _, err := eng.AtomicSwapBundle(bundlePath, "v-race", raw, sumHex); err != nil {
				errCh <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发原子替换失败: %v", err)
	}
}

func TestBuildMergedRangesIPv4MappedIPv6Prefix(t *testing.T) {
	p := netip.MustParsePrefix("::ffff:192.0.2.0/120")
	ranges := BuildMergedRanges([]netip.Prefix{p})
	if len(ranges) != 1 {
		t.Fatalf("ranges len = %d, want 1", len(ranges))
	}
	wantStart := netip.MustParseAddr("192.0.2.0")
	wantEnd := netip.MustParseAddr("192.0.2.255")
	if ranges[0].Start != wantStart || ranges[0].End != wantEnd {
		t.Fatalf("range = [%s, %s], want [%s, %s]", ranges[0].Start, ranges[0].End, wantStart, wantEnd)
	}
	if !MatchMergedRanges(netip.MustParseAddr("192.0.2.123"), ranges) {
		t.Fatal("expected 192.0.2.123 to match ::ffff:192.0.2.0/120")
	}
	if !MatchMergedRanges(netip.MustParseAddr("::ffff:192.0.2.255"), ranges) {
		t.Fatal("expected ::ffff:192.0.2.255 to match ::ffff:192.0.2.0/120")
	}
	if MatchMergedRanges(netip.MustParseAddr("192.0.3.1"), ranges) {
		t.Fatal("unexpected match for 192.0.3.1")
	}
}
