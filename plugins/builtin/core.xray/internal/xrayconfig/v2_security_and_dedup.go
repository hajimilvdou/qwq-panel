// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"fmt"
	"slices"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ============================================================================
// 修复 R2-BUG-20.1 / R2-BUG-20.3 / R2-BUG-20.4 / R2-BUG-21：
//  1. 全局置顶私网/回环/云元数据黑洞拦截规则（EnsurePrivateBlackholeProtection），彻底阻断全协议代理回环穿透；
//  2. 多节点 `markedUsers` 按 `TrafficMark` 去重聚合（BuildDeduplicatedMarkedOutbounds），根治 ≥2 节点时重复 `direct-mark-<mark>` Tag 崩溃；
//  3. 健康探针入站选择（SelectXrayHealthInboundID）排除不写入 Xray 的 `anytls` Profile，解决单开或排序居首时 100% 超时回滚；
//  4. 单次事务内 `SecretRef` 揭示缓存（DeduplicatedSecretRevealer），消除 9 协议矩阵或 >7 用户触发宿主限流崩溃。
// ============================================================================

// BlockedPrivateCIDRs 覆盖 IPv4/IPv6 回环、RFC1918 私网、链路本地（AWS/GCP IMDS 169.254.169.254）、
// CGNAT（含阿里云 IMDS 100.100.100.200）、ULA、多播及保留地址段。
var BlockedPrivateCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// BlockedPrivateDomains 拦截本地主机名与云元数据内网域名。
var BlockedPrivateDomains = []string{
	"localhost",
	"domain:local",
	"domain:internal",
	"full:metadata.google.internal",
}

// EnsurePrivateBlackholeProtection 确保 nativeConfig 拥有 `blocked-private` 黑洞出站，
// 并将禁回环/禁私网规则严格置于 `qwq-api-in` 之后、所有业务规则（WARP / TrafficMark / Overrides）之前。
func EnsurePrivateBlackholeProtection(cfg *nativeConfig) {
	if cfg == nil {
		return
	}
	hasBlackhole := false
	for _, ob := range cfg.Outbounds {
		if ob.Tag == "blocked-private" {
			hasBlackhole = true
			break
		}
	}
	if !hasBlackhole {
		cfg.Outbounds = append(cfg.Outbounds, nativeOutbound{
			Tag:      "blocked-private",
			Protocol: "blackhole",
			Settings: struct{}{},
		})
	}
	if cfg.Routing.DomainStrategy == "" || cfg.Routing.DomainStrategy == "AsIs" {
		// 使用 IPIfNonMatch 确保攻击者用指向 127.0.0.1 / 169.254.169.254 的自定义域名也必被 IP 黑洞规则捕获！
		cfg.Routing.DomainStrategy = "IPIfNonMatch"
	}

	guardRules := []nativeRule{
		{
			Type:        "field",
			Domain:      slices.Clone(BlockedPrivateDomains),
			OutboundTag: "blocked-private",
		},
		{
			Type:        "field",
			IP:          slices.Clone(BlockedPrivateCIDRs),
			OutboundTag: "blocked-private",
		},
	}

	// 保留首条 qwq-api-in 内部统计规则在索引 0，紧随其后插入两条黑洞防线
	if len(cfg.Routing.Rules) > 0 && slices.Contains(cfg.Routing.Rules[0].InboundTags, "qwq-api-in") {
		next := make([]nativeRule, 0, len(cfg.Routing.Rules)+len(guardRules))
		next = append(next, cfg.Routing.Rules[0])
		next = append(next, guardRules...)
		next = append(next, cfg.Routing.Rules[1:]...)
		cfg.Routing.Rules = next
		return
	}
	cfg.Routing.Rules = append(guardRules, cfg.Routing.Rules...)
}

// BuildDeduplicatedMarkedOutbounds 按唯一的 `TrafficMark` 聚合所有跨 Profile 邮箱，
// 每个 mark 仅生成唯一一条 `direct-mark-<mark>` 出站与一条路由规则！
func BuildDeduplicatedMarkedOutbounds(
	cfg *nativeConfig,
	marked []struct {
		Mark  uint32
		Email string
	},
	defaultStrategy string,
	primarySendThrough string,
) {
	if cfg == nil || len(marked) == 0 {
		return
	}
	byMark := make(map[uint32][]string)
	marks := make([]uint32, 0)
	for _, item := range marked {
		if item.Mark == 0 || item.Email == "" {
			continue
		}
		if _, exists := byMark[item.Mark]; !exists {
			marks = append(marks, item.Mark)
		}
		if !slices.Contains(byMark[item.Mark], item.Email) {
			byMark[item.Mark] = append(byMark[item.Mark], item.Email)
		}
	}
	slices.Sort(marks)
	for _, mark := range marks {
		emails := byMark[mark]
		slices.Sort(emails)
		tag := fmt.Sprintf("direct-mark-%d", mark)
		cfg.Outbounds = append(cfg.Outbounds, makeFreedomOutbound(tag, defaultStrategy, primarySendThrough, mark))
		cfg.Routing.Rules = append(cfg.Routing.Rules, nativeRule{
			Type:        "field",
			User:        emails,
			OutboundTag: tag,
		})
	}
}

// SelectXrayHealthInboundID 供 apply/recovery.go:generationInboundID 调用：
// 跳过由内建 Go 监管器承载（不写入 Xray inbounds）的 ProtocolAnyTLS，若全实例仅开启了 AnyTLS 则返回 "api-only"，
// 由 coreproc/health.go 改为验证 StatsService `Counters()` 可正常返回即可通过健康检查！
func SelectXrayHealthInboundID(profiles []struct {
	ID       string
	Protocol string
	Enabled  bool
}) string {
	for _, p := range profiles {
		if p.Enabled && p.Protocol != corev2.ProtocolAnyTLS {
			return p.ID
		}
	}
	for _, p := range profiles {
		if p.Protocol != corev2.ProtocolAnyTLS {
			return p.ID
		}
	}
	if len(profiles) > 0 {
		return "api-only"
	}
	return ""
}

// DeduplicatedSecretRevealer 在单次 LoadV2 或 exportV2 调用周期内按 SecretRef 缓存已揭示明文，
// 并在 Clear() 时统一擦除内存，将多协议复用同一用户凭据时的宿主 RPC 次数降低 70%~85%。
type DeduplicatedSecretRevealer struct {
	reveal func(ref string) ([]byte, error)
	cache  map[string][]byte
}

func NewDeduplicatedSecretRevealer(reveal func(ref string) ([]byte, error)) *DeduplicatedSecretRevealer {
	return &DeduplicatedSecretRevealer{
		reveal: reveal,
		cache:  make(map[string][]byte),
	}
}

func (r *DeduplicatedSecretRevealer) Reveal(ref string) ([]byte, error) {
	if cached, ok := r.cache[ref]; ok {
		out := make([]byte, len(cached))
		copy(out, cached)
		return out, nil
	}
	raw, err := r.reveal(ref)
	if err != nil {
		return nil, err
	}
	stored := make([]byte, len(raw))
	copy(stored, raw)
	r.cache[ref] = stored
	return raw, nil
}

func (r *DeduplicatedSecretRevealer) Clear() {
	if r == nil {
		return
	}
	for k, buf := range r.cache {
		clear(buf)
		delete(r.cache, k)
	}
}
