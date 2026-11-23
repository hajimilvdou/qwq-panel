// SPDX-License-Identifier: AGPL-3.0-only

package trust

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// ReservedOfficialNamespaces 列出仅允许由官方内置公钥（SourceOfficial）签发的保留插件命名空间。
// 任何由管理员手动导入的第三方社区开发者公钥（SourceCustom）均严禁签发这些 ID，
// 防止通过伪造 core.xray / tls.certificates / security.basic 等官方 ID 窃取宿主硬编码特权。
var ReservedOfficialNamespaces = []string{
	"core.",
	"security.",
	"tls.",
	"domain.",
	"web.",
	"proxy.",
	"ai.",
	"server.",
	"containers.",
	"notify.",
	"host.",
	"qwq.",
}

// ReservedOfficialExactIDs 列出不带点号但同样仅限官方公钥签发的保留内置插件 ID。
var ReservedOfficialExactIDs = map[string]struct{}{
	"monitor": {},
	"host":    {},
	"qwq":     {},
}

// PrivilegedHostCapabilities 列出直接控制宿主机内核/防火墙/SSH/系统账户/特权端口的根级能力。
// 默认情况下，仅官方签名插件允许声明此类根能力，第三方自定义公钥插件严禁越权申请。
var PrivilegedHostCapabilities = map[string]struct{}{
	"firewall":       {},
	"sshd":           {},
	"account":        {},
	"sysctl":         {},
	"ban":            {},
	"traffic":        {},
	"service.reload": {},
	"certificates":   {},
	"dns":            {},
}

// IsReservedOfficialPluginID 判断 pluginID 是否属于官方保留命名空间。
func IsReservedOfficialPluginID(pluginID string) bool {
	id := strings.ToLower(strings.TrimSpace(pluginID))
	if _, exact := ReservedOfficialExactIDs[id]; exact {
		return true
	}
	for _, prefix := range ReservedOfficialNamespaces {
		if strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}

// VerifyManifestTrustTier 在 pkgfile.Read 完成加密签名校验后执行第二道供应链信任分层门禁（修复 R2-BUG-04）：
//  1. SourceOfficial 公钥：遵循其既有 .policy.json 约束，允许签发官方内置插件与根能力；
//  2. SourceCustom 公钥：
//     - 严禁签发任何官方保留命名空间插件（防止夺取 core.xray / tls.certificates 等硬编码特权）；
//     - 若导入公钥时指定了 AllowedPrefixes（如 "alice."），强制要求 m.ID 匹配其前缀；
//     - 默认拒绝申请宿主机根级高危能力与特权端口监听（network.listen ingress/custom-domain, network.proxy:direct），
//     将社区插件严格限制在受控沙箱、KV/DataDir、公开路由（/p/<id>/）及受控外联内。
func VerifyManifestTrustTier(m *manifest.Manifest, keySource string, allowedPrefixes []string, allowCustomPrivileged bool) error {
	if m == nil {
		return fmt.Errorf("trust: nil plugin manifest")
	}
	if keySource == SourceOfficial {
		return nil
	}

	if IsReservedOfficialPluginID(m.ID) {
		return fmt.Errorf(
			"trust: plugin id %q belongs to a reserved official namespace and cannot be signed by custom developer key %s",
			m.ID, m.Publisher.KeyID,
		)
	}

	if len(allowedPrefixes) > 0 {
		matched := false
		for _, rawPrefix := range allowedPrefixes {
			p := strings.ToLower(strings.TrimSpace(rawPrefix))
			if p == "" {
				continue
			}
			if !strings.HasSuffix(p, ".") && !strings.HasSuffix(p, "-") {
				if m.ID == p || strings.HasPrefix(m.ID, p+".") {
					matched = true
					break
				}
			} else if strings.HasPrefix(m.ID, p) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf(
				"trust: plugin id %q is outside allowed namespaces %v of custom developer key %s",
				m.ID, allowedPrefixes, m.Publisher.KeyID,
			)
		}
	}

	if allowCustomPrivileged {
		return nil
	}

	for _, capDecl := range m.Capabilities {
		if _, highRisk := PrivilegedHostCapabilities[capDecl.Name]; highRisk {
			return fmt.Errorf(
				"trust: third-party plugin %q cannot request privileged host capability %q (%s)",
				m.ID, capDecl.Name, capDecl.Scope,
			)
		}
		if capDecl.Name == "network.proxy" && capDecl.Scope == "direct" {
			return fmt.Errorf(
				"trust: third-party plugin %q cannot request host namespace raw proxy capability (network.proxy:direct)",
				m.ID,
			)
		}
		if capDecl.Name == "network.listen" && (capDecl.Scope == "ingress" || capDecl.Scope == "custom-domain") {
			return fmt.Errorf(
				"trust: third-party plugin %q cannot request CAP_NET_BIND_SERVICE low-port listener (%s:%s); use public_routes instead",
				m.ID, capDecl.Name, capDecl.Scope,
			)
		}
		if capDecl.Name == "plugin.config" && capDecl.Scope != "" && capDecl.Scope != "self" {
			return fmt.Errorf(
				"trust: third-party plugin %q cannot mutate another plugin's config (%s:%s)",
				m.ID, capDecl.Name, capDecl.Scope,
			)
		}
	}
	return nil
}

var (
	nat64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalPrefix     = netip.MustParsePrefix("64:ff9b:1::/48")
	blockedNonNAT64      = func() []netip.Prefix {
		cidrs := []string{
			"0.0.0.0/8",
			"10.0.0.0/8",
			"100.64.0.0/10",
			"127.0.0.0/8",
			"169.254.0.0/16",
			"172.16.0.0/12",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"192.168.0.0/16",
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"224.0.0.0/4",
			"240.0.0.0/4",
			"::/128",
			"::1/128",
			"fc00::/7",
			"fe80::/10",
			"ff00::/8",
			"2001:db8::/32",
			"2001::/32",
			"2002::/16",
			"100::/64",
		}
		out := make([]netip.Prefix, 0, len(cidrs))
		for _, c := range cidrs {
			out = append(out, netip.MustParsePrefix(c))
		}
		return out
	}()
)

// IsBlockedRemoteFetchAddr 修复 R2-BUG-09：在保持完整 SSRF 防护的前提下，
// 对 NAT64 标准前缀（64:ff9b::/96）深度提取末尾 32 位内嵌 IPv4 地址递归校验，
// 使得纯 IPv6（DNS64/NAT64）VPS 能够正常从 GitHub Release 拉取 .qwqpkg 与探针主题包，
// 同时依然 100% 拦截 64:ff9b::127.0.0.1 / 64:ff9b::169.254.169.254 / 64:ff9b::10.0.0.1 等内嵌私网绕过！
func IsBlockedRemoteFetchAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() ||
		addr.IsInterfaceLocalMulticast() {
		return true
	}
	if nat64WellKnownPrefix.Contains(addr) {
		b16 := addr.As16()
		embeddedV4 := netip.AddrFrom4([4]byte{b16[12], b16[13], b16[14], b16[15]})
		return IsBlockedRemoteFetchAddr(embeddedV4)
	}
	if nat64LocalPrefix.Contains(addr) {
		// RFC 8215 64:ff9b:1::/48 本地 NAT64 前缀同样提取最低 32 位 IPv4（跳过第 64..71 位 u 字节）
		b16 := addr.As16()
		embeddedV4 := netip.AddrFrom4([4]byte{b16[12], b16[13], b16[14], b16[15]})
		return IsBlockedRemoteFetchAddr(embeddedV4)
	}
	for _, pfx := range blockedNonNAT64 {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}
