// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ============================================================================
// 修复 R2-BUG-05 / R2-BUG-06 / R2-BUG-07 / R2-BUG-12 / R2-BUG-22：
// proxy.advanced 统一节点工作台、多租户订阅同步、$secret 双形态解包与 WARP 出站协同核心组件
// ============================================================================

var (
	probeNAT64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	probeCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")
)

// SecretOrPlainField 兼容宿主 x-secret 抽取后的 `{"$secret":"sec_..."}` 引用对象与明文字符串。
type SecretOrPlainField struct {
	Plain     string
	SecretRef string
	Keep      bool
}

func (f *SecretOrPlainField) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*f = SecretOrPlainField{}
		return nil
	}
	if strings.HasPrefix(trimmed, "\"") {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = SecretOrPlainField{Plain: s}
		return nil
	}
	var obj struct {
		Secret        string `json:"$secret"`
		KeepSecret    bool   `json:"$keep_secret"`
		SecretPresent bool   `json:"$secret_present"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*f = SecretOrPlainField{
		SecretRef: strings.TrimSpace(obj.Secret),
		Keep:      obj.KeepSecret || obj.SecretPresent,
	}
	return nil
}

func resolveSecretOrPlain(ctx context.Context, host *pluginsdk.Host, field SecretOrPlainField, purpose string) (string, error) {
	if field.SecretRef != "" {
		if host == nil {
			return "", pluginsdk.Errorf("HOST_UNAVAILABLE", "宿主凭据服务不可用")
		}
		raw, err := host.RevealSecret(ctx, field.SecretRef, purpose)
		if err != nil {
			return "", err
		}
		defer clear(raw)
		var decoded string
		if json.Unmarshal(raw, &decoded) == nil {
			return decoded, nil
		}
		return string(raw), nil
	}
	return field.Plain, nil
}

// IsPublicProbeTargetIP 严格判定目标 IP 是否为公网可达单播地址。
func IsPublicProbeTargetIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		b := ip.As4()
		return b[0] != 0 && b[0] < 240 && !probeCGNATPrefix.Contains(ip)
	}
	if probeNAT64Prefix.Contains(ip) {
		b16 := ip.As16()
		return IsPublicProbeTargetIP(netip.AddrFrom4([4]byte{b16[12], b16[13], b16[14], b16[15]}))
	}
	return ip.IsGlobalUnicast()
}

// ValidatePublicSNIDomain 校验 `nodes.probe_sni` 的候选域名必须为纯公网域名（严禁携带端口或 IP 字面量）。
func ValidatePublicSNIDomain(raw string) (string, bool) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return "", false
	}
	if strings.ContainsAny(d, " \t\r\n/\\@?#:[]") {
		return "", false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", false
	}
	if d == "localhost" || strings.HasSuffix(d, ".localhost") || strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".internal") {
		return "", false
	}
	return d, true
}

// NewPublicProbeDialer 构造在 connect 阶段按解析后真实 IP 拦截回环/内网/IMDS 的安全探测拨号器。
func NewPublicProbeDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, portStr, err := net.SplitHostPort(address)
			if err != nil {
				return pluginsdk.Errorf("PERMISSION_DENIED", "探测目标地址非法")
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				return pluginsdk.Errorf("PERMISSION_DENIED", "探测目标端口非法")
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !IsPublicProbeTargetIP(ip) {
				return pluginsdk.Errorf("PERMISSION_DENIED", "禁止对本机回环、内网或云元数据地址发起连通性探测")
			}
			return nil
		},
	}
}

// BuildUnifiedProfileUsers 合并「节点工作台专属凭据」与「订阅中心活跃多用户凭据」，并按凭据值自动去重（修复 R2-BUG-05）。
func BuildUnifiedProfileUsers(n *proxyNodeRecord, protocol string, activeUsers []userRecord, existing map[string]map[string]bool) []any {
	out := make([]any, 0, len(activeUsers)+1)
	seenSecret := make(map[string]bool, len(activeUsers)+1)

	// 1. 若该 Profile 对应托管节点，优先注入节点自身独立凭据（支持 $keep_secret 槽位保持）
	if n != nil && n.Source == "managed" {
		nodeUserID := "u-" + n.ID
		if len(nodeUserID) > 32 {
			nodeUserID = nodeUserID[:32]
		}
		slots := existing[nodeUserID]
		entry := map[string]any{"id": nodeUserID}
		valid := false

		switch protocol {
		case corev2.ProtocolVLESS, corev2.ProtocolVMess:
			if n.Config.UUID != "" {
				entry["uuid"] = n.Config.UUID
				seenSecret[strings.ToLower(n.Config.UUID)] = true
				valid = true
			} else if slots["uuid"] {
				entry["uuid"] = map[string]any{"$keep_secret": true}
				valid = true
			}
		case corev2.ProtocolShadowsocks2022:
			if n.Config.UserKey != "" {
				effectiveKey := n.Config.UserKey
				if derived, derr := DeriveSS2022UserPSKForCipher(n.Config.UserKey, n.Config.Method, n.ID); derr == nil {
					effectiveKey = derived
				}
				entry["psk"] = effectiveKey
				seenSecret[effectiveKey] = true
				valid = true
			} else if slots["psk"] {
				entry["psk"] = map[string]any{"$keep_secret": true}
				valid = true
			}
		case corev2.ProtocolSOCKS5, corev2.ProtocolHTTP:
			uname := firstNonEmpty(n.Config.Username, "user")
			entry["username"] = uname
			if n.Config.Password != "" {
				entry["auth"] = n.Config.Password
				seenSecret["acct:"+uname] = true
				valid = true
			} else if slots["auth"] {
				entry["auth"] = map[string]any{"$keep_secret": true}
				seenSecret["acct:"+uname] = true
				valid = true
			}
		default:
			if n.Config.Password != "" {
				entry["auth"] = n.Config.Password
				seenSecret[n.Config.Password] = true
				valid = true
			} else if slots["auth"] {
				entry["auth"] = map[string]any{"$keep_secret": true}
				valid = true
			}
		}
		if valid {
			out = append(out, entry)
		}
	}

	ss2022Method := ""
	nodeID := ""
	if n != nil {
		ss2022Method = n.Config.Method
		nodeID = n.ID
	}

	// 2. 追加所有多租户活跃订阅用户（避免与节点自带凭据重复触发 core.xray ErrV2Materials 去重报错）
	for _, u := range activeUsers {
		if n != nil && u.ID == "u-"+n.ID {
			continue
		}
		switch protocol {
		case corev2.ProtocolVLESS, corev2.ProtocolVMess:
			if seenSecret[strings.ToLower(u.VLESSUUID)] {
				continue
			}
			seenSecret[strings.ToLower(u.VLESSUUID)] = true
		case corev2.ProtocolShadowsocks2022:
			effPSK := u.SS2022UserKey
			if derived, derr := DeriveSS2022UserPSKForCipher(u.SS2022UserKey, ss2022Method, nodeID); derr == nil {
				effPSK = derived
			}
			if seenSecret[effPSK] {
				continue
			}
			seenSecret[effPSK] = true
		case corev2.ProtocolSOCKS5, corev2.ProtocolHTTP:
			if seenSecret["acct:"+u.ID] {
				continue
			}
			seenSecret["acct:"+u.ID] = true
		default:
			if seenSecret[u.Hy2Password] {
				continue
			}
			seenSecret[u.Hy2Password] = true
		}
		sub := buildProfileUsersForCipher(protocol, ss2022Method, nodeID, []userRecord{u}, existing)
		out = append(out, sub...)
	}
	return out
}

// ComputeDesiredCoreEnabled 判断 core.xray 顶层 enabled 是否应开启：
// 只要存在至少 1 名活跃订阅用户，或存在至少 1 个已启用的托管节点，即保持开启，绝不因配置 WARP 误关停托管节点！
func ComputeDesiredCoreEnabled(activeUsers []userRecord, managedNodes []proxyNodeRecord) bool {
	if len(activeUsers) > 0 {
		return true
	}
	for _, n := range managedNodes {
		if n.Enabled {
			return true
		}
	}
	return false
}

// RedactServerOnlySecrets 仅擦除服务端独占密钥（Reality 私钥、SS2022 服务端主密钥、VLESS 解密私钥），
// 杜绝在 API 回包与实时预览 JSON 中向浏览器泄露服务端私钥（修复 R2-BUG-06）。
func RedactServerOnlySecrets(cfg *nodeConfig) {
	if cfg == nil {
		return
	}
	cfg.PrivateKey = ""
	cfg.ServerKey = ""
	cfg.Decryption = ""
}

// redactNativePreviewSecrets 脱敏原生预览 JSON 中的服务端独占私钥槽位（privateKey / server_key / decryption）。
func redactNativePreviewSecrets(doc map[string]any) {
	if doc == nil {
		return
	}
	if stream, ok := doc["streamSettings"].(map[string]any); ok {
		if reality, ok := stream["realitySettings"].(map[string]any); ok {
			if pk, ok := reality["privateKey"].(string); ok && pk != "" {
				reality["privateKey"] = "<REDACTED>"
			}
		}
	}
	proto, _ := doc["protocol"].(string)
	if settings, ok := doc["settings"].(map[string]any); ok {
		if proto == "vless" {
			if dec, ok := settings["decryption"].(string); ok && dec != "" && dec != "none" {
				settings["decryption"] = "<REDACTED>"
			}
		}
		if proto == "shadowsocks" {
			if method, _ := settings["method"].(string); strings.HasPrefix(strings.ToLower(method), "2022-blake3-") {
				if pw, ok := settings["password"].(string); ok && pw != "" {
					settings["password"] = "<REDACTED>"
				}
			}
		}
	}
}

// ExtractFullURLUserPassword 完整提取 URI userinfo 中的密码（兼容密码内包含冒号 `:` 的情况，修复 R2-BUG-12）。
func ExtractFullURLUserPassword(u *url.URL) string {
	if u == nil || u.User == nil {
		return ""
	}
	userPart := u.User.Username()
	if passPart, hasColon := u.User.Password(); hasColon {
		return strings.TrimSpace(userPart + ":" + passPart)
	}
	return strings.TrimSpace(userPart)
}

// ProbeExternalOrManagedNode 安全执行节点连通性测试（修复 R2-BUG-07）：
// 外部节点强制走 NewPublicProbeDialer 拦截回环/私网探测；仅本机已登记托管节点允许探测本机监听口。
func ProbeExternalOrManagedNode(ctx context.Context, node proxyNodeRecord, target string, timeout time.Duration) (net.Conn, error) {
	network := "tcp"
	if node.Protocol == corev2.ProtocolHysteria2 || node.Protocol == "tuic" || node.Protocol == "wireguard" {
		network = "udp"
	}
	if node.Source == "managed" {
		d := &net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, network, target)
	}
	return NewPublicProbeDialer(timeout).DialContext(ctx, network, target)
}
