// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"encoding/base64"
	"net"
	"net/netip"
	"strconv"
	"strings"

	v1 "github.com/qwq-panel/qwq/sdk/coreapi"
	"github.com/qwq-panel/qwq/sdk/internal/strictjson"
)

// Validate 确定性检查完整快照，不修改输入、不揭示材料或探测监听。
// 停用 profile 仍须完整有效；顶层停用不掩盖其已启用 profiles 的端口冲突。
func Validate(intent *Intent) error {
	if intent == nil {
		return invalid("", "REQUIRED", "必须提供完整配置")
	}
	v := validator{}
	v.require(intent.SchemaVersion == "2", "/schema_version", "VERSION", "契约版本必须为 2")
	v.require(intent.Enabled != nil, "/enabled", "REQUIRED", "必须显式声明 enabled")
	v.require(len(intent.Profiles) >= 1 && len(intent.Profiles) <= MaxProfiles, "/profiles", "SIZE", "profile 数量必须在 1 至 32 之间")
	if intent.Outbound == nil {
		v.require(false, "/outbound", "REQUIRED", "必须提供出站")
	} else {
		v.require(intent.Outbound.Type == "direct", "/outbound/type", "ENUM", "首版只支持 direct 出站")
	}
	seenProfiles := make(map[string]bool, min(len(intent.Profiles), MaxProfiles))
	seenMarks := make(map[uint32]string)
	uniqueUsers := make(map[string]struct{})
	for index := range min(len(intent.Profiles), MaxProfiles) {
		profile := &intent.Profiles[index]
		path := strictjson.Pointer("/profiles", strconv.Itoa(index))
		v.require(v1.ValidID(profile.ID), path+"/id", "ID", "profile ID 必须是 1 至 32 位的小写稳定标识")
		v.require(!seenProfiles[profile.ID], path+"/id", "DUPLICATE", "profile ID 不能重复")
		seenProfiles[profile.ID] = true
		v.require(profile.Enabled != nil, path+"/enabled", "REQUIRED", "必须显式声明 profile enabled")
		_, listenOK := validListen(profile.Listen)
		v.require(listenOK, path+"/listen", "IP", "监听地址必须是无 zone 的 IPv4 或 IPv6")
		v.require(profile.Port >= 1 && profile.Port <= 65535, path+"/port", "RANGE", "入站端口必须在 1 至 65535 之间")
		v.protocol(profile, path)
		v.require(len(profile.Users) >= 1 && len(profile.Users) <= MaxUsers, path+"/users", "SIZE", "每个 profile 必须有 1 至 256 个用户")
		seenUsers := make(map[string]bool, min(len(profile.Users), MaxUsers))
		for userIndex := range min(len(profile.Users), MaxUsers) {
			user := &profile.Users[userIndex]
			userPath := strictjson.Pointer(path+"/users", strconv.Itoa(userIndex))
			v.require(v1.ValidID(user.ID), userPath+"/id", "ID", "用户 ID 必须是小写稳定标识")
			v.require(!seenUsers[user.ID], userPath+"/id", "DUPLICATE", "用户 ID 在同一 profile 内不能重复")
			seenUsers[user.ID] = true
			uniqueUsers[user.ID] = struct{}{}
			if user.TrafficMark != 0 {
				v.require(user.TrafficMark >= MinTrafficMark && user.TrafficMark <= MaxTrafficMark, userPath+"/traffic_mark", "RANGE", "traffic_mark 必须为 0 或位于 0x5100..0x51FF 保留段内")
				if prevUser, dup := seenMarks[user.TrafficMark]; dup && prevUser != user.ID {
					v.require(false, userPath+"/traffic_mark", "DUPLICATE", "traffic_mark 在完整快照内不能被多个用户共用")
				} else if user.TrafficMark >= MinTrafficMark && user.TrafficMark <= MaxTrafficMark {
					seenMarks[user.TrafficMark] = user.ID
				}
			}
			v.credentials(user, profile.Protocol, userPath)
		}
		v.claim(profile, path)
	}
	v.require(len(uniqueUsers) <= MaxUsers, "/profiles", "SIZE", "节点全局唯一用户数不得超过 256")
	if intent.WARP != nil {
		v.warp(intent.WARP, seenProfiles)
	}
	if len(v.violations) != 0 {
		return &Error{Code: "INVALID_INTENT", Violations: v.violations}
	}
	return nil
}

func (v *validator) warp(w *WARPOutbound, seenProfiles map[string]bool) {
	v.secret(&w.PrivateKey, "/warp/private_key")
	v.require(validWGPublicKey(w.PeerPublicKey), "/warp/peer_public_key", "FORMAT", "WARP 对端公钥必须是 32 字节 Base64 WireGuard 公钥")
	v.require(validWARPEndpoint(w.Endpoint), "/warp/endpoint", "ENDPOINT", "WARP 端点必须是合法的 host:port")
	v.require(validWARPAddrV4(w.AddressV4), "/warp/address_v4", "IP", "WARP IPv4 内网地址格式无效")
	if w.AddressV6 != "" {
		v.require(validWARPAddrV6(w.AddressV6), "/warp/address_v6", "IP", "WARP IPv6 内网地址格式无效")
	}
	if len(w.Reserved) > 0 {
		v.require(len(w.Reserved) == 3, "/warp/reserved", "SIZE", "WARP reserved 必须为 3 个字节整数")
		for idx, b := range w.Reserved {
			v.require(b >= 0 && b <= 255, strictjson.Pointer("/warp/reserved", strconv.Itoa(idx)), "RANGE", "reserved 字节值必须在 0..255 之间")
		}
	}
	if w.MTU != 0 {
		v.require(w.MTU >= 1200 && w.MTU <= 1500, "/warp/mtu", "RANGE", "WARP MTU 必须在 1200..1500 之间")
	}
	v.require(w.RoutingMode == WARPRoutingBoundPorts || w.RoutingMode == WARPRoutingDomains || w.RoutingMode == WARPRoutingAll,
		"/warp/routing_mode", "ENUM", "WARP 分流模式必须为 bound_ports、domains 或 all")
	seenBound := make(map[string]bool, len(w.BoundProfileIDs))
	for idx, pid := range w.BoundProfileIDs {
		p := strictjson.Pointer("/warp/bound_profile_ids", strconv.Itoa(idx))
		v.require(seenProfiles[pid], p, "UNKNOWN_PROFILE", "绑定的代理端口 profile 不存在")
		v.require(!seenBound[pid], p, "DUPLICATE", "绑定的代理端口 profile 不能重复")
		seenBound[pid] = true
	}
	v.require(len(w.Domains) <= MaxWARPDomains, "/warp/domains", "SIZE", "WARP 解锁域名数量不得超过 128")
	for idx, d := range w.Domains {
		p := strictjson.Pointer("/warp/domains", strconv.Itoa(idx))
		v.require(validWARPDomainRule(d), p, "DOMAIN", "WARP 解锁域名格式无效")
	}
}

func validWGPublicKey(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 44 && len(s) != 43 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
	}
	return err == nil && len(raw) == 32
}

func validWARPEndpoint(ep string) bool {
	ep = strings.TrimSpace(ep)
	if ep == "" || len(ep) > 259 || strings.ContainsAny(ep, " \t\r\n\x00/\\;{}\"'`") {
		return false
	}
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil || host == "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return false
		}
		return true
	}
	return !strings.EqualFold(host, "localhost") && !strings.EqualFold(host, "metadata.google.internal")
}

func validWARPAddrV4(s string) bool {
	s = strings.TrimSpace(s)
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Addr().Is4() && pfx.Bits() >= 1 && pfx.Bits() <= 32
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Is4()
	}
	return false
}

func validWARPAddrV6(s string) bool {
	s = strings.TrimSpace(s)
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Addr().Is6() && !pfx.Addr().Is4In6() && pfx.Bits() >= 1 && pfx.Bits() <= 128
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Is6() && !addr.Is4In6()
	}
	return false
}

func validWARPDomainRule(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t\r\n\x00/\\;{}\"'`") {
		return false
	}
	for _, prefix := range []string{"domain:", "full:", "keyword:", "geosite:"} {
		if strings.HasPrefix(s, prefix) {
			return len(s) > len(prefix)
		}
	}
	return strings.Contains(s, ".")
}

type validator struct {
	violations []Violation
	ports      []listenerClaim
}

func (v *validator) require(ok bool, path, code, message string) {
	if !ok {
		v.violations = append(v.violations, Violation{Pointer: path, Code: code, Message: message})
	}
}

func (v *validator) secret(ref *SecretRef, path string) {
	if ref == nil {
		v.require(false, path, "REQUIRED", "必须提供对应协议的秘密引用")
		return
	}
	v.require(v1.ValidSecretRef(*ref), path+"/$secret", "SECRET_REF", "必须使用宿主生成的有效 secret 引用")
}

func validListen(listen string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(listen)
	return addr, err == nil && addr.Zone() == ""
}
