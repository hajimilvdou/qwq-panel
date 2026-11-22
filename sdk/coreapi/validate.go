// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Validate 确定性检查完整 Intent，不修改输入、不解析 DNS、不揭示秘密。
// 即使 Enabled=false，入站仍须完整有效，确保再次启用无需补齐字段。
func Validate(intent *Intent) error {
	if intent == nil {
		return invalid("", "REQUIRED", "必须提供完整配置")
	}
	v := validator{}
	v.require(intent.SchemaVersion == "1", "/schema_version", "VERSION", "契约版本必须为 1")
	v.require(intent.Enabled != nil, "/enabled", "REQUIRED", "必须显式声明 enabled")
	if intent.Inbound == nil {
		v.require(false, "/inbound", "REQUIRED", "必须提供唯一入站")
	} else {
		v.inbound(intent.Inbound)
	}
	if intent.Outbound == nil {
		v.require(false, "/outbound", "REQUIRED", "必须提供出站")
	} else {
		v.require(intent.Outbound.Type == "direct", "/outbound/type", "ENUM", "首版只支持 direct 出站")
	}
	if len(v.violations) != 0 {
		return &Error{Code: "INVALID_INTENT", Violations: v.violations}
	}
	return nil
}

type validator struct{ violations []Violation }

func (v *validator) require(ok bool, path, code, message string) {
	if !ok {
		v.violations = append(v.violations, Violation{path, code, message})
	}
}

func (v *validator) inbound(in *Inbound) {
	const path = "/inbound"
	v.require(validID(in.ID), path+"/id", "ID", "ID 必须是 1 至 32 位的小写稳定标识")
	addr, err := netip.ParseAddr(in.Listen)
	v.require(err == nil && addr.Zone() == "", path+"/listen", "IP", "监听地址必须是无 zone 的 IPv4 或 IPv6")
	v.require(in.Port >= 1024 && in.Port <= 65535, path+"/port", "RANGE", "入站端口必须在 1024 至 65535 之间")
	v.require(in.Protocol == "vless", path+"/protocol", "ENUM", "首版只支持 vless")
	v.require(in.Transport == "raw", path+"/transport", "ENUM", "首版只支持 raw")
	v.require(in.Flow == "xtls-rprx-vision", path+"/flow", "ENUM", "首版只支持 xtls-rprx-vision")
	if in.Security == nil {
		v.require(false, path+"/security", "REQUIRED", "必须提供 REALITY 配置")
	} else {
		v.reality(in.Security, path+"/security")
	}
	v.require(len(in.Users) >= 1 && len(in.Users) <= MaxUsers, path+"/users", "SIZE", "用户数量必须在 1 至 256 之间")
	seen := make(map[string]struct{}, min(len(in.Users), MaxUsers))
	for index, user := range in.Users[:min(len(in.Users), MaxUsers)] {
		userPath := pointer(path+"/users", strconv.Itoa(index))
		v.require(validID(user.ID), userPath+"/id", "ID", "用户 ID 必须是小写稳定标识")
		_, duplicate := seen[user.ID]
		v.require(!duplicate, userPath+"/id", "DUPLICATE", "用户 ID 不能重复")
		seen[user.ID] = struct{}{}
		v.secret(user.UUID, userPath+"/uuid")
	}
}

func (v *validator) reality(reality *Reality, path string) {
	v.require(reality.Mode == "reality", path+"/mode", "ENUM", "首版只支持 reality")
	domain, targetOK := targetDomain(reality.Target)
	v.require(targetOK, path+"/target", "TARGET", "目标必须是合法 DNS 名或 IP 加明确端口")
	v.require(len(reality.ServerNames) >= 1 && len(reality.ServerNames) <= MaxNames, path+"/server_names", "SIZE", "server_names 数量必须在 1 至 8 之间")
	containsTarget := domain == ""
	for index, name := range reality.ServerNames[:min(len(reality.ServerNames), MaxNames)] {
		ok := validDNS(name)
		v.require(ok, pointer(path+"/server_names", strconv.Itoa(index)), "DNS", "SNI 必须是合法 DNS 名，不允许通配符")
		containsTarget = containsTarget || (ok && canonicalDNS(name) == domain)
	}
	if targetOK && domain != "" {
		v.require(containsTarget, path+"/server_names", "TARGET_SNI", "server_names 必须包含目标域名")
	}
	v.secret(reality.PrivateKey, path+"/private_key")
	v.require(len(reality.ShortIDs) >= 1 && len(reality.ShortIDs) <= MaxNames, path+"/short_ids", "SIZE", "short_ids 数量必须在 1 至 8 之间")
	seen := make(map[string]struct{}, min(len(reality.ShortIDs), MaxNames))
	for index, id := range reality.ShortIDs[:min(len(reality.ShortIDs), MaxNames)] {
		itemPath := pointer(path+"/short_ids", strconv.Itoa(index))
		if len(id) < 2 || len(id) > 16 || len(id)%2 != 0 {
			v.require(false, itemPath, "SHORT_ID", "short ID 必须是 2 至 16 位的偶数长度 hex")
			continue
		}
		decoded, err := hex.DecodeString(id)
		ok := err == nil
		v.require(ok, itemPath, "SHORT_ID", "short ID 必须是 2 至 16 位的偶数长度 hex")
		if ok {
			_, duplicate := seen[string(decoded)]
			v.require(!duplicate, itemPath, "DUPLICATE", "short ID 不能重复")
			seen[string(decoded)] = struct{}{}
		}
	}
}

func (v *validator) secret(ref SecretRef, path string) {
	v.require(validSecretID(ref.ID), path+"/$secret", "SECRET_REF", "必须使用宿主生成的有效 secret 引用")
}

func validSecretID(id string) bool {
	if len(id) != 30 || !strings.HasPrefix(id, "sec_") || id[4] > '7' {
		return false
	}
	for _, char := range id[4:] {
		if !strings.ContainsRune("0123456789abcdefghjkmnpqrstvwxyz", char) {
			return false
		}
	}
	return true
}

func validID(id string) bool {
	if len(id) < 1 || len(id) > 32 || id[0] < 'a' || id[0] > 'z' {
		return false
	}
	for _, char := range id[1:] {
		if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && !strings.ContainsRune("._-", char) {
			return false
		}
	}
	return true
}

func canonicalDNS(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func validDNS(name string) bool {
	if len(name) < 1 || len(name) > MaxDNSNameLength {
		return false
	}
	name = strings.TrimSuffix(name, ".")
	numeric := true
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '-' {
				return false
			}
			numeric = numeric && char >= '0' && char <= '9'
		}
	}
	return !numeric
}

func targetDomain(target string) (string, bool) {
	if len(target) > MaxDNSNameLength+6 {
		return "", false
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || port == "" {
		return "", false
	}
	for _, char := range port {
		if char < '0' || char > '9' {
			return "", false
		}
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return "", false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return "", addr.Zone() == ""
	}
	if strings.HasPrefix(target, "[") || !validDNS(host) {
		return "", false
	}
	return canonicalDNS(host), true
}

// ======================== 稳定原生标识 ========================

// InboundTag 映射合法面板 ID；拒绝把自由文本带入原生 tag。
func InboundTag(id string) (string, error) { return stableName("qwq-in-", id) }

// UserEmail 提供固定统计标识，不把 email 当作自由文本永久主键。
func UserEmail(id string) (string, error) { return stableName("qwq-user-", id) }

func stableName(prefix, id string) (string, error) {
	if !validID(id) {
		return "", invalid("/id", "ID", "标识必须是合法面板 ID")
	}
	return prefix + id, nil
}

// ======================== 版本间复用的纯规则 ========================

// ValidID 检查稳定面板 ID，不生成原生标识或修改输入。
func ValidID(id string) bool { return validID(id) }

// ValidSecretRef 只检查宿主引用语法；存在性、owner 和 purpose 仍由宿主校验。
func ValidSecretRef(ref SecretRef) bool { return validSecretID(ref.ID) }

// ValidDNSName 检查无通配符的 ASCII DNS 名；不发起解析或证明域名所有权。
func ValidDNSName(name string) bool { return validDNS(name) }

// ValidateReality 复用 v1 的完整 REALITY 规则，错误路径相对于该对象根。
// 不包含调用方的 profile 前缀，供版本化契约按实际位置重定位。
func ValidateReality(reality *Reality) error {
	if reality == nil {
		return invalid("", "REQUIRED", "必须提供 REALITY 配置")
	}
	v := validator{}
	v.reality(reality, "")
	if len(v.violations) != 0 {
		return &Error{Code: "INVALID_INTENT", Violations: v.violations}
	}
	return nil
}
