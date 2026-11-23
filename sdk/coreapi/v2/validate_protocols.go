// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"errors"
	"strconv"
	"strings"

	v1 "github.com/qwq-panel/qwq/sdk/coreapi"
)

// ======================== 严格协议与凭据联合 ========================
func (v *validator) protocol(profile *Profile, path string) {
	validProtocol := false
	switch profile.Protocol {
	case ProtocolVLESS, ProtocolVMess, ProtocolTrojan, ProtocolShadowsocks, ProtocolShadowsocks2022,
		ProtocolHysteria2, ProtocolAnyTLS, ProtocolSOCKS5, ProtocolHTTP:
		validProtocol = true
	}
	v.require(validProtocol, path+"/protocol", "ENUM", "仅支持 vless、vmess、trojan、shadowsocks、shadowsocks2022、hysteria2、anytls、socks5 或 http")
	for _, member := range []struct {
		name    string
		present bool
	}{
		{ProtocolVLESS, profile.VLESS != nil},
		{ProtocolVMess, profile.VMess != nil},
		{ProtocolTrojan, profile.Trojan != nil},
		{ProtocolShadowsocks, profile.Shadowsocks != nil},
		{ProtocolShadowsocks2022, profile.Shadowsocks2022 != nil},
		{ProtocolHysteria2, profile.Hysteria2 != nil},
		{ProtocolAnyTLS, profile.AnyTLS != nil},
		{ProtocolSOCKS5, profile.SOCKS5 != nil},
		{ProtocolHTTP, profile.HTTP != nil},
	} {
		if member.name == profile.Protocol {
			v.require(member.present, path+"/"+member.name, "REQUIRED", "必须提供选定协议的完整配置")
		} else {
			v.require(!member.present, path+"/"+member.name, "FORBIDDEN", "不能混入其他协议的配置")
		}
	}
	switch profile.Protocol {
	case ProtocolVLESS:
		if profile.VLESS != nil {
			v.vless(profile.VLESS, path+"/vless")
		}
	case ProtocolVMess:
		if profile.VMess != nil {
			v.vmess(profile.VMess, path+"/vmess")
		}
	case ProtocolTrojan:
		if profile.Trojan != nil {
			v.trojan(profile.Trojan, path+"/trojan")
		}
	case ProtocolShadowsocks:
		if profile.Shadowsocks != nil {
			v.shadowsocks(profile.Shadowsocks, path+"/shadowsocks")
		}
	case ProtocolShadowsocks2022:
		if profile.Shadowsocks2022 != nil {
			v.shadowsocks2022(profile.Shadowsocks2022, path+"/shadowsocks2022")
		}
	case ProtocolHysteria2:
		if profile.Hysteria2 != nil {
			v.hysteria2(profile.Hysteria2, path+"/hysteria2")
		}
	case ProtocolAnyTLS:
		if profile.AnyTLS != nil {
			v.anytls(profile.AnyTLS, path+"/anytls")
		}
	case ProtocolSOCKS5:
		// SOCKS5 仅有可选布尔字段，非空检查已完成。
	case ProtocolHTTP:
		// HTTP 仅有可选布尔字段，非空检查已完成。
	}
}

func (v *validator) credentials(user *User, protocol, path string) {
	required := ""
	allowUsername := false
	switch protocol {
	case ProtocolVLESS, ProtocolVMess:
		required = "uuid"
	case ProtocolTrojan, ProtocolShadowsocks, ProtocolHysteria2, ProtocolAnyTLS:
		required = "auth"
	case ProtocolSOCKS5, ProtocolHTTP:
		required = "auth"
		allowUsername = true
	case ProtocolShadowsocks2022:
		required = "psk"
	}
	if user.Username != "" {
		if !allowUsername {
			v.require(false, path+"/username", "FORBIDDEN", "仅 socks5 与 http 协议允许显式设置 username")
		} else {
			v.require(validUsername(user.Username), path+"/username", "FORMAT", "用户名必须是 1 至 64 位不含空白、冒号或控制字符的可见 ASCII")
		}
	}
	for _, field := range []struct {
		name string
		ref  *SecretRef
	}{{"uuid", user.UUID}, {"auth", user.Auth}, {"psk", user.PSK}} {
		if field.name == required {
			v.secret(field.ref, path+"/"+field.name)
		} else {
			v.require(field.ref == nil, path+"/"+field.name, "FORBIDDEN", "不能混入其他协议的用户凭据")
		}
	}
}

func (v *validator) vless(config *VLESS, path string) {
	normTransport := config.NormalizedTransport()
	v.require(normTransport == "raw" || normTransport == "grpc" || normTransport == "ws" || normTransport == "xhttp",
		path+"/transport", "ENUM", "VLESS 传输仅支持 raw、tcp、grpc、ws 或 xhttp")

	if config.SecurityMode != "" {
		v.require(config.SecurityMode == "reality" || config.SecurityMode == "tls" || config.SecurityMode == "none",
			path+"/security_mode", "ENUM", "VLESS 安全模式仅支持 reality、tls 或 none")
	}
	secMode := config.EffectiveSecurityMode()

	if config.Flow != "" && config.Flow != "xtls-rprx-vision" {
		v.require(false, path+"/flow", "ENUM", "VLESS flow 仅支持空值或 xtls-rprx-vision")
	} else if config.Flow == "xtls-rprx-vision" {
		v.require(normTransport == "raw" && (secMode == "reality" || secMode == "tls"),
			path+"/flow", "FORBIDDEN", "xtls-rprx-vision 仅允许在 raw/tcp 搭配 reality 或 tls 时启用")
	}

	switch secMode {
	case "reality":
		v.require(config.TLS == nil, path+"/tls", "FORBIDDEN", "reality 模式不能混入 tls 绑定")
		v.realityBlock(config.Security, path+"/security")
	case "tls":
		v.require(config.Security == nil, path+"/security", "FORBIDDEN", "tls 模式不能混入 reality 配置")
		v.tlsBinding(config.TLS, path+"/tls")
	case "none":
		v.require(config.Security == nil, path+"/security", "FORBIDDEN", "none 模式不能混入 reality 配置")
		v.require(config.TLS == nil, path+"/tls", "FORBIDDEN", "none 模式不能混入 tls 绑定")
	}

	v.transportMeta(config.Path, config.Host, config.ServiceName, path)
	if config.XHTTPMode != "" {
		v.require(normTransport == "xhttp", path+"/xhttp_mode", "FORBIDDEN", "xhttp_mode 仅在 transport 为 xhttp 时允许设置")
		v.require(config.XHTTPMode == "auto" || config.XHTTPMode == "packet-up" || config.XHTTPMode == "stream-up" || config.XHTTPMode == "stream-one",
			path+"/xhttp_mode", "ENUM", "xhttp_mode 仅支持 auto、packet-up、stream-up 或 stream-one")
	}
	if config.Decryption != nil {
		v.secret(config.Decryption, path+"/decryption")
	}
	if config.Encryption != "" {
		v.require(validSafeToken(config.Encryption, 256), path+"/encryption", "FORMAT", "encryption 格式无效")
	}
}

func (v *validator) vmess(config *VMess, path string) {
	normTransport := config.NormalizedTransport()
	v.require(normTransport == "raw" || normTransport == "ws" || normTransport == "grpc",
		path+"/transport", "ENUM", "VMess 传输仅支持 raw、tcp、ws 或 grpc")
	v.require(config.SecurityMode == "none" || config.SecurityMode == "tls",
		path+"/security_mode", "ENUM", "VMess 安全模式仅支持 none 或 tls")
	switch config.SecurityMode {
	case "tls":
		v.tlsBinding(config.TLS, path+"/tls")
	case "none":
		v.require(config.TLS == nil, path+"/tls", "FORBIDDEN", "none 模式不能混入 tls 绑定")
	}
	v.transportMeta(config.Path, config.Host, config.ServiceName, path)
}

func (v *validator) trojan(config *Trojan, path string) {
	normTransport := config.NormalizedTransport()
	v.require(normTransport == "raw" || normTransport == "grpc" || normTransport == "ws",
		path+"/transport", "ENUM", "Trojan 传输仅支持 raw、tcp、grpc 或 ws")
	v.require(config.SecurityMode == "tls" || config.SecurityMode == "reality",
		path+"/security_mode", "ENUM", "Trojan 安全模式仅支持 tls 或 reality")
	switch config.SecurityMode {
	case "tls":
		v.require(config.Reality == nil, path+"/reality", "FORBIDDEN", "tls 模式不能混入 reality 配置")
		v.tlsBinding(config.TLS, path+"/tls")
	case "reality":
		v.require(config.TLS == nil, path+"/tls", "FORBIDDEN", "reality 模式不能混入 tls 绑定")
		v.realityBlock(config.Reality, path+"/reality")
	}
	v.transportMeta(config.Path, config.Host, config.ServiceName, path)
}

func (v *validator) shadowsocks(config *Shadowsocks, path string) {
	v.require(config.Method == MethodAEADAES256GCM || config.Method == MethodAEADAES128GCM || config.Method == MethodAEADChaCha20,
		path+"/method", "ENUM", "传统 Shadowsocks 仅支持 aes-256-gcm、aes-128-gcm 或 chacha20-ietf-poly1305")
}

func (v *validator) hysteria2(config *Hysteria2, path string) {
	v.tlsBinding(config.TLS, path+"/tls")
	if config.ObfsPassword != nil {
		v.secret(config.ObfsPassword, path+"/obfs_password")
	}
	if config.PortHopping != "" {
		v.require(validPortHopping(config.PortHopping), path+"/port_hopping", "FORMAT", "port_hopping 必须为合法端口或端口区间（如 20000-30000）")
	}
}

func (v *validator) anytls(config *AnyTLS, path string) {
	v.tlsBinding(config.TLS, path+"/tls")
	if len(config.PaddingScheme) > 0 {
		v.require(len(config.PaddingScheme) <= 32, path+"/padding_scheme", "SIZE", "AnyTLS padding_scheme 最多允许 32 行")
		for idx, line := range config.PaddingScheme {
			if idx >= 32 {
				break
			}
			v.require(validPaddingLine(line), path+"/padding_scheme/"+strconv.Itoa(idx), "FORMAT", "AnyTLS padding_scheme 行格式无效")
		}
	}
}

func (v *validator) shadowsocks2022(config *Shadowsocks2022, path string) {
	v.require(config.Method == MethodAES128 || config.Method == MethodAES256 || config.Method == MethodChaCha20,
		path+"/method", "ENUM", "SS2022 仅支持 2022-blake3-aes-128-gcm、2022-blake3-aes-256-gcm 或 2022-blake3-chacha20-poly1305")
	v.secret(&config.ServerKey, path+"/server_key")
	if config.Obfs == nil {
		v.require(false, path+"/obfs", "REQUIRED", "必须显式选择混淆模式")
		return
	}
	switch config.Obfs.Mode {
	case ObfsNone:
		v.require(config.Obfs.Host == "", path+"/obfs/host", "FORBIDDEN", "none 模式不接受混淆 host")
	case ObfsHTTP, ObfsTLS:
		v.require(v1.ValidDNSName(config.Obfs.Host), path+"/obfs/host", "DNS", "混淆 host 必须是合法 DNS 名")
		v.require(!config.UDP, path+"/udp", "FORBIDDEN", "simple-obfs 不包装 UDP")
	default:
		v.require(false, path+"/obfs/mode", "ENUM", "混淆模式只能是 none、http 或 tls")
	}
}

func (v *validator) realityBlock(sec *Reality, path string) {
	if err := v1.ValidateReality(sec); err != nil {
		var failure *v1.Error
		if !errors.As(err, &failure) || failure == nil {
			v.require(false, path, "REALITY", "REALITY 配置未通过校验")
			return
		}
		for _, violation := range failure.Violations {
			v.violations = append(v.violations, Violation{
				Pointer: path + violation.Pointer,
				Code:    violation.Code,
				Message: violation.Message,
			})
		}
	}
}

func (v *validator) tlsBinding(tls *TLSBinding, path string) {
	if tls == nil {
		v.require(false, path, "REQUIRED", "必须提供宿主授权的 TLS 绑定")
		return
	}
	v.require(validBindingRef(tls.BindingRef), path+"/binding_ref", "BINDING_REF", "绑定引用必须是 1 至 128 位的受控 ASCII 标识")
	v.require(v1.ValidDNSName(tls.ServerName), path+"/server_name", "DNS", "消费 SNI 必须是合法 DNS 名，不允许通配符")
}

func (v *validator) transportMeta(pathVal, hostVal, serviceName, base string) {
	if pathVal != "" {
		v.require(validTransportPath(pathVal), base+"/path", "FORMAT", "传输路径必须以 / 开头且不含空白或控制字符")
	}
	if hostVal != "" {
		v.require(v1.ValidDNSName(hostVal), base+"/host", "DNS", "传输 Host 必须是合法 DNS 名")
	}
	if serviceName != "" {
		v.require(validSafeToken(serviceName, 128), base+"/service_name", "FORMAT", "gRPC serviceName 格式无效")
	}
}

func validBindingRef(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, char := range id {
		if !(char >= 'A' && char <= 'Z') && !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '_' && char != '.' && char != '-' {
			return false
		}
	}
	return true
}

func validTransportPath(s string) bool {
	if len(s) < 1 || len(s) > 256 || s[0] != '/' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || c == '\\' {
			return false
		}
	}
	return true
}

func validSafeToken(s string, maxLen int) bool {
	if len(s) < 1 || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || c == '\\' {
			return false
		}
	}
	return true
}

func validUsername(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || c == ':' || c == '@' || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}

func validPaddingLine(s string) bool {
	if len(s) < 1 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func validPortHopping(spec string) bool {
	if len(spec) < 1 || len(spec) > 64 {
		return false
	}
	parts := strings.Split(spec, ",")
	if len(parts) > 8 {
		return false
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return false
			}
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo >= hi {
				return false
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return false
			}
		}
	}
	return true
}
