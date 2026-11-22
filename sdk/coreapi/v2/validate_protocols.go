// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"errors"

	v1 "github.com/qwq-panel/qwq/sdk/coreapi"
)

// ======================== 严格协议与凭据联合 ========================
func (v *validator) protocol(profile *Profile, path string) {
	validProtocol := profile.Protocol == ProtocolVLESS || profile.Protocol == ProtocolHysteria2 || profile.Protocol == ProtocolShadowsocks2022
	v.require(validProtocol, path+"/protocol", "ENUM", "仅支持 vless、hysteria2 或 shadowsocks2022")
	for _, member := range []struct {
		name    string
		present bool
	}{
		{ProtocolVLESS, profile.VLESS != nil},
		{ProtocolHysteria2, profile.Hysteria2 != nil},
		{ProtocolShadowsocks2022, profile.Shadowsocks2022 != nil},
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
	case ProtocolHysteria2:
		if profile.Hysteria2 != nil {
			v.hysteria2(profile.Hysteria2, path+"/hysteria2")
		}
	case ProtocolShadowsocks2022:
		if profile.Shadowsocks2022 != nil {
			v.shadowsocks2022(profile.Shadowsocks2022, path+"/shadowsocks2022")
		}
	}
}

func (v *validator) credentials(user *User, protocol, path string) {
	required := ""
	switch protocol {
	case ProtocolVLESS:
		required = "uuid"
	case ProtocolHysteria2:
		required = "auth"
	case ProtocolShadowsocks2022:
		required = "psk"
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
	v.require(config.Transport == "raw", path+"/transport", "ENUM", "首版只支持 raw")
	v.require(config.Flow == "xtls-rprx-vision", path+"/flow", "ENUM", "首版只支持 xtls-rprx-vision")
	if err := v1.ValidateReality(config.Security); err != nil {
		var failure *v1.Error
		if !errors.As(err, &failure) || failure == nil {
			v.require(false, path+"/security", "REALITY", "REALITY 配置未通过校验")
			return
		}
		// 共享校验返回领域规则，定位到该 profile 的实际 REALITY 根。
		for _, violation := range failure.Violations {
			v.violations = append(v.violations, Violation{
				Pointer: path + "/security" + violation.Pointer,
				Code:    violation.Code,
				Message: violation.Message,
			})
		}
	}
}

func (v *validator) hysteria2(config *Hysteria2, path string) {
	if config.TLS == nil {
		v.require(false, path+"/tls", "REQUIRED", "必须提供宿主授权的 TLS 绑定")
		return
	}
	v.require(validBindingRef(config.TLS.BindingRef), path+"/tls/binding_ref", "BINDING_REF", "绑定引用必须是 1 至 128 位的受控 ASCII 标识")
	v.require(v1.ValidDNSName(config.TLS.ServerName), path+"/tls/server_name", "DNS", "消费 SNI 必须是合法 DNS 名，不允许通配符")
}

func (v *validator) shadowsocks2022(config *Shadowsocks2022, path string) {
	v.require(config.Method == MethodAES128 || config.Method == MethodAES256, path+"/method", "ENUM", "SS2022 多用户只支持两个 AES 方法")
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
