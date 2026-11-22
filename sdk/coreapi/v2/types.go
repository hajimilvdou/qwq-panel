// SPDX-License-Identifier: Apache-2.0

package coreapi

import v1 "github.com/qwq-panel/qwq/sdk/coreapi"

// ======================== 契约与固定上限 ========================
const (
	MaxSize     = v1.MaxSize
	MaxUsers    = v1.MaxUsers
	MaxProfiles = 8

	ProtocolVLESS           = "vless"
	ProtocolHysteria2       = "hysteria2"
	ProtocolShadowsocks2022 = "shadowsocks2022"

	MethodAES128 = "2022-blake3-aes-128-gcm"
	MethodAES256 = "2022-blake3-aes-256-gcm"

	ObfsNone = "none"
	ObfsHTTP = "http"
	ObfsTLS  = "tls"

	// MinTrafficMark 与 MaxTrafficMark 限定按用户内核流量整形标记的保留段。
	MinTrafficMark uint32 = 0x5100
	MaxTrafficMark uint32 = 0x51FF
)

// SecretRef、Violation、Error 与 v1 共用身份格式、脱敏和领域错误。
type SecretRef = v1.SecretRef
type Violation = v1.Violation
type Error = v1.Error
type Outbound = v1.Outbound
type Reality = v1.Reality

// Intent 是完整期望快照；Enabled 指针区分缺失字段与显式停用。
type Intent struct {
	SchemaVersion string    `json:"schema_version"`
	Enabled       *bool     `json:"enabled"`
	Profiles      []Profile `json:"profiles"`
	Outbound      *Outbound `json:"outbound"`
}

// Profile 通过 Protocol 选择唯一成员；其他协议成员必须完全缺失。
// 内部 obfs 转发地址与端口由驱动管理，不进入该公开模型。
type Profile struct {
	ID              string           `json:"id"`
	Enabled         *bool            `json:"enabled"`
	Listen          string           `json:"listen"`
	Port            int              `json:"port"`
	Protocol        string           `json:"protocol"`
	Users           []User           `json:"users"`
	VLESS           *VLESS           `json:"vless,omitempty"`
	Hysteria2       *Hysteria2       `json:"hysteria2,omitempty"`
	Shadowsocks2022 *Shadowsocks2022 `json:"shadowsocks2022,omitempty"`
}

// User 的 ID 在整个快照中唯一；凭据由 profile 协议选择，不接受明文。
// TrafficMark 为可选内核流量整形标记（0 表示不限速；非零必须在 0x5100..0x51FF 内且实例唯一）。
type User struct {
	ID          string     `json:"id"`
	UUID        *SecretRef `json:"uuid,omitempty"`
	Auth        *SecretRef `json:"auth,omitempty"`
	PSK         *SecretRef `json:"psk,omitempty"`
	TrafficMark uint32     `json:"traffic_mark,omitempty"`
}

// VLESS 保持既有 RAW / Vision / REALITY 语义与秘密身份。
type VLESS struct {
	Transport string   `json:"transport"`
	Flow      string   `json:"flow"`
	Security  *Reality `json:"security"`
}

// Hysteria2 首期只暴露受控 TLS；未验证的 QUIC/带宽调节不进入契约。
type Hysteria2 struct {
	TLS *TLSBinding `json:"tls"`
}

// TLSBinding 是宿主授权的稳定绑定引用与消费 SNI。
// 引用本身不授予权限；运行时由宿主固定 generation 与 policy revision。
type TLSBinding struct {
	BindingRef string `json:"binding_ref"`
	ServerName string `json:"server_name"`
}

// Shadowsocks2022 只接受 AES 多用户方法；UDP 默认关闭并单独受运行门禁控制。
type Shadowsocks2022 struct {
	Method    string    `json:"method"`
	ServerKey SecretRef `json:"server_key"`
	Obfs      *Obfs     `json:"obfs"`
	UDP       bool      `json:"udp,omitempty"`
}

// Obfs 只表示 none/http/tls 与受控 host，不携带命令、路径或额外参数。
type Obfs struct {
	Mode string `json:"mode"`
	Host string `json:"host,omitempty"`
}

// String 与 GoString 防止普通调试格式意外展开完整期望配置。
func (Intent) String() string    { return "CoreIntent(v2)" }
func (Intent) GoString() string  { return "coreapi.Intent{[REDACTED]}" }
func (Profile) String() string   { return "CoreProfile{[REDACTED]}" }
func (Profile) GoString() string { return "coreapi.Profile{[REDACTED]}" }
