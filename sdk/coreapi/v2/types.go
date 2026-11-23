// SPDX-License-Identifier: Apache-2.0

package coreapi

import v1 "github.com/qwq-panel/qwq/sdk/coreapi"

// ======================== 契约与固定上限 ========================
const (
	MaxSize     = v1.MaxSize
	MaxUsers    = v1.MaxUsers
	MaxProfiles = 32

	ProtocolVLESS           = "vless"
	ProtocolVMess           = "vmess"
	ProtocolTrojan          = "trojan"
	ProtocolShadowsocks     = "shadowsocks"
	ProtocolShadowsocks2022 = "shadowsocks2022"
	ProtocolHysteria2       = "hysteria2"
	ProtocolAnyTLS          = "anytls"
	ProtocolSOCKS5          = "socks5"
	ProtocolHTTP            = "http"

	MethodAEADAES256GCM = "aes-256-gcm"
	MethodAEADAES128GCM = "aes-128-gcm"
	MethodAEADChaCha20  = "chacha20-ietf-poly1305"

	MethodAES128   = "2022-blake3-aes-128-gcm"
	MethodAES256   = "2022-blake3-aes-256-gcm"
	MethodChaCha20 = "2022-blake3-chacha20-poly1305"

	ObfsNone = "none"
	ObfsHTTP = "http"
	ObfsTLS  = "tls"

	// MinTrafficMark 与 MaxTrafficMark 限定按用户内核流量整形标记的保留段。
	MinTrafficMark uint32 = 0x5100
	MaxTrafficMark uint32 = 0x51FF

	// WARP 出口分流模式：指定端口全流量 / 仅解锁域名（可选限定端口）/ 全部代理端口。
	WARPRoutingBoundPorts = "bound_ports"
	WARPRoutingDomains    = "domains"
	WARPRoutingAll        = "all"
	MaxWARPDomains        = 128
	DefaultWARPMTU        = 1280
)

// DefaultAnyTLSPaddingScheme 返回标准 8 阶 AnyTLS 填充方案副本。
func DefaultAnyTLSPaddingScheme() []string {
	return []string{
		"stop=8",
		"0=30-30",
		"1=100-400",
		"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
		"3=9-9,500-1000",
		"4=500-1000",
		"5=500-1000",
		"6=500-1000",
		"7=500-1000",
	}
}

// SecretRef、Violation、Error 与 v1 共用身份格式、脱敏和领域错误。
type SecretRef = v1.SecretRef
type Violation = v1.Violation
type Error = v1.Error
type Outbound = v1.Outbound
type Reality = v1.Reality

// Intent 是完整期望快照；Enabled 指针区分缺失字段与显式停用。
type Intent struct {
	SchemaVersion string        `json:"schema_version"`
	Enabled       *bool         `json:"enabled"`
	Profiles      []Profile     `json:"profiles"`
	Outbound      *Outbound     `json:"outbound"`
	WARP          *WARPOutbound `json:"warp,omitempty"`
}

// WARPOutbound 描述可选的 Cloudflare WARP 用户态 WireGuard 服务端链式出口。
// PrivateKey 仅持宿主签发的 secret 引用，不接受明文。
type WARPOutbound struct {
	Enabled         bool      `json:"enabled"`
	PrivateKey      SecretRef `json:"private_key"`
	PeerPublicKey   string    `json:"peer_public_key"`
	Endpoint        string    `json:"endpoint"`
	AddressV4       string    `json:"address_v4"`
	AddressV6       string    `json:"address_v6,omitempty"`
	Reserved        []int     `json:"reserved,omitempty"`
	MTU             int       `json:"mtu,omitempty"`
	RoutingMode     string    `json:"routing_mode"`
	BoundProfileIDs []string  `json:"bound_profile_ids,omitempty"`
	Domains         []string  `json:"domains,omitempty"`
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
	VMess           *VMess           `json:"vmess,omitempty"`
	Trojan          *Trojan          `json:"trojan,omitempty"`
	Shadowsocks     *Shadowsocks     `json:"shadowsocks,omitempty"`
	Shadowsocks2022 *Shadowsocks2022 `json:"shadowsocks2022,omitempty"`
	Hysteria2       *Hysteria2       `json:"hysteria2,omitempty"`
	AnyTLS          *AnyTLS          `json:"anytls,omitempty"`
	SOCKS5          *SOCKS5          `json:"socks5,omitempty"`
	HTTP            *HTTP            `json:"http,omitempty"`
}

// User 的 ID 在整个快照中唯一；凭据由 profile 协议选择，不接受明文。
// TrafficMark 为可选内核流量整形标记（0 表示不限速；非零必须在 0x5100..0x51FF 内且实例唯一）。
// Username 仅用于 SOCKS5/HTTP，省略时默认使用 User.ID。
type User struct {
	ID          string     `json:"id"`
	Username    string     `json:"username,omitempty"`
	UUID        *SecretRef `json:"uuid,omitempty"`
	Auth        *SecretRef `json:"auth,omitempty"`
	PSK         *SecretRef `json:"psk,omitempty"`
	TrafficMark uint32     `json:"traffic_mark,omitempty"`
}

// VLESS 兼容既有 RAW / Vision / REALITY 配置，并支持 gRPC / WS / XHTTP、TLS 与 VLESS Encryption。
type VLESS struct {
	Transport    string      `json:"transport"`
	Flow         string      `json:"flow,omitempty"`
	SecurityMode string      `json:"security_mode,omitempty"`
	Security     *Reality    `json:"security,omitempty"`
	TLS          *TLSBinding `json:"tls,omitempty"`
	Path         string      `json:"path,omitempty"`
	Host         string      `json:"host,omitempty"`
	ServiceName  string      `json:"service_name,omitempty"`
	XHTTPMode    string      `json:"xhttp_mode,omitempty"`
	Decryption   *SecretRef  `json:"decryption,omitempty"`
	Encryption   string      `json:"encryption,omitempty"`
	Sniffing     *bool       `json:"sniffing,omitempty"`
}

// EffectiveSecurityMode 解析 VLESS 安全模式，缺省且存在 Security 时保持向后兼容的 reality。
func (c *VLESS) EffectiveSecurityMode() string {
	if c == nil {
		return ""
	}
	if c.SecurityMode != "" {
		return c.SecurityMode
	}
	if c.Security != nil {
		return "reality"
	}
	if c.TLS != nil {
		return "tls"
	}
	return "reality"
}

// NormalizedTransport 将 tcp 规范化为 Xray v26 的 raw 传输名。
func (c *VLESS) NormalizedTransport() string {
	if c == nil {
		return ""
	}
	if c.Transport == "tcp" {
		return "raw"
	}
	return c.Transport
}

// VMess 支持 RAW/TCP、WebSocket 与 gRPC 传输，以及 none/tls 安全层。
type VMess struct {
	Transport    string      `json:"transport"`
	SecurityMode string      `json:"security_mode"`
	TLS          *TLSBinding `json:"tls,omitempty"`
	Path         string      `json:"path,omitempty"`
	Host         string      `json:"host,omitempty"`
	ServiceName  string      `json:"service_name,omitempty"`
	Sniffing     *bool       `json:"sniffing,omitempty"`
}

// NormalizedTransport 将 tcp 规范化为 raw。
func (c *VMess) NormalizedTransport() string {
	if c == nil {
		return ""
	}
	if c.Transport == "tcp" {
		return "raw"
	}
	return c.Transport
}

// Trojan 支持 RAW/TCP、gRPC 与 WebSocket 传输，以及 TLS 或 REALITY 安全层。
type Trojan struct {
	Transport    string      `json:"transport"`
	SecurityMode string      `json:"security_mode"`
	TLS          *TLSBinding `json:"tls,omitempty"`
	Reality      *Reality    `json:"reality,omitempty"`
	Path         string      `json:"path,omitempty"`
	Host         string      `json:"host,omitempty"`
	ServiceName  string      `json:"service_name,omitempty"`
	Sniffing     *bool       `json:"sniffing,omitempty"`
}

// NormalizedTransport 将 tcp 规范化为 raw。
func (c *Trojan) NormalizedTransport() string {
	if c == nil {
		return ""
	}
	if c.Transport == "tcp" {
		return "raw"
	}
	return c.Transport
}

// Shadowsocks 表示传统 AEAD 多用户 Shadowsocks 入站。
type Shadowsocks struct {
	Method   string `json:"method"`
	UDP      bool   `json:"udp,omitempty"`
	Sniffing *bool  `json:"sniffing,omitempty"`
}

// Hysteria2 消费受控 TLS，支持可选 Salamander 混淆密码与端口跳跃范围声明。
type Hysteria2 struct {
	TLS          *TLSBinding `json:"tls"`
	ObfsPassword *SecretRef  `json:"obfs_password,omitempty"`
	PortHopping  string      `json:"port_hopping,omitempty"`
	Sniffing     *bool       `json:"sniffing,omitempty"`
}

// AnyTLS 消费宿主托管 TLS 证书，由驱动内建纯 Go AnyTLS v1/v2 服务端承载。
type AnyTLS struct {
	TLS           *TLSBinding `json:"tls"`
	PaddingScheme []string    `json:"padding_scheme,omitempty"`
}

// SOCKS5 表示受密码鉴权保护的 SOCKS5 入站。
type SOCKS5 struct {
	UDP      bool  `json:"udp,omitempty"`
	Sniffing *bool `json:"sniffing,omitempty"`
}

// HTTP 表示受密码鉴权保护的 HTTP 代理入站。
type HTTP struct {
	Sniffing *bool `json:"sniffing,omitempty"`
}

// TLSBinding 是宿主授权的稳定绑定引用与消费 SNI。
// 引用本身不授予权限；运行时由宿主固定 generation 与 policy revision。
type TLSBinding struct {
	BindingRef string `json:"binding_ref"`
	ServerName string `json:"server_name"`
}

// Shadowsocks2022 支持 BLAKE3 AES-128/AES-256 与 ChaCha20；UDP 默认关闭并单独受运行门禁控制。
type Shadowsocks2022 struct {
	Method    string    `json:"method"`
	ServerKey SecretRef `json:"server_key"`
	Obfs      *Obfs     `json:"obfs"`
	UDP       bool      `json:"udp,omitempty"`
	Sniffing  *bool     `json:"sniffing,omitempty"`
}

// Obfs 只表示 none/http/tls 与受控 host，不携带命令、路径或额外参数。
type Obfs struct {
	Mode string `json:"mode"`
	Host string `json:"host,omitempty"`
}

// String 与 GoString 防止普通调试格式意外展开完整期望配置。
func (Intent) String() string       { return "CoreIntent(v2)" }
func (Intent) GoString() string     { return "coreapi.Intent{[REDACTED]}" }
func (Profile) String() string      { return "CoreProfile{[REDACTED]}" }
func (Profile) GoString() string    { return "coreapi.Profile{[REDACTED]}" }
func (WARPOutbound) String() string { return "WARPOutbound{[REDACTED]}" }
