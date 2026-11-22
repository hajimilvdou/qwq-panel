// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"crypto/x509"
	"errors"
	"log/slog"
	"time"

	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 私有协议材料，公开Intent只保留引用 ========================

var ErrV2Materials = errors.New("xrayconfig: invalid v2 material")
var ErrObfsTarget = errors.New("xrayconfig: private obfs target required")
var errMaterialSerialization = errors.New("xrayconfig: refusing to serialize private material")

type V2Materials struct{ Profiles map[string]ProfileMaterials }

// ProfileMaterials 与期望协议一一对应；其他成员必须完全缺失。
type ProfileMaterials struct {
	VLESS           *Secrets
	Hysteria2       *HysteriaMaterials
	Shadowsocks2022 *SS2022Materials
}

type HysteriaMaterials struct {
	Auth map[string][]byte
	TLS  TLSMaterials
}

type TLSMaterials struct {
	BindingRef     string
	Generation     uint64
	PolicyRevision string
	SANs           []string
	Material       tlsmgr.Material
	Purpose        tlsmgr.MaterialPurpose
	Trust          tlsmgr.TrustClass
	Roots          *x509.CertPool
}

type SS2022Materials struct {
	ServerKey []byte
	PSKs      map[string][]byte
}

type ObfsTarget struct {
	Listen string
	Port   int
}

// OutboundFamilyMode 描述双栈出站地址族策略（与 Track 05 netfacts 策略对齐）。
type OutboundFamilyMode string

const (
	FamilyIPv4Only   OutboundFamilyMode = "ipv4_only"
	FamilyIPv6Only   OutboundFamilyMode = "ipv6_only"
	FamilyPreferIPv4 OutboundFamilyMode = "prefer_ipv4"
	FamilyPreferIPv6 OutboundFamilyMode = "prefer_ipv6"
)

type DomainOutboundOverride struct {
	DomainSuffix string             `json:"domain_suffix"`
	Mode         OutboundFamilyMode `json:"mode"`
}

type OutboundPolicy struct {
	DefaultMode OutboundFamilyMode       `json:"default_mode"`
	BindIPv4    string                   `json:"bind_ipv4,omitempty"`
	BindIPv6    string                   `json:"bind_ipv6,omitempty"`
	Overrides   []DomainOutboundOverride `json:"overrides,omitempty"`
}

// V2Options 只能由当前驱动/宿主构造，时钟/根/回环目标不进入公共配置。
type V2Options struct {
	Options
	Now                    time.Time
	PermitTestCertificates bool
	ObfsTargets            map[string]ObfsTarget
	OutboundPolicy         *OutboundPolicy
}

func (V2Materials) String() string         { return "V2Materials{[REDACTED]}" }
func (V2Materials) GoString() string       { return "xrayconfig.V2Materials{[REDACTED]}" }
func (ProfileMaterials) String() string    { return "ProfileMaterials{[REDACTED]}" }
func (ProfileMaterials) GoString() string  { return "xrayconfig.ProfileMaterials{[REDACTED]}" }
func (TLSMaterials) String() string        { return "TLSMaterials{[REDACTED]}" }
func (TLSMaterials) GoString() string      { return "xrayconfig.TLSMaterials{[REDACTED]}" }
func (HysteriaMaterials) String() string   { return "HysteriaMaterials{[REDACTED]}" }
func (HysteriaMaterials) GoString() string { return "xrayconfig.HysteriaMaterials{[REDACTED]}" }
func (SS2022Materials) String() string     { return "SS2022Materials{[REDACTED]}" }
func (SS2022Materials) GoString() string   { return "xrayconfig.SS2022Materials{[REDACTED]}" }

// 日志走同一脱敏值；JSON 序列化直接拒绝，不让 byte slice 自动编码成秘密字符串。
func redactedMaterialLog() slog.Value                  { return slog.StringValue("[REDACTED]") }
func (V2Materials) LogValue() slog.Value               { return redactedMaterialLog() }
func (ProfileMaterials) LogValue() slog.Value          { return redactedMaterialLog() }
func (TLSMaterials) LogValue() slog.Value              { return redactedMaterialLog() }
func (HysteriaMaterials) LogValue() slog.Value         { return redactedMaterialLog() }
func (SS2022Materials) LogValue() slog.Value           { return redactedMaterialLog() }
func (V2Materials) MarshalJSON() ([]byte, error)       { return nil, errMaterialSerialization }
func (ProfileMaterials) MarshalJSON() ([]byte, error)  { return nil, errMaterialSerialization }
func (TLSMaterials) MarshalJSON() ([]byte, error)      { return nil, errMaterialSerialization }
func (HysteriaMaterials) MarshalJSON() ([]byte, error) { return nil, errMaterialSerialization }
func (SS2022Materials) MarshalJSON() ([]byte, error)   { return nil, errMaterialSerialization }

func clearMaterialMap(values map[string][]byte) {
	for id, value := range values {
		clear(value)
		delete(values, id)
	}
}

// Clear 清理调用方拥有的全部短期材料；Render不会替调用方修改缓冲区。
func (materials *V2Materials) Clear() {
	if materials == nil {
		return
	}
	for id, profile := range materials.Profiles {
		if profile.VLESS != nil {
			profile.VLESS.Clear()
		}
		if profile.Hysteria2 != nil {
			clearMaterialMap(profile.Hysteria2.Auth)
			profile.Hysteria2.TLS.Material.Clear()
		}
		if profile.Shadowsocks2022 != nil {
			clear(profile.Shadowsocks2022.ServerKey)
			profile.Shadowsocks2022.ServerKey = nil
			clearMaterialMap(profile.Shadowsocks2022.PSKs)
		}
		delete(materials.Profiles, id)
	}
}
