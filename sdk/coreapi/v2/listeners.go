// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"net/netip"
	"strconv"

	v1 "github.com/qwq-panel/qwq/sdk/coreapi"
	"github.com/qwq-panel/qwq/sdk/internal/strictjson"
)

// Listener 是宿主预演可消费的外部监听声明，不包含驱动内部转发端口。
type Listener struct {
	ProfileID string `json:"profile_id"`
	Network   string `json:"network"`
	Listen    string `json:"listen"`
	Port      int    `json:"port"`
}

// Listeners 返回有效快照中实际启用的声明；协议可用性与端口可达性仍需运行门禁。
func Listeners(intent *Intent) ([]Listener, error) {
	if err := Validate(intent); err != nil {
		return nil, err
	}
	out := make([]Listener, 0, 2*len(intent.Profiles))
	if !*intent.Enabled {
		return out, nil
	}
	for index := range intent.Profiles {
		out = append(out, profileListeners(&intent.Profiles[index])...)
	}
	return out, nil
}

func profileListeners(profile *Profile) []Listener {
	if profile.Enabled == nil || !*profile.Enabled {
		return nil
	}
	var networks []string
	switch profile.Protocol {
	case ProtocolVLESS, ProtocolVMess, ProtocolTrojan, ProtocolAnyTLS, ProtocolSOCKS5, ProtocolHTTP:
		networks = []string{"tcp"}
	case ProtocolHysteria2:
		networks = []string{"udp"}
	case ProtocolShadowsocks:
		networks = []string{"tcp"}
		if profile.Shadowsocks != nil && profile.Shadowsocks.UDP {
			networks = append(networks, "udp")
		}
	case ProtocolShadowsocks2022:
		networks = []string{"tcp"}
		if profile.Shadowsocks2022 != nil && profile.Shadowsocks2022.UDP {
			networks = append(networks, "udp")
		}
	}
	out := make([]Listener, 0, len(networks))
	for _, network := range networks {
		out = append(out, Listener{ProfileID: profile.ID, Network: network, Listen: profile.Listen, Port: profile.Port})
	}
	return out
}

// ======================== 分传输的监听占用 ========================
type listenerClaim struct {
	network string
	addr    netip.Addr
	port    int
}

// CheckListenerConflicts 将公开外层和驱动内部监听交给同一地址族规则校验。
// 同一 profile 的 TCP/UDP 或不同端口可共存；:: 按可能双栈保守判定。
func CheckListenerConflicts(listeners []Listener) error {
	if len(listeners) > 3*MaxProfiles {
		return invalid("/listeners", "SIZE", "外层与内部监听数量超过上限")
	}
	claims := make([]listenerClaim, 0, len(listeners))
	for index, listener := range listeners {
		path := strictjson.Pointer("/listeners", strconv.Itoa(index))
		if !v1.ValidID(listener.ProfileID) {
			return invalid(path+"/profile_id", "ID", "监听必须关联有效 profile")
		}
		if listener.Network != "tcp" && listener.Network != "udp" {
			return invalid(path+"/network", "ENUM", "监听传输必须是 tcp 或 udp")
		}
		addr, valid := validListen(listener.Listen)
		if !valid {
			return invalid(path+"/listen", "IP", "监听地址必须是无 zone 的 IPv4 或 IPv6")
		}
		if listener.Port < 1 || listener.Port > 65535 {
			return invalid(path+"/port", "RANGE", "监听端口必须在 1 至 65535 之间")
		}
		next := listenerClaim{network: listener.Network, addr: addr, port: listener.Port}
		if conflicts(claims, next) {
			return invalid(path+"/port", "PORT_CONFLICT", "外层与内部监听不能重叠")
		}
		claims = append(claims, next)
	}
	return nil
}

func conflicts(claims []listenerClaim, next listenerClaim) bool {
	for _, prior := range claims {
		if next.network == prior.network && next.port == prior.port && addressesOverlap(next.addr, prior.addr) {
			return true
		}
	}
	return false
}

func (v *validator) claim(profile *Profile, path string) {
	addr, ok := validListen(profile.Listen)
	if !ok || profile.Port < 1 || profile.Port > 65535 {
		return
	}
	conflict := false
	for _, listener := range profileListeners(profile) {
		next := listenerClaim{network: listener.Network, addr: addr, port: listener.Port}
		conflict = conflict || conflicts(v.ports, next)
		v.ports = append(v.ports, next)
	}
	v.require(!conflict, path+"/port", "PORT_CONFLICT", "已启用 profiles 的同传输监听不能重叠")
}

func addressesOverlap(a, b netip.Addr) bool {
	a, b = a.Unmap(), b.Unmap()
	// :: 可能双栈绑定；不依赖当前机器 IPV6_V6ONLY 默认值。
	if a.Is6() && a.IsUnspecified() || b.Is6() && b.IsUnspecified() {
		return true
	}
	if a.Is4() != b.Is4() {
		return false
	}
	return a.IsUnspecified() || b.IsUnspecified() || a == b
}
