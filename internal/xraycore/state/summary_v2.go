// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/xraycore/xrayconfig"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== Core Intent v2 无秘密运行摘要 ========================

// PublicProfileSummary 是单个 v2 profile 的公开投影，不含任何秘密值或秘密引用 ID。
type PublicProfileSummary struct {
	ID             string   `json:"id"`
	Enabled        bool     `json:"enabled"`
	Listen         string   `json:"listen"`
	Port           int      `json:"port"`
	Protocol       string   `json:"protocol"`
	Transport      string   `json:"transport,omitempty"`
	SecurityMode   string   `json:"security_mode,omitempty"`
	ServerName     string   `json:"server_name,omitempty"`
	BindingRef     string   `json:"binding_ref,omitempty"`
	Method         string   `json:"method,omitempty"`
	ObfsMode       string   `json:"obfs_mode,omitempty"`
	ObfsHost       string   `json:"obfs_host,omitempty"`
	ObfsBridgePort int      `json:"obfs_bridge_port,omitempty"`
	UDP            bool     `json:"udp,omitempty"`
	UserIDs        []string `json:"user_ids"`
}

// V2IntentSummary 保存 v2 期望配置的公开投影与不可逆引用摘要，用于幂等判定与 Plan 预演。
type V2IntentSummary struct {
	SchemaVersion string                 `json:"schema_version"`
	OutboundType  string                 `json:"outbound_type"`
	Profiles      []PublicProfileSummary `json:"profiles"`
	RefsDigest    string                 `json:"refs_digest"`
}

// SummarizeV2 在纯校验后构造规范排序的 v2 摘要，顺序变化不影响等价判定。
func SummarizeV2(intent *corev2.Intent) (*V2IntentSummary, error) {
	if err := corev2.Validate(intent); err != nil {
		return nil, err
	}
	profiles := slices.Clone(intent.Profiles)
	slices.SortFunc(profiles, func(a, b corev2.Profile) int { return strings.Compare(a.ID, b.ID) })
	obfsTargets := xrayconfig.AllocateObfsTargets(intent)

	refsHash := sha256.New()
	_, _ = io.WriteString(refsHash, "v2\x00"+intent.Outbound.Type+"\x00")
	out := make([]PublicProfileSummary, 0, len(profiles))
	for _, p := range profiles {
		users := slices.Clone(p.Users)
		slices.SortFunc(users, func(a, b corev2.User) int { return strings.Compare(a.ID, b.ID) })
		userIDs := make([]string, 0, len(users))

		ps := PublicProfileSummary{
			ID:       p.ID,
			Enabled:  *p.Enabled,
			Listen:   p.Listen,
			Port:     p.Port,
			Protocol: p.Protocol,
		}
		_, _ = io.WriteString(refsHash, p.ID+"\x00"+p.Protocol+"\x00"+p.Listen+"\x00"+strconv.Itoa(p.Port)+"\x00")
		if *p.Enabled {
			_, _ = io.WriteString(refsHash, "1\x00")
		} else {
			_, _ = io.WriteString(refsHash, "0\x00")
		}

		hashReality := func(r *corev2.Reality) {
			if r == nil {
				return
			}
			_, _ = io.WriteString(refsHash, r.Target+"\x00"+r.PrivateKey.ID+"\x00")
			sniList := slices.Clone(r.ServerNames)
			slices.Sort(sniList)
			for _, s := range sniList {
				_, _ = io.WriteString(refsHash, s+"\x00")
			}
			shortIDs := slices.Clone(r.ShortIDs)
			slices.Sort(shortIDs)
			for _, sid := range shortIDs {
				_, _ = io.WriteString(refsHash, sid+"\x00")
			}
		}
		hashTLS := func(t *corev2.TLSBinding) {
			if t == nil {
				return
			}
			ps.BindingRef = t.BindingRef
			ps.ServerName = t.ServerName
			_, _ = io.WriteString(refsHash, t.BindingRef+"\x00"+t.ServerName+"\x00")
		}
		hashOptBool := func(b *bool) {
			if b == nil {
				_, _ = io.WriteString(refsHash, "nil\x00")
			} else if *b {
				_, _ = io.WriteString(refsHash, "true\x00")
			} else {
				_, _ = io.WriteString(refsHash, "false\x00")
			}
		}

		switch p.Protocol {
		case corev2.ProtocolVLESS:
			if p.VLESS != nil {
				ps.Transport = p.VLESS.NormalizedTransport()
				ps.SecurityMode = p.VLESS.EffectiveSecurityMode()
				_, _ = io.WriteString(refsHash, ps.Transport+"\x00"+p.VLESS.Flow+"\x00"+ps.SecurityMode+"\x00"+
					p.VLESS.Path+"\x00"+p.VLESS.Host+"\x00"+p.VLESS.ServiceName+"\x00"+p.VLESS.XHTTPMode+"\x00"+p.VLESS.Encryption+"\x00")
				if p.VLESS.Decryption != nil {
					_, _ = io.WriteString(refsHash, p.VLESS.Decryption.ID+"\x00")
				}
				hashOptBool(p.VLESS.Sniffing)
				hashReality(p.VLESS.Security)
				hashTLS(p.VLESS.TLS)
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.UUID != nil {
					_, _ = io.WriteString(refsHash, u.UUID.ID+"\x00")
				}
			}
		case corev2.ProtocolVMess:
			if p.VMess != nil {
				ps.Transport = p.VMess.NormalizedTransport()
				ps.SecurityMode = p.VMess.SecurityMode
				_, _ = io.WriteString(refsHash, ps.Transport+"\x00"+ps.SecurityMode+"\x00"+
					p.VMess.Path+"\x00"+p.VMess.Host+"\x00"+p.VMess.ServiceName+"\x00")
				hashOptBool(p.VMess.Sniffing)
				hashTLS(p.VMess.TLS)
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.UUID != nil {
					_, _ = io.WriteString(refsHash, u.UUID.ID+"\x00")
				}
			}
		case corev2.ProtocolTrojan:
			if p.Trojan != nil {
				ps.Transport = p.Trojan.NormalizedTransport()
				ps.SecurityMode = p.Trojan.SecurityMode
				_, _ = io.WriteString(refsHash, ps.Transport+"\x00"+ps.SecurityMode+"\x00"+
					p.Trojan.Path+"\x00"+p.Trojan.Host+"\x00"+p.Trojan.ServiceName+"\x00")
				hashOptBool(p.Trojan.Sniffing)
				hashTLS(p.Trojan.TLS)
				hashReality(p.Trojan.Reality)
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.Auth != nil {
					_, _ = io.WriteString(refsHash, u.Auth.ID+"\x00")
				}
			}
		case corev2.ProtocolShadowsocks:
			if p.Shadowsocks != nil {
				ps.Method = p.Shadowsocks.Method
				ps.UDP = p.Shadowsocks.UDP
				_, _ = io.WriteString(refsHash, p.Shadowsocks.Method+"\x00"+strconv.FormatBool(p.Shadowsocks.UDP)+"\x00")
				hashOptBool(p.Shadowsocks.Sniffing)
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.Auth != nil {
					_, _ = io.WriteString(refsHash, u.Auth.ID+"\x00")
				}
			}
		case corev2.ProtocolHysteria2:
			if p.Hysteria2 != nil {
				hashTLS(p.Hysteria2.TLS)
				if p.Hysteria2.ObfsPassword != nil {
					_, _ = io.WriteString(refsHash, p.Hysteria2.ObfsPassword.ID+"\x00")
				}
				_, _ = io.WriteString(refsHash, p.Hysteria2.PortHopping+"\x00")
				hashOptBool(p.Hysteria2.Sniffing)
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.Auth != nil {
					_, _ = io.WriteString(refsHash, u.Auth.ID+"\x00")
				}
			}
		case corev2.ProtocolShadowsocks2022:
			if p.Shadowsocks2022 != nil {
				ps.Method = p.Shadowsocks2022.Method
				ps.UDP = p.Shadowsocks2022.UDP
				_, _ = io.WriteString(refsHash, p.Shadowsocks2022.Method+"\x00"+p.Shadowsocks2022.ServerKey.ID+"\x00"+strconv.FormatBool(p.Shadowsocks2022.UDP)+"\x00")
				hashOptBool(p.Shadowsocks2022.Sniffing)
				if p.Shadowsocks2022.Obfs != nil {
					ps.ObfsMode = p.Shadowsocks2022.Obfs.Mode
					ps.ObfsHost = p.Shadowsocks2022.Obfs.Host
					if target, ok := obfsTargets[p.ID]; ok {
						ps.ObfsBridgePort = target.Port
					}
					_, _ = io.WriteString(refsHash, p.Shadowsocks2022.Obfs.Mode+"\x00"+p.Shadowsocks2022.Obfs.Host+"\x00")
				}
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.PSK != nil {
					_, _ = io.WriteString(refsHash, u.PSK.ID+"\x00")
				}
			}
		case corev2.ProtocolAnyTLS:
			if p.AnyTLS != nil {
				ps.SecurityMode = "tls"
				hashTLS(p.AnyTLS.TLS)
				for _, line := range p.AnyTLS.PaddingScheme {
					_, _ = io.WriteString(refsHash, line+"\x00")
				}
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.Auth != nil {
					_, _ = io.WriteString(refsHash, u.Auth.ID+"\x00")
				}
			}
		case corev2.ProtocolSOCKS5:
			if p.SOCKS5 != nil {
				ps.UDP = p.SOCKS5.UDP
				_, _ = io.WriteString(refsHash, strconv.FormatBool(p.SOCKS5.UDP)+"\x00")
				hashOptBool(p.SOCKS5.Sniffing)
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+u.Username+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.Auth != nil {
					_, _ = io.WriteString(refsHash, u.Auth.ID+"\x00")
				}
			}
		case corev2.ProtocolHTTP:
			if p.HTTP != nil {
				hashOptBool(p.HTTP.Sniffing)
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+u.Username+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.Auth != nil {
					_, _ = io.WriteString(refsHash, u.Auth.ID+"\x00")
				}
			}
		}
		ps.UserIDs = userIDs
		out = append(out, ps)
	}
	if intent.WARP != nil {
		w := intent.WARP
		_, _ = io.WriteString(refsHash, "warp\x00"+strconv.FormatBool(w.Enabled)+"\x00"+w.PrivateKey.ID+"\x00"+
			w.PeerPublicKey+"\x00"+w.Endpoint+"\x00"+w.AddressV4+"\x00"+w.AddressV6+"\x00"+
			strconv.Itoa(w.MTU)+"\x00"+w.RoutingMode+"\x00")
		for _, b := range w.Reserved {
			_, _ = io.WriteString(refsHash, strconv.Itoa(b)+",")
		}
		_, _ = io.WriteString(refsHash, "\x00")
		bound := slices.Clone(w.BoundProfileIDs)
		slices.Sort(bound)
		for _, pid := range bound {
			_, _ = io.WriteString(refsHash, pid+"\x00")
		}
		doms := slices.Clone(w.Domains)
		slices.Sort(doms)
		for _, d := range doms {
			_, _ = io.WriteString(refsHash, d+"\x00")
		}
	}

	return &V2IntentSummary{
		SchemaVersion: "2",
		OutboundType:  intent.Outbound.Type,
		Profiles:      out,
		RefsDigest:    "sha256:" + hex.EncodeToString(refsHash.Sum(nil)),
	}, nil
}

// AllUserIDs 返回全部 profile 的去重排序用户列表，供 Plan 差异计算使用。
func (s V2IntentSummary) AllUserIDs() []string {
	seen := make(map[string]struct{})
	ids := make([]string, 0)
	for _, p := range s.Profiles {
		for _, id := range p.UserIDs {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	return ids
}

// FindHysteriaProfile 按 profileID 与 bindingRef 查找对应的 Hysteria2 profile 摘要。
func (s V2IntentSummary) FindHysteriaProfile(profileID, bindingRef string) (PublicProfileSummary, bool) {
	for _, p := range s.Profiles {
		if p.Protocol == corev2.ProtocolHysteria2 && p.ID == profileID && p.BindingRef == bindingRef {
			return p, true
		}
	}
	return PublicProfileSummary{}, false
}

// FindTLSProfile 按 profileID 与 bindingRef 查找任意使用宿主 TLS 绑定的 profile 摘要（含 Hysteria2/AnyTLS/VLESS/VMess/Trojan）。
func (s V2IntentSummary) FindTLSProfile(profileID, bindingRef string) (PublicProfileSummary, bool) {
	for _, p := range s.Profiles {
		if p.ID == profileID && p.BindingRef == bindingRef && p.BindingRef != "" {
			return p, true
		}
	}
	return PublicProfileSummary{}, false
}

// EnabledAnyTLSProfiles 返回所有启用中的 AnyTLS profile 公开摘要。
func (s V2IntentSummary) EnabledAnyTLSProfiles() []PublicProfileSummary {
	var out []PublicProfileSummary
	for _, p := range s.Profiles {
		if p.Enabled && p.Protocol == corev2.ProtocolAnyTLS {
			out = append(out, p)
		}
	}
	return out
}

// ObfsPlans 从持久化摘要确定性还原所有启用中的 simple-obfs 外层计划（供重启恢复与 TLS 热重载使用）。
func (s V2IntentSummary) ObfsPlans() []xrayconfig.ObfsPlan {
	var plans []xrayconfig.ObfsPlan
	for _, p := range s.Profiles {
		if !p.Enabled || p.Protocol != corev2.ProtocolShadowsocks2022 ||
			p.ObfsMode == "" || p.ObfsMode == corev2.ObfsNone || p.ObfsBridgePort <= 0 {
			continue
		}
		plans = append(plans, xrayconfig.ObfsPlan{
			ProfileID: p.ID,
			Mode:      p.ObfsMode,
			Host:      p.ObfsHost,
			External:  corev2.Listener{ProfileID: p.ID, Network: "tcp", Listen: p.Listen, Port: p.Port},
			Target:    xrayconfig.ObfsTarget{Listen: "127.0.0.1", Port: p.ObfsBridgePort},
		})
	}
	return plans
}

// Validate 约束持久化 v2 摘要的规范形状与界限。
func (s V2IntentSummary) Validate() error {
	if s.SchemaVersion != "2" || s.OutboundType != "direct" || len(s.Profiles) < 1 || len(s.Profiles) > corev2.MaxProfiles {
		return ErrCorrupt
	}
	if !ValidDigest(s.RefsDigest) {
		return ErrCorrupt
	}
	for idx, p := range s.Profiles {
		if idx > 0 && s.Profiles[idx-1].ID >= p.ID {
			return ErrCorrupt
		}
		if _, err := coreapi.InboundTag(p.ID); err != nil {
			return ErrCorrupt
		}
		if _, err := netip.ParseAddr(p.Listen); err != nil || p.Port < 1 || p.Port > 65535 {
			return ErrCorrupt
		}
		if p.ObfsBridgePort != 0 && (p.ObfsBridgePort < 1024 || p.ObfsBridgePort > 65535) {
			return ErrCorrupt
		}
		switch p.Protocol {
		case corev2.ProtocolVLESS, corev2.ProtocolVMess, corev2.ProtocolTrojan, corev2.ProtocolShadowsocks,
			corev2.ProtocolHysteria2, corev2.ProtocolShadowsocks2022, corev2.ProtocolAnyTLS,
			corev2.ProtocolSOCKS5, corev2.ProtocolHTTP:
		default:
			return ErrCorrupt
		}
		if (p.Protocol == corev2.ProtocolHysteria2 || p.Protocol == corev2.ProtocolAnyTLS) && (p.BindingRef == "" || p.ServerName == "") {
			return ErrCorrupt
		}
		if len(p.UserIDs) < 1 || len(p.UserIDs) > corev2.MaxUsers || !slices.IsSorted(p.UserIDs) {
			return ErrCorrupt
		}
		for ui, uid := range p.UserIDs {
			if _, err := coreapi.UserEmail(uid); err != nil || (ui > 0 && p.UserIDs[ui-1] == uid) {
				return ErrCorrupt
			}
		}
	}
	return nil
}
