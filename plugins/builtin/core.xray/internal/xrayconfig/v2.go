// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	corev1 "github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 三协议共享原生骨架与独立适配器 ========================

const (
	// ObfsBridgePortBase 是受控 simple-obfs 回环转发端口池起始值（30000..30999）。
	ObfsBridgePortBase = 30000
	// MaxObfsBridgePorts 是受控回环桥接端口池上限。
	MaxObfsBridgePorts = 1000
)

// DeriveRealityPublicKey 从 Xray REALITY Base64URL/Std 32 字节私钥确定性派生 X25519 公钥（B-X1）。
func DeriveRealityPublicKey(privKeyEncoded string) (string, error) {
	trimmed := strings.TrimSpace(privKeyEncoded)
	raw, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return "", fmt.Errorf("xrayconfig: invalid base64 reality private key")
		}
	}
	defer clear(raw)
	if len(raw) != 32 {
		return "", fmt.Errorf("xrayconfig: reality private key must be 32 bytes")
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("xrayconfig: invalid X25519 private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// AllocateObfsTargets 为开启 simple-obfs 的 SS2022 profile 确定性分配 127.0.0.1:30000..30999 回环目标。
// 自动避开所有 profile 已声明的外部端口，避免同机冲突。
func AllocateObfsTargets(intent *corev2.Intent) map[string]ObfsTarget {
	if intent == nil {
		return nil
	}
	usedPorts := make(map[int]bool, len(intent.Profiles))
	for _, p := range intent.Profiles {
		usedPorts[p.Port] = true
	}
	profiles := slices.Clone(intent.Profiles)
	slices.SortFunc(profiles, func(a, b corev2.Profile) int { return strings.Compare(a.ID, b.ID) })

	var targets map[string]ObfsTarget
	nextPort := ObfsBridgePortBase
	for _, p := range profiles {
		if p.Protocol != corev2.ProtocolShadowsocks2022 || p.Shadowsocks2022 == nil ||
			p.Shadowsocks2022.Obfs == nil || p.Shadowsocks2022.Obfs.Mode == corev2.ObfsNone {
			continue
		}
		for usedPorts[nextPort] && nextPort < ObfsBridgePortBase+MaxObfsBridgePorts {
			nextPort++
		}
		if nextPort >= ObfsBridgePortBase+MaxObfsBridgePorts {
			break
		}
		if targets == nil {
			targets = make(map[string]ObfsTarget)
		}
		targets[p.ID] = ObfsTarget{Listen: "127.0.0.1", Port: nextPort}
		usedPorts[nextPort] = true
		nextPort++
	}
	return targets
}

// ValidWireGuardKey 校验 32 字节标准/无填充 Base64 WireGuard 私钥或公钥。
func ValidWireGuardKey(value []byte) bool {
	trimmed := strings.TrimSpace(string(value))
	if len(trimmed) != 44 && len(trimmed) != 43 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	defer clear(decoded)
	return err == nil && len(decoded) == 32
}

// RenderV2 是完整候选的纯渲染；未启用profile仍校验形状/材料，但不创建监听。
// 顶层enabled=false保留其enabled profiles的预检候选，实际启动由Apply决定。
func RenderV2(intent *corev2.Intent, materials V2Materials, options V2Options) ([]byte, error) {
	if err := corev2.Validate(intent); err != nil {
		return nil, err
	}
	if !ValidSocket(options.APISocket) {
		return nil, ErrSocket
	}
	if _, err := planObfs(intent, options); err != nil {
		return nil, err
	}
	if len(materials.Profiles) != len(intent.Profiles) {
		return nil, ErrV2Materials
	}
	if intent.WARP != nil {
		if materials.WARP == nil || !ValidWireGuardKey(materials.WARP.PrivateKey) {
			return nil, ErrV2Materials
		}
	}
	profiles := slices.Clone(intent.Profiles)
	slices.SortFunc(profiles, func(left, right corev2.Profile) int { return strings.Compare(left.ID, right.ID) })
	inbounds := make([]nativeInbound, 0, len(profiles))
	enabledTagsByProfile := make(map[string]string, len(profiles))
	allEnabledTags := make([]string, 0, len(profiles))
	needSniff := intent.WARP != nil && intent.WARP.Enabled && intent.WARP.RoutingMode == corev2.WARPRoutingDomains
	type markedUser struct {
		mark  uint32
		email string
	}
	var markedUsers []markedUser
	for _, profile := range profiles {
		material, found := materials.Profiles[profile.ID]
		if !found {
			return nil, ErrV2Materials
		}
		var inbound nativeInbound
		var err error
		switch profile.Protocol {
		case corev2.ProtocolVLESS:
			if material.VLESS == nil || material.Hysteria2 != nil || material.Shadowsocks2022 != nil {
				return nil, ErrV2Materials
			}
			inbound, err = vlessInbound(projectVLESS(profile, intent.Outbound), *material.VLESS)
		case corev2.ProtocolHysteria2:
			if material.Hysteria2 == nil || material.VLESS != nil || material.Shadowsocks2022 != nil {
				return nil, ErrV2Materials
			}
			inbound, err = hysteriaInbound(profile, *material.Hysteria2, options)
		case corev2.ProtocolShadowsocks2022:
			if material.Shadowsocks2022 == nil || material.VLESS != nil || material.Hysteria2 != nil {
				return nil, ErrV2Materials
			}
			inbound, err = ss2022Inbound(profile, *material.Shadowsocks2022, options)
		}
		if err != nil {
			return nil, err
		}
		if *profile.Enabled {
			if needSniff {
				inbound.Sniffing = &nativeSniffing{
					Enabled:      true,
					DestOverride: []string{"http", "tls", "quic"},
					RouteOnly:    true,
				}
			}
			inbounds = append(inbounds, inbound)
			enabledTagsByProfile[profile.ID] = inbound.Tag
			allEnabledTags = append(allEnabledTags, inbound.Tag)
			for _, u := range profile.Users {
				if u.TrafficMark != 0 {
					email, eerr := corev1.UserEmail(u.ID)
					if eerr != nil {
						return nil, eerr
					}
					markedUsers = append(markedUsers, markedUser{mark: u.TrafficMark, email: email})
				}
			}
		}
	}
	cfg := baseNativeConfig(inbounds, options.Options)
	defaultStrategy := ""
	primarySendThrough := ""
	if options.OutboundPolicy != nil {
		defaultStrategy = xrayDomainStrategy(options.OutboundPolicy.DefaultMode)
		switch options.OutboundPolicy.DefaultMode {
		case FamilyIPv4Only:
			primarySendThrough = options.OutboundPolicy.BindIPv4
		case FamilyIPv6Only:
			primarySendThrough = options.OutboundPolicy.BindIPv6
		}
		cfg.Outbounds = []nativeOutbound{
			makeFreedomOutbound("qwq-direct", defaultStrategy, primarySendThrough, 0),
			makeFreedomOutbound("direct-v4", "UseIPv4", options.OutboundPolicy.BindIPv4, 0),
			makeFreedomOutbound("direct-v6", "UseIPv6", options.OutboundPolicy.BindIPv6, 0),
			{Tag: "blocked-private", Protocol: "blackhole", Settings: struct{}{}},
		}
		cfg.Routing.DomainStrategy = "AsIs"
		for _, ov := range options.OutboundPolicy.Overrides {
			sfx := strings.TrimSpace(strings.TrimPrefix(ov.DomainSuffix, "."))
			if sfx == "" {
				continue
			}
			targetTag := "qwq-direct"
			if ov.Mode == FamilyIPv4Only {
				targetTag = "direct-v4"
			} else if ov.Mode == FamilyIPv6Only {
				targetTag = "direct-v6"
			}
			cfg.Routing.Rules = append(cfg.Routing.Rules, nativeRule{
				Type:        "field",
				Domain:      []string{"domain:" + sfx},
				OutboundTag: targetTag,
			})
		}
	}
	if intent.WARP != nil && intent.WARP.Enabled && materials.WARP != nil {
		appendWARPOutboundAndRules(&cfg, intent.WARP, materials.WARP.PrivateKey, enabledTagsByProfile, allEnabledTags)
	}
	if len(markedUsers) > 0 {
		slices.SortFunc(markedUsers, func(a, b markedUser) int {
			if a.mark < b.mark {
				return -1
			}
			if a.mark > b.mark {
				return 1
			}
			return strings.Compare(a.email, b.email)
		})
		for _, mu := range markedUsers {
			tag := fmt.Sprintf("direct-mark-%d", mu.mark)
			cfg.Outbounds = append(cfg.Outbounds, makeFreedomOutbound(tag, defaultStrategy, primarySendThrough, mu.mark))
			cfg.Routing.Rules = append(cfg.Routing.Rules, nativeRule{
				Type:        "field",
				User:        []string{mu.email},
				OutboundTag: tag,
			})
		}
	}
	return encodeNativeConfig(cfg)
}

func xrayDomainStrategy(mode OutboundFamilyMode) string {
	switch mode {
	case FamilyIPv4Only:
		return "UseIPv4"
	case FamilyIPv6Only:
		return "UseIPv6"
	case FamilyPreferIPv6:
		return "UseIPv6v4"
	default:
		return "UseIPv4v6"
	}
}

func makeFreedomOutbound(tag, strategy, sendThrough string, mark uint32) nativeOutbound {
	var settings any = struct{}{}
	if strategy != "" {
		settings = nativeFreedomSettings{DomainStrategy: strategy}
	}
	ob := nativeOutbound{
		Tag:         tag,
		Protocol:    "freedom",
		SendThrough: sendThrough,
		Settings:    settings,
	}
	if mark != 0 {
		ob.Stream = &nativeOutboundStream{
			Sockopt: &nativeSockopt{Mark: mark},
		}
	}
	return ob
}

func appendWARPOutboundAndRules(
	cfg *nativeConfig,
	warp *corev2.WARPOutbound,
	privateKey []byte,
	enabledTagsByProfile map[string]string,
	allEnabledTags []string,
) {
	addrs := []string{ensureCIDR(warp.AddressV4, "/32")}
	if strings.TrimSpace(warp.AddressV6) != "" {
		addrs = append(addrs, ensureCIDR(warp.AddressV6, "/128"))
	}
	mtu := warp.MTU
	if mtu <= 0 {
		mtu = corev2.DefaultWARPMTU
	}
	cfg.Outbounds = append(cfg.Outbounds, nativeOutbound{
		Tag:      "qwq-warp",
		Protocol: "wireguard",
		Settings: nativeWireGuardSettings{
			SecretKey: strings.TrimSpace(string(privateKey)),
			Address:   addrs,
			Peers: []nativeWireGuardPeer{{
				PublicKey: strings.TrimSpace(warp.PeerPublicKey),
				Endpoint:  strings.TrimSpace(warp.Endpoint),
			}},
			Reserved:   slices.Clone(warp.Reserved),
			MTU:        mtu,
			KernelMode: false,
		},
	})
	if cfg.Routing.DomainStrategy == "" {
		cfg.Routing.DomainStrategy = "AsIs"
	}
	// 内网与回环地址始终直连，防止管理访问或本机回环流量误入 WARP。
	cfg.Routing.Rules = append(cfg.Routing.Rules, nativeRule{
		Type:        "field",
		IP:          []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"},
		OutboundTag: "qwq-direct",
	})

	boundTags := make([]string, 0, len(warp.BoundProfileIDs))
	for _, pid := range warp.BoundProfileIDs {
		if tag, ok := enabledTagsByProfile[pid]; ok {
			boundTags = append(boundTags, tag)
		}
	}
	slices.Sort(boundTags)

	switch warp.RoutingMode {
	case corev2.WARPRoutingBoundPorts:
		if len(boundTags) > 0 {
			cfg.Routing.Rules = append(cfg.Routing.Rules, nativeRule{
				Type:        "field",
				InboundTags: boundTags,
				OutboundTag: "qwq-warp",
			})
		}
	case corev2.WARPRoutingDomains:
		doms := make([]string, 0, len(warp.Domains))
		for _, d := range warp.Domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if !strings.Contains(d, ":") {
				d = "domain:" + strings.TrimPrefix(d, ".")
			}
			doms = append(doms, d)
		}
		if len(doms) > 0 {
			rule := nativeRule{
				Type:        "field",
				Domain:      doms,
				OutboundTag: "qwq-warp",
			}
			if len(boundTags) > 0 {
				rule.InboundTags = boundTags
			} else if len(allEnabledTags) > 0 {
				rule.InboundTags = slices.Clone(allEnabledTags)
			}
			cfg.Routing.Rules = append(cfg.Routing.Rules, rule)
		}
	case corev2.WARPRoutingAll:
		if len(allEnabledTags) > 0 {
			cfg.Routing.Rules = append(cfg.Routing.Rules, nativeRule{
				Type:        "field",
				InboundTags: slices.Clone(allEnabledTags),
				OutboundTag: "qwq-warp",
			})
		}
	}
}

func ensureCIDR(addr, suffix string) string {
	addr = strings.TrimSpace(addr)
	if strings.Contains(addr, "/") {
		return addr
	}
	return addr + suffix
}

func projectVLESS(profile corev2.Profile, outbound *corev2.Outbound) *corev1.Intent {
	enabled := *profile.Enabled
	users := make([]corev1.User, len(profile.Users))
	for index, user := range profile.Users {
		users[index] = corev1.User{ID: user.ID, UUID: *user.UUID}
	}
	return &corev1.Intent{SchemaVersion: "1", Enabled: &enabled, Outbound: outbound, Inbound: &corev1.Inbound{
		ID: profile.ID, Listen: profile.Listen, Port: profile.Port, Protocol: "vless", Transport: profile.VLESS.Transport, Flow: profile.VLESS.Flow, Security: profile.VLESS.Security, Users: users}}
}

func ss2022Inbound(profile corev2.Profile, materials SS2022Materials, options V2Options) (nativeInbound, error) {
	users, err := ss2022Users(profile, materials)
	if err != nil {
		return nativeInbound{}, err
	}
	tag, err := corev1.InboundTag(profile.ID)
	if err != nil {
		return nativeInbound{}, err
	}
	listen, port := profile.Listen, profile.Port
	if profile.Shadowsocks2022.Obfs.Mode != corev2.ObfsNone {
		// RenderV2 已将外层和内部目标一起校验，不能在这里另选端口。
		target := options.ObfsTargets[profile.ID]
		listen, port = target.Listen, target.Port
	}
	network := "tcp"
	if profile.Shadowsocks2022.UDP {
		network = "tcp,udp"
	}
	return nativeInbound{Tag: tag, Listen: listen, Port: &port, Protocol: "shadowsocks", Settings: ss2022Settings{Method: profile.Shadowsocks2022.Method, Password: string(materials.ServerKey), Users: users, Network: network}}, nil
}
