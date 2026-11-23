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
	var markedUsers []struct {
		Mark  uint32
		Email string
	}
	for _, profile := range profiles {
		material, found := materials.Profiles[profile.ID]
		if !found {
			return nil, ErrV2Materials
		}
		var inbound nativeInbound
		var err error
		emitToXray := true
		if !profileMaterialsMatchProtocol(profile.Protocol, material) {
			return nil, ErrV2Materials
		}
		switch profile.Protocol {
		case corev2.ProtocolVLESS:
			inbound, err = vlessV2Inbound(profile, *material.VLESS, material.VLESSTLS, material.VLESSDecryption, options)
		case corev2.ProtocolVMess:
			inbound, err = vmessInbound(profile, *material.VMess, options)
		case corev2.ProtocolTrojan:
			inbound, err = trojanInbound(profile, *material.Trojan, options)
		case corev2.ProtocolShadowsocks:
			inbound, err = ssAEADInbound(profile, *material.Shadowsocks)
		case corev2.ProtocolHysteria2:
			inbound, err = hysteriaInbound(profile, *material.Hysteria2, options)
		case corev2.ProtocolShadowsocks2022:
			inbound, err = ss2022Inbound(profile, *material.Shadowsocks2022, options)
		case corev2.ProtocolAnyTLS:
			// AnyTLS 由内建纯 Go AnyTLSSupervisor 承载，不写入 Xray 原生 inbounds，但仍严格核验材料与 TLS 绑定。
			emitToXray = false
			err = validateAnyTLSMaterials(profile, *material.AnyTLS, options)
		case corev2.ProtocolSOCKS5:
			inbound, err = socks5Inbound(profile, *material.SOCKS5)
		case corev2.ProtocolHTTP:
			inbound, err = httpInbound(profile, *material.HTTP)
		default:
			return nil, ErrV2Materials
		}
		if err != nil {
			return nil, err
		}
		if *profile.Enabled && emitToXray {
			if needSniff || profileWantsSniffing(profile) {
				inbound.Sniffing = &nativeSniffing{
					Enabled:      true,
					DestOverride: []string{"http", "tls", "quic"},
					RouteOnly:    needSniff && !profileWantsSniffing(profile),
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
					markedUsers = append(markedUsers, struct {
						Mark  uint32
						Email string
					}{Mark: u.TrafficMark, Email: email})
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
	BuildDeduplicatedMarkedOutbounds(&cfg, markedUsers, defaultStrategy, primarySendThrough)
	EnsurePrivateBlackholeProtection(&cfg)
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
		cfg.Routing.DomainStrategy = "IPIfNonMatch"
	}

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

func profileMaterialsMatchProtocol(protocol string, m ProfileMaterials) bool {
	present := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	count := present(m.VLESS != nil) + present(m.VMess != nil) + present(m.Trojan != nil) +
		present(m.Shadowsocks != nil) + present(m.Shadowsocks2022 != nil) +
		present(m.Hysteria2 != nil) + present(m.AnyTLS != nil) +
		present(m.SOCKS5 != nil) + present(m.HTTP != nil)
	if count != 1 {
		return false
	}
	if protocol != corev2.ProtocolVLESS && (m.VLESSTLS != nil || len(m.VLESSDecryption) != 0) {
		return false
	}
	switch protocol {
	case corev2.ProtocolVLESS:
		return m.VLESS != nil
	case corev2.ProtocolVMess:
		return m.VMess != nil
	case corev2.ProtocolTrojan:
		return m.Trojan != nil
	case corev2.ProtocolShadowsocks:
		return m.Shadowsocks != nil
	case corev2.ProtocolShadowsocks2022:
		return m.Shadowsocks2022 != nil
	case corev2.ProtocolHysteria2:
		return m.Hysteria2 != nil
	case corev2.ProtocolAnyTLS:
		return m.AnyTLS != nil
	case corev2.ProtocolSOCKS5:
		return m.SOCKS5 != nil
	case corev2.ProtocolHTTP:
		return m.HTTP != nil
	default:
		return false
	}
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
	// Xray-core v26 中 2022-blake3-chacha20-poly1305 为单用户服务端模式（不含 users 字段）。
	if profile.Shadowsocks2022.Method == corev2.MethodChaCha20 {
		email := ""
		if len(users) > 0 {
			email = users[0].Email
		}
		return nativeInbound{
			Tag:      tag,
			Listen:   listen,
			Port:     &port,
			Protocol: "shadowsocks",
			Settings: ss2022SingleSettings{
				Method:   profile.Shadowsocks2022.Method,
				Password: string(materials.ServerKey),
				Email:    email,
				Level:    0,
				Network:  network,
			},
		}, nil
	}
	return nativeInbound{Tag: tag, Listen: listen, Port: &port, Protocol: "shadowsocks", Settings: ss2022Settings{Method: profile.Shadowsocks2022.Method, Password: string(materials.ServerKey), Users: users, Network: network}}, nil
}
