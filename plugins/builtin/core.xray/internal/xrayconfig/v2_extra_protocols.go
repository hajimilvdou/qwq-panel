// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"slices"
	"strings"

	corev1 "github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 全协议矩阵原生入站渲染（Xray v26.11.9） ========================

func alpnForTransport(transport string) []string {
	switch transport {
	case "grpc":
		return []string{"h2"}
	case "ws":
		return []string{"http/1.1"}
	default:
		return []string{"h2", "http/1.1"}
	}
}

func applyTransportStream(stream *nativeStream, transport, path, host, serviceName, xhttpMode string) {
	switch transport {
	case "ws":
		p := path
		if p == "" {
			p = "/"
		}
		stream.WS = &nativeWS{Path: p, Host: host}
	case "grpc":
		sn := serviceName
		if sn == "" {
			sn = "grpc"
		}
		stream.GRPC = &nativeGRPC{ServiceName: sn}
	case "xhttp":
		p := path
		if p == "" {
			p = "/"
		}
		mode := xhttpMode
		if mode == "" {
			mode = "auto"
		}
		stream.XHTTP = &nativeXHTTP{Path: p, Host: host, Mode: mode}
	}
}

func vlessV2Inbound(profile corev2.Profile, secrets Secrets, tlsMat *TLSMaterials, decryption []byte, options V2Options) (nativeInbound, error) {
	cfg := profile.VLESS
	normTransport := cfg.NormalizedTransport()
	secMode := cfg.EffectiveSecurityMode()

	if len(secrets.UUIDs) != len(profile.Users) {
		return nativeInbound{}, ErrV2Materials
	}
	if cfg.Decryption != nil {
		if !ValidPasswordMaterial(decryption, 1) {
			return nativeInbound{}, ErrV2Materials
		}
	} else if len(decryption) != 0 {
		return nativeInbound{}, ErrV2Materials
	}

	stream := &nativeStream{
		Network:  normTransport,
		Security: secMode,
	}
	switch secMode {
	case "reality":
		if tlsMat != nil || !ValidPrivateKey(secrets.PrivateKey) {
			return nativeInbound{}, ErrV2Materials
		}
		stream.Reality = &nativeReality{
			Target:      cfg.Security.Target,
			ServerNames: slices.Clone(cfg.Security.ServerNames),
			PrivateKey:  string(secrets.PrivateKey),
			ShortIDs:    slices.Clone(cfg.Security.ShortIDs),
		}
	case "tls":
		if tlsMat == nil || len(secrets.PrivateKey) != 0 {
			return nativeInbound{}, ErrV2Materials
		}
		tlsObj, err := buildNativeTLS(cfg.TLS, *tlsMat, options, alpnForTransport(normTransport), "1.2")
		if err != nil {
			return nativeInbound{}, err
		}
		stream.TLS = tlsObj
	case "none":
		if tlsMat != nil || len(secrets.PrivateKey) != 0 {
			return nativeInbound{}, ErrV2Materials
		}
	default:
		return nativeInbound{}, ErrV2Materials
	}
	applyTransportStream(stream, normTransport, cfg.Path, cfg.Host, cfg.ServiceName, cfg.XHTTPMode)

	users := slices.Clone(profile.Users)
	slices.SortFunc(users, func(a, b corev2.User) int { return strings.Compare(a.ID, b.ID) })
	nativeUsers := make([]nativeUser, 0, len(users))
	seen := make(map[string]struct{}, len(users))
	for _, user := range users {
		value, exists := secrets.UUIDs[user.ID]
		if !exists || !ValidUUID(value) {
			return nativeInbound{}, ErrV2Materials
		}
		uuid := strings.ToLower(string(value))
		if _, dup := seen[uuid]; dup {
			return nativeInbound{}, ErrV2Materials
		}
		seen[uuid] = struct{}{}
		email, err := corev1.UserEmail(user.ID)
		if err != nil {
			return nativeInbound{}, err
		}
		nativeUsers = append(nativeUsers, nativeUser{ID: uuid, Email: email, Level: 0, Flow: cfg.Flow})
	}

	tag, err := corev1.InboundTag(profile.ID)
	if err != nil {
		return nativeInbound{}, err
	}
	decStr := "none"
	if len(decryption) > 0 {
		decStr = string(decryption)
	}
	port := profile.Port
	return nativeInbound{
		Tag:      tag,
		Listen:   profile.Listen,
		Port:     &port,
		Protocol: "vless",
		Settings: vlessSettings{Decryption: decStr, Users: nativeUsers},
		Stream:   stream,
	}, nil
}

func vmessInbound(profile corev2.Profile, materials VMessMaterials, options V2Options) (nativeInbound, error) {
	cfg := profile.VMess
	if len(materials.UUIDs) != len(profile.Users) {
		return nativeInbound{}, ErrV2Materials
	}
	normTransport := cfg.NormalizedTransport()
	stream := &nativeStream{
		Network:  normTransport,
		Security: cfg.SecurityMode,
	}
	switch cfg.SecurityMode {
	case "tls":
		if materials.TLS == nil {
			return nativeInbound{}, ErrV2Materials
		}
		tlsObj, err := buildNativeTLS(cfg.TLS, *materials.TLS, options, alpnForTransport(normTransport), "1.2")
		if err != nil {
			return nativeInbound{}, err
		}
		stream.TLS = tlsObj
	case "none":
		if materials.TLS != nil {
			return nativeInbound{}, ErrV2Materials
		}
	default:
		return nativeInbound{}, ErrV2Materials
	}
	applyTransportStream(stream, normTransport, cfg.Path, cfg.Host, cfg.ServiceName, "")

	users := slices.Clone(profile.Users)
	slices.SortFunc(users, func(a, b corev2.User) int { return strings.Compare(a.ID, b.ID) })
	clients := make([]vmessUser, 0, len(users))
	seen := make(map[string]struct{}, len(users))
	for _, user := range users {
		value, exists := materials.UUIDs[user.ID]
		if !exists || !ValidUUID(value) {
			return nativeInbound{}, ErrV2Materials
		}
		uuid := strings.ToLower(string(value))
		if _, dup := seen[uuid]; dup {
			return nativeInbound{}, ErrV2Materials
		}
		seen[uuid] = struct{}{}
		email, err := corev1.UserEmail(user.ID)
		if err != nil {
			return nativeInbound{}, err
		}
		clients = append(clients, vmessUser{ID: uuid, Email: email, Level: 0})
	}
	tag, err := corev1.InboundTag(profile.ID)
	if err != nil {
		return nativeInbound{}, err
	}
	port := profile.Port
	return nativeInbound{
		Tag:      tag,
		Listen:   profile.Listen,
		Port:     &port,
		Protocol: "vmess",
		Settings: vmessSettings{Clients: clients},
		Stream:   stream,
	}, nil
}

func trojanInbound(profile corev2.Profile, materials TrojanMaterials, options V2Options) (nativeInbound, error) {
	cfg := profile.Trojan
	if len(materials.Auth) != len(profile.Users) {
		return nativeInbound{}, ErrV2Materials
	}
	normTransport := cfg.NormalizedTransport()
	stream := &nativeStream{
		Network:  normTransport,
		Security: cfg.SecurityMode,
	}
	switch cfg.SecurityMode {
	case "tls":
		if materials.TLS == nil || len(materials.PrivateKey) != 0 {
			return nativeInbound{}, ErrV2Materials
		}
		tlsObj, err := buildNativeTLS(cfg.TLS, *materials.TLS, options, alpnForTransport(normTransport), "1.2")
		if err != nil {
			return nativeInbound{}, err
		}
		stream.TLS = tlsObj
	case "reality":
		if materials.TLS != nil || !ValidPrivateKey(materials.PrivateKey) {
			return nativeInbound{}, ErrV2Materials
		}
		stream.Reality = &nativeReality{
			Target:      cfg.Reality.Target,
			ServerNames: slices.Clone(cfg.Reality.ServerNames),
			PrivateKey:  string(materials.PrivateKey),
			ShortIDs:    slices.Clone(cfg.Reality.ShortIDs),
		}
	default:
		return nativeInbound{}, ErrV2Materials
	}
	applyTransportStream(stream, normTransport, cfg.Path, cfg.Host, cfg.ServiceName, "")

	users := slices.Clone(profile.Users)
	slices.SortFunc(users, func(a, b corev2.User) int { return strings.Compare(a.ID, b.ID) })
	clients := make([]trojanUser, 0, len(users))
	seen := make(map[string]struct{}, len(users))
	for _, user := range users {
		value, exists := materials.Auth[user.ID]
		if !exists || !ValidPasswordMaterial(value, 1) {
			return nativeInbound{}, ErrV2Materials
		}
		pwd := string(value)
		if _, dup := seen[pwd]; dup {
			return nativeInbound{}, ErrV2Materials
		}
		seen[pwd] = struct{}{}
		email, err := corev1.UserEmail(user.ID)
		if err != nil {
			return nativeInbound{}, err
		}
		clients = append(clients, trojanUser{Password: pwd, Email: email, Level: 0})
	}
	tag, err := corev1.InboundTag(profile.ID)
	if err != nil {
		return nativeInbound{}, err
	}
	port := profile.Port
	return nativeInbound{
		Tag:      tag,
		Listen:   profile.Listen,
		Port:     &port,
		Protocol: "trojan",
		Settings: trojanSettings{Clients: clients},
		Stream:   stream,
	}, nil
}

func ssAEADInbound(profile corev2.Profile, materials ShadowsocksMaterials) (nativeInbound, error) {
	cfg := profile.Shadowsocks
	if len(materials.Auth) != len(profile.Users) {
		return nativeInbound{}, ErrV2Materials
	}
	users := slices.Clone(profile.Users)
	slices.SortFunc(users, func(a, b corev2.User) int { return strings.Compare(a.ID, b.ID) })
	clients := make([]ssAEADUser, 0, len(users))
	seen := make(map[string]struct{}, len(users))
	for _, user := range users {
		value, exists := materials.Auth[user.ID]
		if !exists || !ValidPasswordMaterial(value, 1) {
			return nativeInbound{}, ErrV2Materials
		}
		pwd := string(value)
		if _, dup := seen[pwd]; dup {
			return nativeInbound{}, ErrV2Materials
		}
		seen[pwd] = struct{}{}
		email, err := corev1.UserEmail(user.ID)
		if err != nil {
			return nativeInbound{}, err
		}
		clients = append(clients, ssAEADUser{
			Method:   cfg.Method,
			Password: pwd,
			Email:    email,
			Level:    0,
		})
	}
	tag, err := corev1.InboundTag(profile.ID)
	if err != nil {
		return nativeInbound{}, err
	}
	network := "tcp"
	if cfg.UDP {
		network = "tcp,udp"
	}
	port := profile.Port
	return nativeInbound{
		Tag:      tag,
		Listen:   profile.Listen,
		Port:     &port,
		Protocol: "shadowsocks",
		Settings: ssAEADSettings{Clients: clients, Network: network},
	}, nil
}

func proxyAccounts(profile corev2.Profile, materials AccountMaterials) ([]proxyAccount, error) {
	if len(materials.Auth) != len(profile.Users) {
		return nil, ErrV2Materials
	}
	users := slices.Clone(profile.Users)
	slices.SortFunc(users, func(a, b corev2.User) int { return strings.Compare(a.ID, b.ID) })
	accounts := make([]proxyAccount, 0, len(users))
	seenUsers := make(map[string]struct{}, len(users))
	for _, user := range users {
		value, exists := materials.Auth[user.ID]
		if !exists || !ValidPasswordMaterial(value, 1) {
			return nil, ErrV2Materials
		}
		uname := user.Username
		if uname == "" {
			uname = user.ID
		}
		if _, dup := seenUsers[uname]; dup {
			return nil, ErrV2Materials
		}
		seenUsers[uname] = struct{}{}
		accounts = append(accounts, proxyAccount{User: uname, Pass: string(value)})
	}
	return accounts, nil
}

func socks5Inbound(profile corev2.Profile, materials AccountMaterials) (nativeInbound, error) {
	accounts, err := proxyAccounts(profile, materials)
	if err != nil {
		return nativeInbound{}, err
	}
	tag, err := corev1.InboundTag(profile.ID)
	if err != nil {
		return nativeInbound{}, err
	}
	port := profile.Port
	return nativeInbound{
		Tag:      tag,
		Listen:   profile.Listen,
		Port:     &port,
		Protocol: "socks",
		Settings: socksSettings{
			Auth:      "password",
			Accounts:  accounts,
			UDP:       profile.SOCKS5.UDP,
			UserLevel: 0,
		},
	}, nil
}

func httpInbound(profile corev2.Profile, materials AccountMaterials) (nativeInbound, error) {
	accounts, err := proxyAccounts(profile, materials)
	if err != nil {
		return nativeInbound{}, err
	}
	tag, err := corev1.InboundTag(profile.ID)
	if err != nil {
		return nativeInbound{}, err
	}
	port := profile.Port
	return nativeInbound{
		Tag:      tag,
		Listen:   profile.Listen,
		Port:     &port,
		Protocol: "http",
		Settings: httpSettings{
			Accounts:         accounts,
			AllowTransparent: false,
			UserLevel:        0,
		},
	}, nil
}

func validateAnyTLSMaterials(profile corev2.Profile, materials AnyTLSMaterials, options V2Options) error {
	if len(materials.Auth) != len(profile.Users) {
		return ErrV2Materials
	}
	seen := make(map[string]struct{}, len(profile.Users))
	for _, user := range profile.Users {
		val, found := materials.Auth[user.ID]
		if !found || !ValidPasswordMaterial(val, 1) {
			return ErrV2Materials
		}
		s := string(val)
		if _, dup := seen[s]; dup {
			return ErrV2Materials
		}
		seen[s] = struct{}{}
	}
	return validateBoundTLS(profile.AnyTLS.TLS, materials.TLS, options)
}

func profileWantsSniffing(profile corev2.Profile) bool {
	switch profile.Protocol {
	case corev2.ProtocolVLESS:
		return profile.VLESS != nil && profile.VLESS.Sniffing != nil && *profile.VLESS.Sniffing
	case corev2.ProtocolVMess:
		return profile.VMess != nil && profile.VMess.Sniffing != nil && *profile.VMess.Sniffing
	case corev2.ProtocolTrojan:
		return profile.Trojan != nil && profile.Trojan.Sniffing != nil && *profile.Trojan.Sniffing
	case corev2.ProtocolShadowsocks:
		return profile.Shadowsocks != nil && profile.Shadowsocks.Sniffing != nil && *profile.Shadowsocks.Sniffing
	case corev2.ProtocolShadowsocks2022:
		return profile.Shadowsocks2022 != nil && profile.Shadowsocks2022.Sniffing != nil && *profile.Shadowsocks2022.Sniffing
	case corev2.ProtocolHysteria2:
		return profile.Hysteria2 != nil && profile.Hysteria2.Sniffing != nil && *profile.Hysteria2.Sniffing
	case corev2.ProtocolSOCKS5:
		return profile.SOCKS5 != nil && profile.SOCKS5.Sniffing != nil && *profile.SOCKS5.Sniffing
	case corev2.ProtocolHTTP:
		return profile.HTTP != nil && profile.HTTP.Sniffing != nil && *profile.HTTP.Sniffing
	default:
		return false
	}
}
