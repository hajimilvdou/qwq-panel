// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 外部节点多协议 URI 解析（11 种协议） ========================

func decodeFlexibleBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if out, err := enc.DecodeString(s); err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 payload")
}

func parsePortStrict(raw string, fallback int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" && fallback > 0 {
		return fallback, nil
	}
	p, err := strconv.Atoi(raw)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	return p, nil
}

func parseExternalNodeURI(rawURI string) (proxyNodeRecord, error) {
	line := strings.TrimSpace(rawURI)
	if line == "" {
		return proxyNodeRecord{}, fmt.Errorf("empty uri")
	}
	schemeRaw, _, ok := strings.Cut(line, "://")
	if !ok {
		return proxyNodeRecord{}, fmt.Errorf("missing scheme")
	}
	scheme := strings.ToLower(strings.TrimSpace(schemeRaw))

	switch scheme {
	case "vmess":
		return parseVMessURI(line)
	case "ss":
		return parseShadowsocksURI(line)
	case "vless":
		return parseVLESSURI(line)
	case "trojan":
		return parseTrojanURI(line)
	case "hysteria2", "hy2":
		return parseHysteria2URI(line)
	case "anytls":
		return parseAnyTLSURI(line)
	case "socks5", "socks":
		return parseSOCKS5URI(line)
	case "http":
		return parseHTTPURI(line)
	case "tuic":
		return parseTUICURI(line)
	case "wireguard", "wg":
		return parseWireGuardURI(line)
	default:
		return proxyNodeRecord{}, fmt.Errorf("unsupported scheme %q", scheme)
	}
}

func parseVMessURI(line string) (proxyNodeRecord, error) {
	payload := strings.TrimSpace(line[len("vmess://"):])
	if idx := strings.IndexByte(payload, '#'); idx >= 0 {
		payload = payload[:idx]
	}
	raw, err := decodeFlexibleBase64(payload)
	if err != nil {
		return proxyNodeRecord{}, fmt.Errorf("decode vmess base64: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return proxyNodeRecord{}, fmt.Errorf("decode vmess json: %w", err)
	}
	strField := func(k string) string {
		v, ok := m[k]
		if !ok || v == nil {
			return ""
		}
		switch t := v.(type) {
		case string:
			return strings.TrimSpace(t)
		case float64:
			return strconv.FormatInt(int64(t), 10)
		default:
			return strings.TrimSpace(fmt.Sprint(t))
		}
	}
	host := strField("add")
	if host == "" {
		return proxyNodeRecord{}, fmt.Errorf("vmess missing server")
	}
	port, err := parsePortStrict(strField("port"), 0)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	uuid := strField("id")
	if uuid == "" {
		return proxyNodeRecord{}, fmt.Errorf("vmess missing uuid")
	}
	netType := strings.ToLower(strField("net"))
	if netType == "" || netType == "tcp" {
		netType = "raw"
	}
	secMode := "none"
	if strings.EqualFold(strField("tls"), "tls") {
		secMode = "tls"
	}
	name := firstNonEmpty(strField("ps"), fmt.Sprintf("vmess-%s:%d", host, port))
	cfg := nodeConfig{
		UUID:     uuid,
		SNI:      firstNonEmpty(strField("sni"), strField("host")),
		Host:     strField("host"),
		Path:     strField("path"),
		Insecure: boolPtr(strField("skip-cert-verify") == "true"),
	}
	if netType == "grpc" {
		cfg.ServiceName = strField("path")
		cfg.Path = ""
	}
	return proxyNodeRecord{
		ID:            generateNodeID("ext-vmess"),
		Source:        "external",
		Name:          name,
		Protocol:      corev2.ProtocolVMess,
		Transport:     netType,
		SecurityMode:  secMode,
		Server:        host,
		Port:          port,
		Config:        cfg,
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

func parseVLESSURI(line string) (proxyNodeRecord, error) {
	u, err := url.Parse(line)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	uuid := strings.TrimSpace(u.User.Username())
	host := strings.TrimSpace(u.Hostname())
	port, err := parsePortStrict(u.Port(), 443)
	if err != nil || uuid == "" || host == "" {
		return proxyNodeRecord{}, fmt.Errorf("invalid vless uri")
	}
	q := u.Query()
	transport := strings.ToLower(firstNonEmpty(q.Get("type"), "raw"))
	if transport == "tcp" {
		transport = "raw"
	}
	secMode := strings.ToLower(firstNonEmpty(q.Get("security"), "none"))
	name := firstNonEmpty(u.Fragment, fmt.Sprintf("vless-%s:%d", host, port))
	cfg := nodeConfig{
		UUID:        uuid,
		Flow:        strings.TrimSpace(q.Get("flow")),
		Encryption:  firstNonEmpty(q.Get("encryption"), "none"),
		SNI:         strings.TrimSpace(q.Get("sni")),
		PublicKey:   strings.TrimSpace(q.Get("pbk")),
		ShortID:     strings.TrimSpace(q.Get("sid")),
		Fingerprint: firstNonEmpty(q.Get("fp"), "chrome"),
		Path:        strings.TrimSpace(q.Get("path")),
		Host:        strings.TrimSpace(q.Get("host")),
		ServiceName: strings.TrimSpace(q.Get("serviceName")),
		XHTTPMode:   strings.TrimSpace(q.Get("mode")),
		Insecure:    boolPtr(q.Get("allowInsecure") == "1" || strings.EqualFold(q.Get("allowInsecure"), "true")),
	}
	return proxyNodeRecord{
		ID:            generateNodeID("ext-vless"),
		Source:        "external",
		Name:          name,
		Protocol:      corev2.ProtocolVLESS,
		Transport:     transport,
		SecurityMode:  secMode,
		Server:        host,
		Port:          port,
		Config:        cfg,
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

func parseTrojanURI(line string) (proxyNodeRecord, error) {
	u, err := url.Parse(line)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	password := strings.TrimSpace(u.User.Username())
	host := strings.TrimSpace(u.Hostname())
	port, err := parsePortStrict(u.Port(), 443)
	if err != nil || password == "" || host == "" {
		return proxyNodeRecord{}, fmt.Errorf("invalid trojan uri")
	}
	q := u.Query()
	transport := strings.ToLower(firstNonEmpty(q.Get("type"), "raw"))
	if transport == "tcp" {
		transport = "raw"
	}
	secMode := strings.ToLower(firstNonEmpty(q.Get("security"), "tls"))
	name := firstNonEmpty(u.Fragment, fmt.Sprintf("trojan-%s:%d", host, port))
	cfg := nodeConfig{
		Password:    password,
		SNI:         firstNonEmpty(q.Get("sni"), q.Get("peer"), host),
		PublicKey:   strings.TrimSpace(q.Get("pbk")),
		ShortID:     strings.TrimSpace(q.Get("sid")),
		Fingerprint: strings.TrimSpace(q.Get("fp")),
		Path:        strings.TrimSpace(q.Get("path")),
		Host:        strings.TrimSpace(q.Get("host")),
		ServiceName: strings.TrimSpace(q.Get("serviceName")),
		Insecure:    boolPtr(q.Get("allowInsecure") == "1" || strings.EqualFold(q.Get("allowInsecure"), "true")),
	}
	return proxyNodeRecord{
		ID:            generateNodeID("ext-trojan"),
		Source:        "external",
		Name:          name,
		Protocol:      corev2.ProtocolTrojan,
		Transport:     transport,
		SecurityMode:  secMode,
		Server:        host,
		Port:          port,
		Config:        cfg,
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

func parseShadowsocksURI(line string) (proxyNodeRecord, error) {
	rest := strings.TrimSpace(line[len("ss://"):])
	name := ""
	if hashIdx := strings.LastIndexByte(rest, '#'); hashIdx >= 0 {
		if unesc, err := url.PathUnescape(rest[hashIdx+1:]); err == nil {
			name = strings.TrimSpace(unesc)
		} else {
			name = strings.TrimSpace(rest[hashIdx+1:])
		}
		rest = rest[:hashIdx]
	}
	queryPart := ""
	if qIdx := strings.IndexByte(rest, '?'); qIdx >= 0 {
		queryPart = rest[qIdx+1:]
		rest = rest[:qIdx]
	}
	rest = strings.TrimSuffix(rest, "/")

	var method, password, hostPort string
	if atIdx := strings.LastIndexByte(rest, '@'); atIdx >= 0 {
		userInfo := rest[:atIdx]
		hostPort = rest[atIdx+1:]
		if strings.Contains(userInfo, ":") {
			method, password, _ = strings.Cut(userInfo, ":")
			if u, err := url.PathUnescape(password); err == nil {
				password = u
			}
		} else {
			decoded, err := decodeFlexibleBase64(userInfo)
			if err != nil {
				return proxyNodeRecord{}, fmt.Errorf("decode ss userinfo: %w", err)
			}
			method, password, _ = strings.Cut(string(decoded), ":")
		}
	} else {
		decoded, err := decodeFlexibleBase64(rest)
		if err != nil {
			return proxyNodeRecord{}, fmt.Errorf("decode legacy ss uri: %w", err)
		}
		s := string(decoded)
		at := strings.LastIndexByte(s, '@')
		if at < 0 {
			return proxyNodeRecord{}, fmt.Errorf("invalid legacy ss uri")
		}
		method, password, _ = strings.Cut(s[:at], ":")
		hostPort = s[at+1:]
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return proxyNodeRecord{}, fmt.Errorf("invalid ss host:port")
	}
	port, err := parsePortStrict(portStr, 0)
	if err != nil || method == "" || password == "" || host == "" {
		return proxyNodeRecord{}, fmt.Errorf("invalid ss fields")
	}

	cfg := nodeConfig{
		Method:   strings.TrimSpace(method),
		Password: password,
		UDP:      boolPtr(true),
	}
	if queryPart != "" {
		if q, err := url.ParseQuery(queryPart); err == nil {
			if plugin := q.Get("plugin"); plugin != "" {
				for _, seg := range strings.Split(plugin, ";") {
					k, v, ok := strings.Cut(seg, "=")
					if !ok {
						continue
					}
					switch strings.TrimSpace(k) {
					case "obfs":
						cfg.ObfsMode = strings.TrimSpace(v)
					case "obfs-host":
						cfg.ObfsHost = strings.TrimSpace(v)
					}
				}
			}
		}
	}

	proto := corev2.ProtocolShadowsocks
	if strings.HasPrefix(strings.ToLower(cfg.Method), "2022-blake3-") {
		proto = corev2.ProtocolShadowsocks2022
		if sKey, uKey, hasColon := strings.Cut(password, ":"); hasColon {
			cfg.ServerKey = sKey
			cfg.UserKey = uKey
		} else {
			cfg.ServerKey = password
		}
	}
	name = firstNonEmpty(name, fmt.Sprintf("ss-%s:%d", host, port))
	return proxyNodeRecord{
		ID:            generateNodeID("ext-ss"),
		Source:        "external",
		Name:          name,
		Protocol:      proto,
		Transport:     "raw",
		SecurityMode:  "none",
		Server:        host,
		Port:          port,
		Config:        cfg,
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

func parseHysteria2URI(line string) (proxyNodeRecord, error) {
	u, err := url.Parse(line)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	password := strings.TrimSpace(u.User.Username())
	if p, ok := u.User.Password(); ok && p != "" {
		password = password + ":" + p
	}
	host := strings.TrimSpace(u.Hostname())
	port, err := parsePortStrict(u.Port(), 443)
	if err != nil || password == "" || host == "" {
		return proxyNodeRecord{}, fmt.Errorf("invalid hysteria2 uri")
	}
	q := u.Query()
	name := firstNonEmpty(u.Fragment, fmt.Sprintf("hy2-%s:%d", host, port))
	cfg := nodeConfig{
		Password:     password,
		SNI:          firstNonEmpty(q.Get("sni"), host),
		Insecure:     boolPtr(q.Get("insecure") == "1" || strings.EqualFold(q.Get("insecure"), "true")),
		ObfsMode:     strings.TrimSpace(q.Get("obfs")),
		ObfsPassword: strings.TrimSpace(q.Get("obfs-password")),
		PortHopping:  strings.TrimSpace(q.Get("mport")),
		Fingerprint:  strings.TrimSpace(q.Get("pinSHA256")),
	}
	return proxyNodeRecord{
		ID:            generateNodeID("ext-hy2"),
		Source:        "external",
		Name:          name,
		Protocol:      corev2.ProtocolHysteria2,
		Transport:     "udp",
		SecurityMode:  "tls",
		Server:        host,
		Port:          port,
		Config:        cfg,
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

func parseAnyTLSURI(line string) (proxyNodeRecord, error) {
	u, err := url.Parse(line)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	password := strings.TrimSpace(u.User.Username())
	host := strings.TrimSpace(u.Hostname())
	port, err := parsePortStrict(u.Port(), 443)
	if err != nil || password == "" || host == "" {
		return proxyNodeRecord{}, fmt.Errorf("invalid anytls uri")
	}
	q := u.Query()
	name := firstNonEmpty(u.Fragment, fmt.Sprintf("anytls-%s:%d", host, port))
	cfg := nodeConfig{
		Password:    password,
		SNI:         firstNonEmpty(q.Get("sni"), host),
		Insecure:    boolPtr(q.Get("insecure") == "1" || strings.EqualFold(q.Get("insecure"), "true")),
		Fingerprint: strings.TrimSpace(q.Get("fp")),
	}
	return proxyNodeRecord{
		ID:            generateNodeID("ext-anytls"),
		Source:        "external",
		Name:          name,
		Protocol:      corev2.ProtocolAnyTLS,
		Transport:     "raw",
		SecurityMode:  "tls",
		Server:        host,
		Port:          port,
		Config:        cfg,
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

func parseSOCKS5URI(line string) (proxyNodeRecord, error) {
	u, err := url.Parse(line)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	host := strings.TrimSpace(u.Hostname())
	port, err := parsePortStrict(u.Port(), 1080)
	if err != nil || host == "" {
		return proxyNodeRecord{}, fmt.Errorf("invalid socks5 uri")
	}
	user := strings.TrimSpace(u.User.Username())
	pass, _ := u.User.Password()
	name := firstNonEmpty(u.Fragment, fmt.Sprintf("socks5-%s:%d", host, port))
	return proxyNodeRecord{
		ID:            generateNodeID("ext-socks5"),
		Source:        "external",
		Name:          name,
		Protocol:      corev2.ProtocolSOCKS5,
		Transport:     "raw",
		SecurityMode:  "none",
		Server:        host,
		Port:          port,
		Config:        nodeConfig{Username: user, Password: pass, UDP: boolPtr(true)},
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

func parseHTTPURI(line string) (proxyNodeRecord, error) {
	u, err := url.Parse(line)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	host := strings.TrimSpace(u.Hostname())
	port, err := parsePortStrict(u.Port(), 8080)
	if err != nil || host == "" {
		return proxyNodeRecord{}, fmt.Errorf("invalid http uri")
	}
	user := strings.TrimSpace(u.User.Username())
	pass, _ := u.User.Password()
	name := firstNonEmpty(u.Fragment, fmt.Sprintf("http-%s:%d", host, port))
	return proxyNodeRecord{
		ID:            generateNodeID("ext-http"),
		Source:        "external",
		Name:          name,
		Protocol:      corev2.ProtocolHTTP,
		Transport:     "raw",
		SecurityMode:  "none",
		Server:        host,
		Port:          port,
		Config:        nodeConfig{Username: user, Password: pass},
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

func parseTUICURI(line string) (proxyNodeRecord, error) {
	u, err := url.Parse(line)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	uuid := strings.TrimSpace(u.User.Username())
	pass, _ := u.User.Password()
	host := strings.TrimSpace(u.Hostname())
	port, err := parsePortStrict(u.Port(), 443)
	if err != nil || uuid == "" || host == "" {
		return proxyNodeRecord{}, fmt.Errorf("invalid tuic uri")
	}
	q := u.Query()
	var alpn []string
	if rawALPN := strings.TrimSpace(q.Get("alpn")); rawALPN != "" {
		for _, a := range strings.Split(rawALPN, ",") {
			if s := strings.TrimSpace(a); s != "" {
				alpn = append(alpn, s)
			}
		}
	}
	name := firstNonEmpty(u.Fragment, fmt.Sprintf("tuic-%s:%d", host, port))
	return proxyNodeRecord{
		ID:           generateNodeID("ext-tuic"),
		Source:       "external",
		Name:         name,
		Protocol:     "tuic",
		Transport:    "udp",
		SecurityMode: "tls",
		Server:       host,
		Port:         port,
		Config: nodeConfig{
			UUID:              uuid,
			Password:          pass,
			SNI:               firstNonEmpty(q.Get("sni"), host),
			CongestionControl: firstNonEmpty(q.Get("congestion_control"), "bbr"),
			ALPN:              alpn,
			Insecure:          boolPtr(q.Get("allow_insecure") == "1" || q.Get("insecure") == "1"),
		},
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

func parseWireGuardURI(line string) (proxyNodeRecord, error) {
	u, err := url.Parse(line)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	privKey := strings.TrimSpace(u.User.Username())
	if unesc, err := url.PathUnescape(privKey); err == nil && unesc != "" {
		privKey = unesc
	}
	host := strings.TrimSpace(u.Hostname())
	port, err := parsePortStrict(u.Port(), 51820)
	if err != nil || host == "" {
		return proxyNodeRecord{}, fmt.Errorf("invalid wireguard uri")
	}
	q := u.Query()
	mtu := 1280
	if m, err := strconv.Atoi(strings.TrimSpace(q.Get("mtu"))); err == nil && m >= 1200 && m <= 1500 {
		mtu = m
	}
	var reserved []int
	if rRaw := strings.TrimSpace(q.Get("reserved")); rRaw != "" {
		for _, part := range strings.Split(rRaw, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n >= 0 && n <= 255 {
				reserved = append(reserved, n)
			}
		}
	}
	addrV4, addrV6 := "172.16.0.2/32", ""
	for _, a := range strings.Split(q.Get("address"), ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.Contains(a, ":") {
			addrV6 = a
		} else {
			addrV4 = a
		}
	}
	name := firstNonEmpty(u.Fragment, fmt.Sprintf("wg-%s:%d", host, port))
	return proxyNodeRecord{
		ID:           generateNodeID("ext-wg"),
		Source:       "external",
		Name:         name,
		Protocol:     "wireguard",
		Transport:    "udp",
		SecurityMode: "none",
		Server:       host,
		Port:         port,
		Config: nodeConfig{
			PrivateKey:    privKey,
			PeerPublicKey: strings.TrimSpace(q.Get("publickey")),
			AddressV4:     addrV4,
			AddressV6:     addrV6,
			MTU:           mtu,
			Reserved:      reserved,
		},
		RawURI:        line,
		Enabled:       true,
		LastLatencyMS: -1,
	}, nil
}

// ======================== 节点 -> ShareURI / Clash Meta / sing-box 渲染 ========================

func buildSubNodeFromRecord(rec proxyNodeRecord, defaultHost string, user *userRecord) (subNode, bool) {
	server := strings.Trim(strings.TrimSpace(firstNonEmpty(rec.Server, defaultHost)), "[]")
	if server == "" {
		server = "YOUR_SERVER_IP"
	}
	hostPort := net.JoinHostPort(server, strconv.Itoa(rec.Port))
	name := strings.TrimSpace(rec.Name)
	if user != nil {
		prefix := firstNonEmpty(user.DisplayName, user.ID)
		if rec.Source == "managed" {
			name = prefix + "-" + firstNonEmpty(rec.Name, rec.ID)
		}
	}
	if name == "" {
		name = rec.ID
	}

	uuidVal := rec.Config.UUID
	passVal := rec.Config.Password
	userKey := rec.Config.UserKey
	if user != nil && rec.Source == "managed" {
		if user.VLESSUUID != "" {
			uuidVal = user.VLESSUUID
		}
		if user.Hy2Password != "" {
			passVal = user.Hy2Password
		}
		if user.SS2022UserKey != "" {
			userKey = user.SS2022UserKey
		}
	}

	transport := strings.ToLower(strings.TrimSpace(rec.Transport))
	if transport == "" || transport == "raw" {
		transport = "tcp"
	}
	secMode := strings.ToLower(strings.TrimSpace(rec.SecurityMode))
	udpEnabled := rec.Config.UDP == nil || *rec.Config.UDP

	switch rec.Protocol {
	case corev2.ProtocolVLESS:
		enc := firstNonEmpty(rec.Config.Encryption, "none")
		q := url.Values{}
		q.Set("encryption", enc)
		if rec.Config.Flow != "" {
			q.Set("flow", rec.Config.Flow)
		}
		q.Set("security", firstNonEmpty(secMode, "none"))
		if secMode == "reality" {
			q.Set("sni", rec.Config.SNI)
			q.Set("fp", firstNonEmpty(rec.Config.Fingerprint, "chrome"))
			q.Set("pbk", rec.Config.PublicKey)
			if rec.Config.ShortID != "" {
				q.Set("sid", rec.Config.ShortID)
			}
		} else if secMode == "tls" {
			if rec.Config.SNI != "" {
				q.Set("sni", rec.Config.SNI)
			}
			if rec.Config.isInsecure() {
				q.Set("allowInsecure", "1")
			}
		}
		q.Set("type", transport)
		if transport == "ws" || transport == "xhttp" {
			if rec.Config.Path != "" {
				q.Set("path", rec.Config.Path)
			}
			if rec.Config.Host != "" {
				q.Set("host", rec.Config.Host)
			}
		}
		if transport == "xhttp" && rec.Config.XHTTPMode != "" {
			q.Set("mode", rec.Config.XHTTPMode)
		}
		if transport == "grpc" && rec.Config.ServiceName != "" {
			q.Set("serviceName", rec.Config.ServiceName)
		}
		uri := fmt.Sprintf("vless://%s@%s?%s#%s", url.PathEscape(uuidVal), hostPort, q.Encode(), url.PathEscape(name))

		cn := map[string]any{
			"name":    name,
			"type":    "vless",
			"server":  server,
			"port":    rec.Port,
			"uuid":    uuidVal,
			"network": transport,
			"tls":     secMode == "reality" || secMode == "tls",
			"udp":     true,
		}
		if rec.Config.Flow != "" {
			cn["flow"] = rec.Config.Flow
		}
		sb := map[string]any{
			"type":        "vless",
			"tag":         name,
			"server":      server,
			"server_port": rec.Port,
			"uuid":        uuidVal,
		}
		if rec.Config.Flow != "" {
			sb["flow"] = rec.Config.Flow
		}
		if secMode == "reality" {
			ro := map[string]any{"public-key": rec.Config.PublicKey}
			sbr := map[string]any{"enabled": true, "public_key": rec.Config.PublicKey}
			if rec.Config.ShortID != "" {
				ro["short-id"] = rec.Config.ShortID
				sbr["short_id"] = rec.Config.ShortID
			}
			cn["servername"] = rec.Config.SNI
			cn["client-fingerprint"] = firstNonEmpty(rec.Config.Fingerprint, "chrome")
			cn["reality-opts"] = ro
			sb["tls"] = map[string]any{
				"enabled":     true,
				"server_name": rec.Config.SNI,
				"utls":        map[string]any{"enabled": true, "fingerprint": firstNonEmpty(rec.Config.Fingerprint, "chrome")},
				"reality":     sbr,
			}
		} else if secMode == "tls" {
			cn["servername"] = rec.Config.SNI
			cn["skip-cert-verify"] = rec.Config.isInsecure()
			sb["tls"] = map[string]any{
				"enabled":     true,
				"server_name": rec.Config.SNI,
				"insecure":    rec.Config.isInsecure(),
			}
		}
		attachSubTransport(cn, sb, transport, rec.Config)
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true

	case corev2.ProtocolVMess:
		isTLS := secMode == "tls"
		tlsStr := ""
		if isTLS {
			tlsStr = "tls"
		}
		pVal := rec.Config.Path
		if transport == "grpc" && rec.Config.ServiceName != "" {
			pVal = rec.Config.ServiceName
		}
		v2n := map[string]any{
			"v": "2", "ps": name, "add": server, "port": strconv.Itoa(rec.Port),
			"id": uuidVal, "aid": "0", "scy": "auto", "net": transport, "type": "none",
			"host": rec.Config.Host, "path": pVal, "tls": tlsStr, "sni": rec.Config.SNI,
		}
		raw, _ := json.Marshal(v2n)
		uri := "vmess://" + base64.StdEncoding.EncodeToString(raw)

		cn := map[string]any{
			"name": name, "type": "vmess", "server": server, "port": rec.Port,
			"uuid": uuidVal, "alterId": 0, "cipher": "auto", "network": transport,
			"tls": isTLS, "udp": true,
		}
		sb := map[string]any{
			"type": "vmess", "tag": name, "server": server, "server_port": rec.Port,
			"uuid": uuidVal, "security": "auto", "alter_id": 0,
		}
		if isTLS {
			cn["servername"] = rec.Config.SNI
			cn["skip-cert-verify"] = rec.Config.isInsecure()
			sb["tls"] = map[string]any{"enabled": true, "server_name": rec.Config.SNI, "insecure": rec.Config.isInsecure()}
		}
		attachSubTransport(cn, sb, transport, rec.Config)
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true

	case corev2.ProtocolTrojan:
		q := url.Values{}
		q.Set("security", firstNonEmpty(secMode, "tls"))
		if rec.Config.SNI != "" {
			q.Set("sni", rec.Config.SNI)
		}
		if secMode == "reality" {
			q.Set("fp", firstNonEmpty(rec.Config.Fingerprint, "chrome"))
			q.Set("pbk", rec.Config.PublicKey)
			if rec.Config.ShortID != "" {
				q.Set("sid", rec.Config.ShortID)
			}
		} else if rec.Config.isInsecure() {
			q.Set("allowInsecure", "1")
		}
		q.Set("type", transport)
		if transport == "ws" && rec.Config.Path != "" {
			q.Set("path", rec.Config.Path)
		}
		if transport == "ws" && rec.Config.Host != "" {
			q.Set("host", rec.Config.Host)
		}
		if transport == "grpc" && rec.Config.ServiceName != "" {
			q.Set("serviceName", rec.Config.ServiceName)
		}
		uri := fmt.Sprintf("trojan://%s@%s?%s#%s", url.PathEscape(passVal), hostPort, q.Encode(), url.PathEscape(name))

		cn := map[string]any{
			"name": name, "type": "trojan", "server": server, "port": rec.Port,
			"password": passVal, "network": transport, "sni": rec.Config.SNI, "udp": true,
		}
		sb := map[string]any{
			"type": "trojan", "tag": name, "server": server, "server_port": rec.Port,
			"password": passVal,
		}
		if secMode == "reality" {
			ro := map[string]any{"public-key": rec.Config.PublicKey}
			sbr := map[string]any{"enabled": true, "public_key": rec.Config.PublicKey}
			if rec.Config.ShortID != "" {
				ro["short-id"] = rec.Config.ShortID
				sbr["short_id"] = rec.Config.ShortID
			}
			cn["client-fingerprint"] = firstNonEmpty(rec.Config.Fingerprint, "chrome")
			cn["reality-opts"] = ro
			sb["tls"] = map[string]any{
				"enabled": true, "server_name": rec.Config.SNI,
				"utls":    map[string]any{"enabled": true, "fingerprint": firstNonEmpty(rec.Config.Fingerprint, "chrome")},
				"reality": sbr,
			}
		} else {
			cn["skip-cert-verify"] = rec.Config.isInsecure()
			sb["tls"] = map[string]any{"enabled": true, "server_name": rec.Config.SNI, "insecure": rec.Config.isInsecure()}
		}
		attachSubTransport(cn, sb, transport, rec.Config)
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true

	case corev2.ProtocolShadowsocks, corev2.ProtocolShadowsocks2022:
		method := firstNonEmpty(rec.Config.Method, corev2.MethodAEADAES256GCM)
		pwd := passVal
		if rec.Protocol == corev2.ProtocolShadowsocks2022 {
			if method == corev2.MethodChaCha20 || userKey == "" {
				pwd = firstNonEmpty(rec.Config.ServerKey, passVal)
			} else if rec.Config.ServerKey != "" {
				pwd = rec.Config.ServerKey + ":" + userKey
			} else {
				pwd = userKey
			}
		}
		ui := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + pwd))
		obfsMode := strings.ToLower(strings.TrimSpace(rec.Config.ObfsMode))
		hasObfs := obfsMode == "http" || obfsMode == "tls"
		obfsHost := firstNonEmpty(rec.Config.ObfsHost, "www.bing.com")
		var uri string
		if hasObfs {
			pluginVal := fmt.Sprintf("obfs-local;obfs=%s;obfs-host=%s", obfsMode, obfsHost)
			uri = fmt.Sprintf("ss://%s@%s/?plugin=%s#%s", ui, hostPort, url.QueryEscape(pluginVal), url.PathEscape(name))
		} else {
			uri = fmt.Sprintf("ss://%s@%s#%s", ui, hostPort, url.PathEscape(name))
		}
		cn := map[string]any{
			"name": name, "type": "ss", "server": server, "port": rec.Port,
			"cipher": method, "password": pwd, "udp": udpEnabled,
		}
		sb := map[string]any{
			"type": "shadowsocks", "tag": name, "server": server, "server_port": rec.Port,
			"method": method, "password": pwd,
		}
		if !udpEnabled {
			sb["network"] = "tcp"
		}
		if hasObfs {
			cn["plugin"] = "obfs"
			cn["plugin-opts"] = map[string]any{"mode": obfsMode, "host": obfsHost}
			sb["plugin"] = "obfs-local"
			sb["plugin_opts"] = fmt.Sprintf("obfs=%s;obfs-host=%s", obfsMode, obfsHost)
		}
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true

	case corev2.ProtocolHysteria2:
		sni := firstNonEmpty(rec.Config.SNI, server)
		q := url.Values{}
		q.Set("sni", sni)
		if rec.Config.isInsecure() {
			q.Set("insecure", "1")
		} else {
			q.Set("insecure", "0")
		}
		if rec.Config.ObfsPassword != "" {
			q.Set("obfs", "salamander")
			q.Set("obfs-password", rec.Config.ObfsPassword)
		}
		if rec.Config.PortHopping != "" {
			q.Set("mport", rec.Config.PortHopping)
		}
		uri := fmt.Sprintf("hysteria2://%s@%s?%s#%s", url.PathEscape(passVal), hostPort, q.Encode(), url.PathEscape(name))
		cn := map[string]any{
			"name": name, "type": "hysteria2", "server": server, "port": rec.Port,
			"password": passVal, "sni": sni, "skip-cert-verify": rec.Config.isInsecure(),
		}
		sb := map[string]any{
			"type": "hysteria2", "tag": name, "server": server, "server_port": rec.Port,
			"password": passVal,
			"tls":      map[string]any{"enabled": true, "server_name": sni, "insecure": rec.Config.isInsecure()},
		}
		if rec.Config.ObfsPassword != "" {
			cn["obfs"] = "salamander"
			cn["obfs-password"] = rec.Config.ObfsPassword
			sb["obfs"] = map[string]any{"type": "salamander", "password": rec.Config.ObfsPassword}
		}
		if rec.Config.PortHopping != "" {
			cn["ports"] = rec.Config.PortHopping
			sb["server_ports"] = []string{strings.ReplaceAll(rec.Config.PortHopping, "-", ":")}
		}
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true

	case corev2.ProtocolAnyTLS:
		sni := firstNonEmpty(rec.Config.SNI, server)
		q := url.Values{}
		q.Set("sni", sni)
		if rec.Config.isInsecure() {
			q.Set("insecure", "1")
		} else {
			q.Set("insecure", "0")
		}
		uri := fmt.Sprintf("anytls://%s@%s?%s#%s", url.PathEscape(passVal), hostPort, q.Encode(), url.PathEscape(name))
		cn := map[string]any{
			"name": name, "type": "anytls", "server": server, "port": rec.Port,
			"password": passVal, "sni": sni, "skip-cert-verify": rec.Config.isInsecure(), "udp": false,
		}
		sb := map[string]any{
			"type": "anytls", "tag": name, "server": server, "server_port": rec.Port,
			"password": passVal,
			"tls":      map[string]any{"enabled": true, "server_name": sni, "insecure": rec.Config.isInsecure()},
		}
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true

	case corev2.ProtocolSOCKS5:
		uname := firstNonEmpty(rec.Config.Username, "user")
		if user != nil && rec.Source == "managed" {
			uname = user.ID
		}
		uri := fmt.Sprintf("socks5://%s:%s@%s#%s", url.PathEscape(uname), url.PathEscape(passVal), hostPort, url.PathEscape(name))
		cn := map[string]any{
			"name": name, "type": "socks5", "server": server, "port": rec.Port,
			"username": uname, "password": passVal, "udp": udpEnabled,
		}
		sb := map[string]any{
			"type": "socks", "tag": name, "server": server, "server_port": rec.Port,
			"version": "5", "username": uname, "password": passVal,
		}
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true

	case corev2.ProtocolHTTP:
		uname := firstNonEmpty(rec.Config.Username, "user")
		if user != nil && rec.Source == "managed" {
			uname = user.ID
		}
		uri := fmt.Sprintf("http://%s:%s@%s#%s", url.PathEscape(uname), url.PathEscape(passVal), hostPort, url.PathEscape(name))
		cn := map[string]any{
			"name": name, "type": "http", "server": server, "port": rec.Port,
			"username": uname, "password": passVal,
		}
		sb := map[string]any{
			"type": "http", "tag": name, "server": server, "server_port": rec.Port,
			"username": uname, "password": passVal,
		}
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true

	case "tuic":
		sni := firstNonEmpty(rec.Config.SNI, server)
		cc := firstNonEmpty(rec.Config.CongestionControl, "bbr")
		uri := rec.RawURI
		if uri == "" {
			q := url.Values{"sni": {sni}, "congestion_control": {cc}}
			if rec.Config.isInsecure() {
				q.Set("allow_insecure", "1")
			}
			uri = fmt.Sprintf("tuic://%s:%s@%s?%s#%s", url.PathEscape(uuidVal), url.PathEscape(passVal), hostPort, q.Encode(), url.PathEscape(name))
		}
		cn := map[string]any{
			"name": name, "type": "tuic", "server": server, "port": rec.Port,
			"uuid": uuidVal, "password": passVal, "sni": sni,
			"congestion-controller": cc, "skip-cert-verify": rec.Config.isInsecure(),
		}
		sb := map[string]any{
			"type": "tuic", "tag": name, "server": server, "server_port": rec.Port,
			"uuid": uuidVal, "password": passVal, "congestion_control": cc,
			"tls": map[string]any{"enabled": true, "server_name": sni, "insecure": rec.Config.isInsecure()},
		}
		if len(rec.Config.ALPN) > 0 {
			cn["alpn"] = rec.Config.ALPN
			sb["tls"].(map[string]any)["alpn"] = rec.Config.ALPN
		}
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true

	case "wireguard":
		uri := rec.RawURI
		if uri == "" {
			q := url.Values{
				"publickey": {rec.Config.PeerPublicKey},
				"address":   {firstNonEmpty(rec.Config.AddressV4, "172.16.0.2/32")},
				"mtu":       {strconv.Itoa(max(rec.Config.MTU, 1280))},
			}
			uri = fmt.Sprintf("wireguard://%s@%s?%s#%s", url.PathEscape(rec.Config.PrivateKey), hostPort, q.Encode(), url.PathEscape(name))
		}
		addrs := []string{firstNonEmpty(rec.Config.AddressV4, "172.16.0.2/32")}
		if rec.Config.AddressV6 != "" {
			addrs = append(addrs, rec.Config.AddressV6)
		}
		mtu := rec.Config.MTU
		if mtu <= 0 {
			mtu = 1280
		}
		cn := map[string]any{
			"name": name, "type": "wireguard", "server": server, "port": rec.Port,
			"ip": strings.Split(addrs[0], "/")[0], "private-key": rec.Config.PrivateKey,
			"public-key": rec.Config.PeerPublicKey, "mtu": mtu, "udp": true,
		}
		if rec.Config.AddressV6 != "" {
			cn["ipv6"] = strings.Split(rec.Config.AddressV6, "/")[0]
		}
		sb := map[string]any{
			"type": "wireguard", "tag": name, "server": server, "server_port": rec.Port,
			"local_address": addrs, "private_key": rec.Config.PrivateKey,
			"peer_public_key": rec.Config.PeerPublicKey, "mtu": mtu,
		}
		if len(rec.Config.Reserved) > 0 {
			sb["reserved"] = rec.Config.Reserved
		}
		return subNode{Name: name, ShareURI: uri, ClashNode: cn, SingboxOutbound: sb}, true
	}

	return subNode{}, false
}

func attachSubTransport(cn, sb map[string]any, transport string, cfg nodeConfig) {
	switch transport {
	case "ws":
		wsPath := firstNonEmpty(cfg.Path, "/")
		wsOpts := map[string]any{"path": wsPath}
		sbTr := map[string]any{"type": "ws", "path": wsPath}
		if cfg.Host != "" {
			wsOpts["headers"] = map[string]any{"Host": cfg.Host}
			sbTr["headers"] = map[string]any{"Host": cfg.Host}
		}
		cn["ws-opts"] = wsOpts
		sb["transport"] = sbTr
	case "grpc":
		sn := firstNonEmpty(cfg.ServiceName, "grpc")
		cn["grpc-opts"] = map[string]any{"grpc-service-name": sn}
		sb["transport"] = map[string]any{"type": "grpc", "service_name": sn}
	case "xhttp":
		p := firstNonEmpty(cfg.Path, "/")
		xOpts := map[string]any{"path": p}
		sbTr := map[string]any{"type": "http", "path": p}
		if cfg.Host != "" {
			xOpts["host"] = cfg.Host
			sbTr["host"] = []string{cfg.Host}
		}
		if cfg.XHTTPMode != "" {
			xOpts["mode"] = cfg.XHTTPMode
		}
		cn["xhttp-opts"] = xOpts
		sb["transport"] = sbTr
	}
}

// ======================== 原生 Xray / AnyTLS JSON 实时预览生成 ========================

func buildNativeInboundPreview(rec proxyNodeRecord) (engine string, doc map[string]any) {
	tag := "qwq-in-" + firstNonEmpty(rec.ID, rec.Protocol+"-preview")
	listen := firstNonEmpty(rec.Listen, "0.0.0.0")
	sniffOn := rec.Config.Sniffing == nil || *rec.Config.Sniffing
	sniffObj := map[string]any{
		"enabled":      sniffOn,
		"destOverride": []string{"http", "tls", "quic"},
	}

	normTransport := strings.ToLower(strings.TrimSpace(rec.Transport))
	if normTransport == "" || normTransport == "tcp" {
		normTransport = "raw"
	}
	secMode := strings.ToLower(strings.TrimSpace(rec.SecurityMode))
	udpEnabled := rec.Config.UDP == nil || *rec.Config.UDP
	networkStr := "tcp"
	if udpEnabled {
		networkStr = "tcp,udp"
	}

	if rec.Protocol == corev2.ProtocolAnyTLS {
		scheme := normalizePaddingScheme(rec.Config.PaddingScheme)
		return "anytls", map[string]any{
			"engine":   "qwq-anytls-v2",
			"tag":      tag,
			"listen":   listen,
			"port":     rec.Port,
			"protocol": "anytls",
			"users": []map[string]any{{
				"id":       "default",
				"password": rec.Config.Password,
			}},
			"tls": map[string]any{
				"binding_ref": firstNonEmpty(rec.Config.BindingRef, "<managed-tls-binding>"),
				"server_name": firstNonEmpty(rec.Config.SNI, rec.Server, "example.com"),
				"min_version": "1.2",
			},
			"padding_scheme": scheme,
		}
	}

	buildStream := func() map[string]any {
		st := map[string]any{
			"network":  normTransport,
			"security": firstNonEmpty(secMode, "none"),
		}
		switch secMode {
		case "reality":
			sni := firstNonEmpty(rec.Config.SNI, "www.microsoft.com")
			target := firstNonEmpty(rec.Config.Target, sni+":443")
			st["realitySettings"] = map[string]any{
				"target":      target,
				"serverNames": []string{sni},
				"privateKey":  firstNonEmpty(rec.Config.PrivateKey, "<generated-private-key>"),
				"shortIds":    []string{firstNonEmpty(rec.Config.ShortID, "01234567")},
			}
		case "tls":
			st["tlsSettings"] = map[string]any{
				"serverName":       firstNonEmpty(rec.Config.SNI, rec.Server, "example.com"),
				"minVersion":       "1.2",
				"rejectUnknownSni": true,
				"certificates": []map[string]any{{
					"usage":          "encipherment",
					"oneTimeLoading": true,
					"bindingRef":     firstNonEmpty(rec.Config.BindingRef, "<managed-tls-binding>"),
				}},
			}
		}
		switch normTransport {
		case "ws":
			ws := map[string]any{"path": firstNonEmpty(rec.Config.Path, "/")}
			if rec.Config.Host != "" {
				ws["host"] = rec.Config.Host
			}
			st["wsSettings"] = ws
		case "grpc":
			st["grpcSettings"] = map[string]any{"serviceName": firstNonEmpty(rec.Config.ServiceName, "grpc")}
		case "xhttp":
			xh := map[string]any{
				"path": firstNonEmpty(rec.Config.Path, "/"),
				"mode": firstNonEmpty(rec.Config.XHTTPMode, "auto"),
			}
			if rec.Config.Host != "" {
				xh["host"] = rec.Config.Host
			}
			st["xhttpSettings"] = xh
		}
		return st
	}

	switch rec.Protocol {
	case corev2.ProtocolVLESS:
		userObj := map[string]any{
			"id":    rec.Config.UUID,
			"email": "qwq-user-default",
			"level": 0,
		}
		if rec.Config.Flow != "" {
			userObj["flow"] = rec.Config.Flow
		}
		return "xray", map[string]any{
			"tag":      tag,
			"listen":   listen,
			"port":     rec.Port,
			"protocol": "vless",
			"settings": map[string]any{
				"decryption": firstNonEmpty(rec.Config.Decryption, "none"),
				"users":      []map[string]any{userObj},
			},
			"streamSettings": buildStream(),
			"sniffing":       sniffObj,
		}

	case corev2.ProtocolVMess:
		return "xray", map[string]any{
			"tag":      tag,
			"listen":   listen,
			"port":     rec.Port,
			"protocol": "vmess",
			"settings": map[string]any{
				"clients": []map[string]any{{
					"id":    rec.Config.UUID,
					"email": "qwq-user-default",
					"level": 0,
				}},
			},
			"streamSettings": buildStream(),
			"sniffing":       sniffObj,
		}

	case corev2.ProtocolTrojan:
		return "xray", map[string]any{
			"tag":      tag,
			"listen":   listen,
			"port":     rec.Port,
			"protocol": "trojan",
			"settings": map[string]any{
				"clients": []map[string]any{{
					"password": rec.Config.Password,
					"email":    "qwq-user-default",
					"level":    0,
				}},
			},
			"streamSettings": buildStream(),
			"sniffing":       sniffObj,
		}

	case corev2.ProtocolShadowsocks:
		method := firstNonEmpty(rec.Config.Method, corev2.MethodAEADAES256GCM)
		return "xray", map[string]any{
			"tag":      tag,
			"listen":   listen,
			"port":     rec.Port,
			"protocol": "shadowsocks",
			"settings": map[string]any{
				"clients": []map[string]any{{
					"method":   method,
					"password": rec.Config.Password,
					"email":    "qwq-user-default",
					"level":    0,
				}},
				"network": networkStr,
			},
			"sniffing": sniffObj,
		}

	case corev2.ProtocolShadowsocks2022:
		method := firstNonEmpty(rec.Config.Method, corev2.MethodAES128)
		var settings map[string]any
		if method == corev2.MethodChaCha20 {
			settings = map[string]any{
				"method":   method,
				"password": rec.Config.ServerKey,
				"email":    "qwq-user-default",
				"level":    0,
				"network":  networkStr,
			}
		} else {
			settings = map[string]any{
				"method":   method,
				"password": rec.Config.ServerKey,
				"users": []map[string]any{{
					"password": rec.Config.UserKey,
					"email":    "qwq-user-default",
					"level":    0,
				}},
				"network": networkStr,
			}
		}
		return "xray", map[string]any{
			"tag":      tag,
			"listen":   listen,
			"port":     rec.Port,
			"protocol": "shadowsocks",
			"settings": settings,
			"sniffing": sniffObj,
		}

	case corev2.ProtocolHysteria2:
		st := map[string]any{
			"network":          "hysteria",
			"security":         "tls",
			"hysteriaSettings": map[string]any{"version": 2},
			"tlsSettings": map[string]any{
				"serverName":       firstNonEmpty(rec.Config.SNI, rec.Server, "example.com"),
				"alpn":             []string{"h3"},
				"minVersion":       "1.3",
				"rejectUnknownSni": true,
				"certificates": []map[string]any{{
					"usage":          "encipherment",
					"oneTimeLoading": true,
					"bindingRef":     firstNonEmpty(rec.Config.BindingRef, "<managed-tls-binding>"),
				}},
			},
		}
		if rec.Config.ObfsPassword != "" {
			st["finalmask"] = map[string]any{
				"udp": []map[string]any{{
					"type":     "salamander",
					"settings": map[string]any{"password": rec.Config.ObfsPassword},
				}},
			}
		}
		return "xray", map[string]any{
			"tag":      tag,
			"listen":   listen,
			"port":     rec.Port,
			"protocol": "hysteria",
			"settings": map[string]any{
				"version": 2,
				"users": []map[string]any{{
					"auth":  rec.Config.Password,
					"email": "qwq-user-default",
					"level": 0,
				}},
			},
			"streamSettings": st,
			"sniffing":       sniffObj,
		}

	case corev2.ProtocolSOCKS5:
		return "xray", map[string]any{
			"tag":      tag,
			"listen":   listen,
			"port":     rec.Port,
			"protocol": "socks",
			"settings": map[string]any{
				"auth": "password",
				"accounts": []map[string]any{{
					"user": firstNonEmpty(rec.Config.Username, "user"),
					"pass": rec.Config.Password,
				}},
				"udp":       udpEnabled,
				"userLevel": 0,
			},
			"sniffing": sniffObj,
		}

	case corev2.ProtocolHTTP:
		return "xray", map[string]any{
			"tag":      tag,
			"listen":   listen,
			"port":     rec.Port,
			"protocol": "http",
			"settings": map[string]any{
				"accounts": []map[string]any{{
					"user": firstNonEmpty(rec.Config.Username, "user"),
					"pass": rec.Config.Password,
				}},
				"allowTransparent": false,
				"userLevel":        0,
			},
			"sniffing": sniffObj,
		}
	}

	return "xray", map[string]any{"tag": tag, "protocol": rec.Protocol, "port": rec.Port}
}
