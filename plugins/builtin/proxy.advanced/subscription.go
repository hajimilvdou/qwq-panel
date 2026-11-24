// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/routingrules"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 公开订阅路由（/p/proxy.advanced/sub/<token>） ========================

// ServePublicRoute 实现 pluginsdk.PublicRouteHandler，对外提供高熵令牌鉴权的多格式代理订阅。
func (i *instance) ServePublicRoute(ctx context.Context, req pluginsdk.PublicRouteRequest) (pluginsdk.PublicRouteResponse, error) {
	if req.Route != "sub" {
		return plainTextResponse(404, "route not found"), nil
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method != "GET" && method != "HEAD" {
		return plainTextResponse(405, "method not allowed"), nil
	}

	token, ok := extractSubscriptionToken(req.Path)
	if !ok {
		return plainTextResponse(404, "subscription not found"), nil
	}

	user, found, err := i.store.FindUserBySubscriptionToken(ctx, token)
	if err != nil {
		return plainTextResponse(500, "internal error"), nil
	}
	if !found {
		return plainTextResponse(404, "subscription not found"), nil
	}

	format, validFmt := resolveSubscriptionFormat(req.RawQuery, req.Headers)
	if !validFmt {
		return plainTextResponse(400, "unsupported subscription format"), nil
	}
	uaSummary := sanitizeUserAgent(headerValue(req.Headers, "user-agent"))

	if user.Status != "active" {
		_ = i.store.RecordSubscriptionAccess(ctx, user.ID, format, uaSummary, 403)
		return plainTextResponse(403, "subscription inactive"), nil
	}

	cfg := i.configSnapshot()
	chains, _ := i.store.ListChainsWithSecrets(ctx)
	brutals, _ := i.store.ListBrutalBindings(ctx)
	dbNodes, _ := i.store.ListNodes(ctx, "", "", "", "", true)
	body, contentType, err := renderSubscriptionPayloadFull(cfg, user, format, chains, brutals, dbNodes)
	if err != nil {
		return plainTextResponse(503, "subscription endpoint not configured"), nil
	}

	expireSec := int64(0)
	if user.ExpiresAt > 0 {
		expireSec = user.ExpiresAt / 1000
	}
	userInfoHeader := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
		user.PeriodUpBytes, user.PeriodDownBytes, user.QuotaBytes, expireSec)

	_ = i.store.RecordSubscriptionAccess(ctx, user.ID, format, uaSummary, 200)

	headers := []pluginsdk.HTTPHeader{
		{Name: "Content-Type", Value: contentType},
		{Name: "Subscription-Userinfo", Value: userInfoHeader},
		{Name: "Profile-Update-Interval", Value: "24"},
		{Name: "Cache-Control", Value: "no-store"},
	}
	if method == "HEAD" {
		body = nil
	}
	return pluginsdk.PublicRouteResponse{
		Status:  200,
		Headers: headers,
		Body:    body,
	}, nil
}

func extractSubscriptionToken(rawPath string) (string, bool) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(rawPath), "/")
	trimmed = strings.TrimPrefix(trimmed, "sub/")
	if trimmed == "" || strings.Contains(trimmed, "/") || strings.Contains(trimmed, "..") {
		return "", false
	}
	return trimmed, true
}

func resolveSubscriptionFormat(rawQuery string, headers []pluginsdk.HTTPHeader) (string, bool) {
	if strings.TrimSpace(rawQuery) != "" {
		values, err := url.ParseQuery(rawQuery)
		if err != nil {
			return "", false
		}
		if explicit := strings.ToLower(strings.TrimSpace(values.Get("format"))); explicit != "" {
			switch explicit {
			case "clash", "singbox", "v2ray", "raw":
				return explicit, true
			default:
				return "", false
			}
		}
	}
	ua := strings.ToLower(headerValue(headers, "user-agent"))
	switch {
	case strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") || strings.Contains(ua, "stash") || strings.Contains(ua, "verge"):
		return "clash", true
	case strings.Contains(ua, "sing-box") || strings.Contains(ua, "sfa") || strings.Contains(ua, "sfi") || strings.Contains(ua, "sfm"):
		return "singbox", true
	default:
		return "v2ray", true
	}
}

func headerValue(headers []pluginsdk.HTTPHeader, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func sanitizeUserAgent(raw string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		if r >= 0x20 && r <= 0x7e {
			b.WriteRune(r)
			if b.Len() >= 64 {
				break
			}
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func plainTextResponse(status uint32, msg string) pluginsdk.PublicRouteResponse {
	return pluginsdk.PublicRouteResponse{
		Status: status,
		Headers: []pluginsdk.HTTPHeader{
			{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
			{Name: "Cache-Control", Value: "no-store"},
		},
		Body: []byte(msg),
	}
}

// ======================== 多协议订阅渲染（v2ray Base64 / Clash Meta YAML / sing-box JSON） ========================

type subNode struct {
	Name            string
	ShareURI        string
	ClashNode       map[string]any
	SingboxOutbound map[string]any
}

func renderSubscriptionPayloadFull(cfg proxyConfig, user userRecord, format string, chains []chainWithSecret, brutals []brutalBindingRecord, dbNodes []proxyNodeRecord) ([]byte, string, error) {
	effCfg := applyBrutalSubPortOverrides(cfg, brutals)
	effPublicHost := detectPrimaryPublicHost(effCfg.PublicHost, "")
	if strings.TrimSpace(effCfg.PublicHost) == "" && effPublicHost != "" {
		effCfg.PublicHost = effPublicHost
	}
	nodes := buildUserSubscriptionNodes(effCfg, user)

	seenNames := make(map[string]bool, len(nodes)+len(dbNodes))
	for _, n := range nodes {
		seenNames[n.Name] = true
	}
	for _, rec := range dbNodes {
		if !rec.Enabled {
			continue
		}
		// 托管节点若未配置 server 且缺少 public_host，自动使用 detectPrimaryPublicHost 兜底。
		resolvedHost := detectPrimaryPublicHost(effCfg.PublicHost, rec.Server)
		if rec.Source == "managed" && resolvedHost == "" {
			continue
		}
		sn, ok := buildSubNodeFromRecord(rec, effCfg.PublicHost, &user)
		if !ok {
			continue
		}
		if seenNames[sn.Name] {
			sn.Name = sn.Name + "-" + rec.ID
			if sn.ClashNode != nil {
				sn.ClashNode["name"] = sn.Name
			}
			if sn.SingboxOutbound != nil {
				sn.SingboxOutbound["tag"] = sn.Name
			}
		}
		seenNames[sn.Name] = true
		nodes = append(nodes, sn)
	}

	if len(nodes) == 0 {
		return nil, "", fmt.Errorf("no public endpoints configured")
	}
	nodes = appendClientDialerChainNodes(nodes, user, chains)

	switch format {
	case "clash":
		return []byte(renderClashSubscription(nodes)), "text/yaml; charset=utf-8", nil
	case "singbox":
		raw, err := renderSingboxSubscription(nodes, effCfg.PublicHost)
		if err != nil {
			return nil, "", err
		}
		return raw, "application/json; charset=utf-8", nil
	default:
		lines := make([]string, 0, len(nodes))
		for _, n := range nodes {
			if n.ShareURI != "" {
				lines = append(lines, n.ShareURI)
			}
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
		return []byte(encoded), "text/plain; charset=utf-8", nil
	}
}

// applyBrutalSubPortOverrides 仅对用户显式启用且勾选 enable_in_sub 的 TCP 协议替换其对外接管端口，
// 未勾选的其它 TCP 订阅继续保留原始端口。
func applyBrutalSubPortOverrides(cfg proxyConfig, brutals []brutalBindingRecord) proxyConfig {
	out := cfg
	for _, b := range brutals {
		if !b.Enabled || !b.EnableInSub || b.ListenPort <= 0 || b.ListenPort > 65535 {
			continue
		}
		switch b.Protocol {
		case "vless":
			if out.VLESSPort > 0 && (b.TargetPort == int(out.VLESSPort) || strings.HasPrefix(b.InboundTag, "vless")) {
				out.VLESSPort = uint16(b.ListenPort)
			}
		case "shadowsocks":
			if out.SSPort > 0 && (b.TargetPort == int(out.SSPort) || strings.HasPrefix(b.InboundTag, "ss")) {
				out.SSPort = uint16(b.ListenPort)
			}
		}
	}
	return out
}

// appendClientDialerChainNodes 为配置了 client_dialer / both 链式代理的用户在 Clash (dialer-proxy) 与 sing-box (detour) 中追加落地链节点。
func appendClientDialerChainNodes(nodes []subNode, user userRecord, chains []chainWithSecret) []subNode {
	if len(nodes) == 0 || len(chains) == 0 {
		return nodes
	}
	entryName := nodes[0].Name
	byID := make(map[string]chainWithSecret, len(chains))
	var selected []chainWithSecret
	for _, c := range chains {
		if c.Enabled && (c.Mode == "client_dialer" || c.Mode == "both") {
			byID[c.ID] = c
		}
	}
	if user.ChainID != "" {
		if c, ok := byID[user.ChainID]; ok {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 {
		for _, c := range chains {
			if c.Enabled && c.ApplyDefault && (c.Mode == "client_dialer" || c.Mode == "both") {
				selected = append(selected, c)
				break
			}
		}
	}
	for _, c := range selected {
		prevDialer := entryName
		visited := map[string]bool{}
		cur := c
		for {
			if visited[cur.ID] {
				break
			}
			visited[cur.ID] = true
			nodeName := "chain-" + cur.Name
			clashNode, sbOut := buildChainSubEntry(nodeName, prevDialer, cur)
			if clashNode != nil && sbOut != nil {
				nodes = append(nodes, subNode{
					Name:            nodeName,
					ClashNode:       clashNode,
					SingboxOutbound: sbOut,
				})
				prevDialer = nodeName
			}
			if cur.NextHopID == "" {
				break
			}
			next, ok := byID[cur.NextHopID]
			if !ok {
				break
			}
			cur = next
		}
	}
	return nodes
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func buildChainSubEntry(name, dialer string, c chainWithSecret) (map[string]any, map[string]any) {
	switch c.Protocol {
	case "socks5":
		cn := map[string]any{"name": name, "type": "socks5", "server": c.Server, "port": c.Port, "udp": true, "dialer-proxy": dialer}
		sb := map[string]any{"type": "socks", "tag": name, "server": c.Server, "server_port": c.Port, "detour": dialer}
		if c.Secret.Username != "" {
			cn["username"] = c.Secret.Username
			cn["password"] = c.Secret.Password
			sb["username"] = c.Secret.Username
			sb["password"] = c.Secret.Password
		}
		return cn, sb
	case "http":
		cn := map[string]any{"name": name, "type": "http", "server": c.Server, "port": c.Port, "udp": true, "dialer-proxy": dialer}
		sb := map[string]any{"type": "http", "tag": name, "server": c.Server, "server_port": c.Port, "detour": dialer}
		if c.Secret.Username != "" {
			cn["username"] = c.Secret.Username
			cn["password"] = c.Secret.Password
			sb["username"] = c.Secret.Username
			sb["password"] = c.Secret.Password
		}
		return cn, sb
	case "vless":
		cn := map[string]any{"name": name, "type": "vless", "server": c.Server, "port": c.Port, "uuid": c.Secret.UUID, "tls": c.Secret.TLS, "udp": true, "dialer-proxy": dialer}
		sb := map[string]any{"type": "vless", "tag": name, "server": c.Server, "server_port": c.Port, "uuid": c.Secret.UUID, "detour": dialer}
		if c.Secret.Flow != "" {
			cn["flow"] = c.Secret.Flow
			sb["flow"] = c.Secret.Flow
		}
		if c.Secret.TLS {
			sni := firstNonEmpty(c.Secret.SNI, c.Server)
			cn["servername"] = sni
			cn["skip-cert-verify"] = c.Secret.SkipVerify
			sb["tls"] = map[string]any{"enabled": true, "server_name": sni, "insecure": c.Secret.SkipVerify}
		} else if c.Secret.SNI != "" {
			cn["servername"] = c.Secret.SNI
		}
		return cn, sb
	case "trojan":
		sni := firstNonEmpty(c.Secret.SNI, c.Server)
		cn := map[string]any{"name": name, "type": "trojan", "server": c.Server, "port": c.Port, "password": c.Secret.Password, "sni": sni, "skip-cert-verify": c.Secret.SkipVerify, "udp": true, "dialer-proxy": dialer}
		sb := map[string]any{"type": "trojan", "tag": name, "server": c.Server, "server_port": c.Port, "password": c.Secret.Password, "detour": dialer, "tls": map[string]any{"enabled": true, "server_name": sni, "insecure": c.Secret.SkipVerify}}
		return cn, sb
	case "shadowsocks":
		cn := map[string]any{"name": name, "type": "ss", "server": c.Server, "port": c.Port, "cipher": c.Secret.Method, "password": c.Secret.Password, "udp": true, "dialer-proxy": dialer}
		sb := map[string]any{"type": "shadowsocks", "tag": name, "server": c.Server, "server_port": c.Port, "method": c.Secret.Method, "password": c.Secret.Password, "detour": dialer}
		return cn, sb
	default:
		return nil, nil
	}
}

func buildUserSubscriptionNodes(cfg proxyConfig, user userRecord) []subNode {
	cleanHost := strings.Trim(strings.TrimSpace(cfg.PublicHost), "[]")
	if cleanHost == "" {
		return nil
	}
	prefix := strings.TrimSpace(user.DisplayName)
	if prefix == "" {
		prefix = user.ID
	}

	nodes := make([]subNode, 0, 3)

	// 1. VLESS Vision + REALITY
	if cfg.VLESSPort > 0 && cfg.RealitySNI != "" && cfg.RealityPublicKey != "" {
		name := prefix + "-vless"
		hostPort := net.JoinHostPort(cleanHost, strconv.Itoa(int(cfg.VLESSPort)))
		q := fmt.Sprintf("encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s",
			url.QueryEscape(cfg.RealitySNI), url.QueryEscape(cfg.RealityPublicKey))
		if cfg.RealityShortID != "" {
			q += "&sid=" + url.QueryEscape(cfg.RealityShortID)
		}
		q += "&type=tcp"
		uri := fmt.Sprintf("vless://%s@%s?%s#%s", url.PathEscape(user.VLESSUUID), hostPort, q, url.PathEscape(name))

		realityOpts := map[string]any{"public-key": cfg.RealityPublicKey}
		sbReality := map[string]any{"enabled": true, "public_key": cfg.RealityPublicKey}
		if cfg.RealityShortID != "" {
			realityOpts["short-id"] = cfg.RealityShortID
			sbReality["short_id"] = cfg.RealityShortID
		}
		nodes = append(nodes, subNode{
			Name:     name,
			ShareURI: uri,
			ClashNode: map[string]any{
				"name":               name,
				"type":               "vless",
				"server":             cleanHost,
				"port":               int(cfg.VLESSPort),
				"uuid":               user.VLESSUUID,
				"network":            "tcp",
				"tls":                true,
				"udp":                true,
				"flow":               "xtls-rprx-vision",
				"servername":         cfg.RealitySNI,
				"client-fingerprint": "chrome",
				"reality-opts":       realityOpts,
			},
			SingboxOutbound: map[string]any{
				"type":        "vless",
				"tag":         name,
				"server":      cleanHost,
				"server_port": int(cfg.VLESSPort),
				"uuid":        user.VLESSUUID,
				"flow":        "xtls-rprx-vision",
				"tls": map[string]any{
					"enabled":     true,
					"server_name": cfg.RealitySNI,
					"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
					"reality":     sbReality,
				},
			},
		})
	}

	// 2. Hysteria2
	if cfg.Hy2Port > 0 && cfg.Hy2SNI != "" {
		name := prefix + "-hy2"
		hostPort := net.JoinHostPort(cleanHost, strconv.Itoa(int(cfg.Hy2Port)))
		insecureStr := "0"
		skipVerify := false
		if !cfg.Hy2PublicTrusted {
			insecureStr = "1"
			skipVerify = true
		}
		q := fmt.Sprintf("sni=%s&insecure=%s", url.QueryEscape(cfg.Hy2SNI), insecureStr)
		if !cfg.Hy2PublicTrusted && cfg.Hy2CertPinSHA256 != "" {
			q += "&pinSHA256=" + url.QueryEscape(cfg.Hy2CertPinSHA256)
		}
		uri := fmt.Sprintf("hysteria2://%s@%s?%s#%s", url.PathEscape(user.Hy2Password), hostPort, q, url.PathEscape(name))

		clashNode := map[string]any{
			"name":             name,
			"type":             "hysteria2",
			"server":           cleanHost,
			"port":             int(cfg.Hy2Port),
			"password":         user.Hy2Password,
			"sni":              cfg.Hy2SNI,
			"skip-cert-verify": skipVerify,
		}
		if !cfg.Hy2PublicTrusted && cfg.Hy2CertPinSHA256 != "" {
			clashNode["fingerprint"] = cfg.Hy2CertPinSHA256
		}
		nodes = append(nodes, subNode{
			Name:      name,
			ShareURI:  uri,
			ClashNode: clashNode,
			SingboxOutbound: map[string]any{
				"type":        "hysteria2",
				"tag":         name,
				"server":      cleanHost,
				"server_port": int(cfg.Hy2Port),
				"password":    user.Hy2Password,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": cfg.Hy2SNI,
					"insecure":    skipVerify,
				},
			},
		})
	}

	// 3. Shadowsocks-2022（含可选 simple-obfs）
	if cfg.SSPort > 0 && cfg.SSMethod != "" {
		name := prefix + "-ss2022"
		hostPort := net.JoinHostPort(cleanHost, strconv.Itoa(int(cfg.SSPort)))
		password := user.SS2022UserKey
		if cfg.SSServerKey != "" {
			password = cfg.SSServerKey + ":" + user.SS2022UserKey
		}
		userInfo := base64.RawURLEncoding.EncodeToString([]byte(cfg.SSMethod + ":" + password))
		obfsMode := strings.ToLower(strings.TrimSpace(cfg.SSObfsMode))
		hasObfs := obfsMode == "http" || obfsMode == "tls"
		obfsHost := strings.TrimSpace(cfg.SSObfsHost)
		if hasObfs && obfsHost == "" {
			obfsHost = "www.bing.com"
		}
		var uri string
		if hasObfs {
			pluginVal := fmt.Sprintf("obfs-local;obfs=%s;obfs-host=%s", obfsMode, obfsHost)
			uri = fmt.Sprintf("ss://%s@%s/?plugin=%s#%s", userInfo, hostPort, url.QueryEscape(pluginVal), url.PathEscape(name))
		} else {
			uri = fmt.Sprintf("ss://%s@%s#%s", userInfo, hostPort, url.PathEscape(name))
		}
		clashNode := map[string]any{
			"name":     name,
			"type":     "ss",
			"server":   cleanHost,
			"port":     int(cfg.SSPort),
			"cipher":   cfg.SSMethod,
			"password": password,
			"udp":      cfg.SSUDP,
		}
		sbOut := map[string]any{
			"type":        "shadowsocks",
			"tag":         name,
			"server":      cleanHost,
			"server_port": int(cfg.SSPort),
			"method":      cfg.SSMethod,
			"password":    password,
		}
		if !cfg.SSUDP {
			sbOut["network"] = "tcp"
		}
		if hasObfs {
			clashNode["plugin"] = "obfs"
			clashNode["plugin-opts"] = map[string]any{"mode": obfsMode, "host": obfsHost}
			sbOut["plugin"] = "obfs-local"
			sbOut["plugin_opts"] = fmt.Sprintf("obfs=%s;obfs-host=%s", obfsMode, obfsHost)
		}
		nodes = append(nodes, subNode{
			Name:            name,
			ShareURI:        uri,
			ClashNode:       clashNode,
			SingboxOutbound: sbOut,
		})
	}

	return nodes
}

func renderClashSubscription(nodes []subNode) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		names = append(names, n.Name)
		writeYAMLListItemMap(&b, n.ClashNode, 2)
	}
	b.WriteString("proxy-groups:\n")
	b.WriteString("  - name: Proxy\n")
	b.WriteString("    type: select\n")
	b.WriteString("    proxies:\n")
	for _, name := range names {
		b.WriteString("      - ")
		b.WriteString(formatYAMLScalar(name))
		b.WriteByte('\n')
	}
	b.WriteString("rules:\n")
	b.WriteString("  - MATCH,Proxy\n")
	return b.String()
}

func firstStringFromAnySlice(v any, fallback string) string {
	if s, ok := v.([]string); ok && len(s) > 0 && strings.TrimSpace(s[0]) != "" {
		return strings.TrimSpace(s[0])
	}
	return fallback
}

func renderSingboxSubscription(nodes []subNode, publicHost string) ([]byte, error) {
	tags := make([]string, 0, len(nodes))
	outbounds := make([]any, 0, len(nodes)+2)
	for _, n := range nodes {
		tags = append(tags, n.Name)
	}
	outbounds = append(outbounds, map[string]any{
		"type":      "selector",
		"tag":       "proxy",
		"outbounds": tags,
	})
	for _, n := range nodes {
		outbounds = append(outbounds, n.SingboxOutbound)
	}
	outbounds = append(outbounds, map[string]any{
		"type": "direct",
		"tag":  "direct",
	})

	antiPoison := routingrules.BuildAntiPoisonDNSConfig(publicHost, nil)
	bootstrapAddr := firstStringFromAnySlice(antiPoison["bootstrap_dns"], "223.5.5.5")
	domesticAddr := firstStringFromAnySlice(antiPoison["domestic_doh"], "https://dns.alidns.com/dns-query")
	remoteAddr := firstStringFromAnySlice(antiPoison["remote_doh"], "https://1.1.1.1/dns-query")
	vpsBypass, _ := antiPoison["vps_bypass_domains"].([]string)

	dnsRules := make([]any, 0, 2)
	if len(vpsBypass) > 0 {
		dnsRules = append(dnsRules, map[string]any{
			"domain": vpsBypass,
			"server": "bootstrap_dns",
		})
	}
	dnsRules = append(dnsRules, map[string]any{
		"outbound": []string{"any"},
		"server":   "bootstrap_dns",
	})

	doc := map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": 2080,
				"sniff":       true,
			},
		},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "remote_doh", "address": remoteAddr, "detour": "proxy"},
				map[string]any{"tag": "domestic_doh", "address": domesticAddr, "address_resolver": "bootstrap_dns", "detour": "direct"},
				map[string]any{"tag": "bootstrap_dns", "address": bootstrapAddr, "detour": "direct"},
			},
			"rules":    dnsRules,
			"final":    "remote_doh",
			"strategy": "prefer_ipv4",
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"final":                 "proxy",
			"auto_detect_interface": true,
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func writeYAMLListItemMap(b *strings.Builder, m map[string]any, indent int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	lead := strings.Repeat(" ", indent)
	cont := strings.Repeat(" ", indent+2)
	for idx, k := range keys {
		prefix := cont
		if idx == 0 {
			prefix = lead + "- "
		}
		v := m[k]
		switch val := v.(type) {
		case map[string]any:
			b.WriteString(prefix)
			b.WriteString(k)
			b.WriteString(":\n")
			writeYAMLMap(b, val, indent+4)
		case []string:
			b.WriteString(prefix)
			b.WriteString(k)
			if len(val) == 0 {
				b.WriteString(": []\n")
				continue
			}
			b.WriteString(":\n")
			itemPrefix := strings.Repeat(" ", indent+4) + "- "
			for _, item := range val {
				b.WriteString(itemPrefix)
				b.WriteString(formatYAMLScalar(item))
				b.WriteByte('\n')
			}
		default:
			b.WriteString(prefix)
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(formatYAMLScalar(v))
			b.WriteByte('\n')
		}
	}
}

func writeYAMLMap(b *strings.Builder, m map[string]any, indent int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	prefix := strings.Repeat(" ", indent)
	for _, k := range keys {
		v := m[k]
		switch val := v.(type) {
		case map[string]any:
			b.WriteString(prefix)
			b.WriteString(k)
			b.WriteString(":\n")
			writeYAMLMap(b, val, indent+2)
		case []string:
			b.WriteString(prefix)
			b.WriteString(k)
			if len(val) == 0 {
				b.WriteString(": []\n")
				continue
			}
			b.WriteString(":\n")
			itemPrefix := strings.Repeat(" ", indent+2) + "- "
			for _, item := range val {
				b.WriteString(itemPrefix)
				b.WriteString(formatYAMLScalar(item))
				b.WriteByte('\n')
			}
		default:
			b.WriteString(prefix)
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(formatYAMLScalar(v))
			b.WriteByte('\n')
		}
	}
}

func formatYAMLScalar(v any) string {
	switch val := v.(type) {
	case bool:
		return strconv.FormatBool(val)
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case string:
		if needsYAMLQuoting(val) {
			return strconv.Quote(val)
		}
		return val
	default:
		s := fmt.Sprint(val)
		if needsYAMLQuoting(s) {
			return strconv.Quote(s)
		}
		return s
	}
}

func needsYAMLQuoting(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return true
	}
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off", "null", "~":
		return true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
		switch r {
		case ':', '#', '{', '}', '[', ']', ',', '&', '*', '?', '|', '<', '>', '=', '!', '%', '@', '`', '"', '\'', '\\':
			return true
		}
	}
	return strings.HasPrefix(s, "-")
}
