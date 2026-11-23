// SPDX-License-Identifier: AGPL-3.0-only

// Package export 生成标准客户端分享 URI、Clash Meta（Mihomo）节点与 sing-box outbound 配置。
package export

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// ======================== 导出端点与多格式客户端配置结构 ========================

// ExportEndpoint 描述客户端连接的公网入口地址、端口与展示备注。
type ExportEndpoint struct {
	Host  string `json:"host"`
	Port  uint16 `json:"port"`
	Label string `json:"label"`
}

// ExportBundle 汇总单个用户或节点的多格式标准客户端导出内容。
type ExportBundle struct {
	ProfileID       string         `json:"profile_id,omitempty"`
	UserID          string         `json:"user_id,omitempty"`
	Protocol        string         `json:"protocol"`
	ShareURI        string         `json:"share_uri"`
	ClashNode       map[string]any `json:"clash_node"`
	ClashYAML       string         `json:"clash_yaml"`
	SingboxOutbound map[string]any `json:"singbox_outbound"`
}

// ======================== VLESS + Reality 导出 ========================

// BuildVLESSReality 生成 VLESS Vision + REALITY 的标准 URI、Clash Meta 节点与 sing-box outbound。
func BuildVLESSReality(ep ExportEndpoint, profileID, userID, uuid, serverName, derivedPubKey, shortID string) ExportBundle {
	cleanHost := normalizeHost(ep.Host)
	hostPort := formatHostPort(cleanHost, ep.Port)
	label := resolveLabel(ep.Label, profileID, "vless-reality")

	params := []queryParam{
		{key: "encryption", val: "none"},
		{key: "flow", val: "xtls-rprx-vision"},
		{key: "security", val: "reality"},
		{key: "sni", val: serverName},
		{key: "fp", val: "chrome"},
		{key: "pbk", val: derivedPubKey},
	}
	if strings.TrimSpace(shortID) != "" {
		params = append(params, queryParam{key: "sid", val: strings.TrimSpace(shortID)})
	}
	params = append(params, queryParam{key: "type", val: "tcp"})

	shareURI := fmt.Sprintf("vless://%s@%s?%s#%s",
		url.PathEscape(uuid),
		hostPort,
		encodeQueryParams(params),
		url.PathEscape(label),
	)

	realityOpts := map[string]any{
		"public-key": derivedPubKey,
	}
	if strings.TrimSpace(shortID) != "" {
		realityOpts["short-id"] = strings.TrimSpace(shortID)
	}

	clashNode := map[string]any{
		"name":               label,
		"type":               "vless",
		"server":             cleanHost,
		"port":               int(ep.Port),
		"uuid":               uuid,
		"network":            "tcp",
		"tls":                true,
		"udp":                true,
		"flow":               "xtls-rprx-vision",
		"servername":         serverName,
		"client-fingerprint": "chrome",
		"reality-opts":       realityOpts,
	}

	singboxReality := map[string]any{
		"enabled":    true,
		"public_key": derivedPubKey,
	}
	if strings.TrimSpace(shortID) != "" {
		singboxReality["short_id"] = strings.TrimSpace(shortID)
	}

	singboxOutbound := map[string]any{
		"type":        "vless",
		"tag":         label,
		"server":      cleanHost,
		"server_port": int(ep.Port),
		"uuid":        uuid,
		"flow":        "xtls-rprx-vision",
		"tls": map[string]any{
			"enabled":     true,
			"server_name": serverName,
			"utls": map[string]any{
				"enabled":     true,
				"fingerprint": "chrome",
			},
			"reality": singboxReality,
		},
	}

	return ExportBundle{
		ProfileID:       profileID,
		UserID:          userID,
		Protocol:        "vless-reality",
		ShareURI:        shareURI,
		ClashNode:       clashNode,
		ClashYAML:       renderClashYAML(clashNode),
		SingboxOutbound: singboxOutbound,
	}
}

// ======================== Hysteria2 导出 ========================

// BuildHysteria2 生成 Hysteria2 的标准 URI、Clash Meta 节点与 sing-box outbound。
// 当 publicTrusted 为 true 时强制严格校验（insecure=0 / skip-cert-verify: false）；
// 非公信证书时设 insecure=1 并在提供时附带 pinSHA256。
func BuildHysteria2(ep ExportEndpoint, profileID, userID, authPassword, serverName string, publicTrusted bool, certPinSHA256 string) ExportBundle {
	cleanHost := normalizeHost(ep.Host)
	hostPort := formatHostPort(cleanHost, ep.Port)
	label := resolveLabel(ep.Label, profileID, "hysteria2")
	pin := strings.TrimSpace(certPinSHA256)

	insecureStr := "0"
	skipVerify := false
	if !publicTrusted {
		insecureStr = "1"
		skipVerify = true
	}

	params := []queryParam{
		{key: "sni", val: serverName},
		{key: "insecure", val: insecureStr},
	}
	if !publicTrusted && pin != "" {
		params = append(params, queryParam{key: "pinSHA256", val: pin})
	}

	shareURI := fmt.Sprintf("hysteria2://%s@%s?%s#%s",
		url.User(authPassword).String(),
		hostPort,
		encodeQueryParams(params),
		url.PathEscape(label),
	)

	clashNode := map[string]any{
		"name":             label,
		"type":             "hysteria2",
		"server":           cleanHost,
		"port":             int(ep.Port),
		"password":         authPassword,
		"sni":              serverName,
		"skip-cert-verify": skipVerify,
	}
	if !publicTrusted && pin != "" {
		clashNode["fingerprint"] = pin
	}

	singboxOutbound := map[string]any{
		"type":        "hysteria2",
		"tag":         label,
		"server":      cleanHost,
		"server_port": int(ep.Port),
		"password":    authPassword,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": serverName,
			"insecure":    skipVerify,
		},
	}

	return ExportBundle{
		ProfileID:       profileID,
		UserID:          userID,
		Protocol:        "hysteria2",
		ShareURI:        shareURI,
		ClashNode:       clashNode,
		ClashYAML:       renderClashYAML(clashNode),
		SingboxOutbound: singboxOutbound,
	}
}

// ======================== Shadowsocks-2022（含可选 simple-obfs）导出 ========================

// BuildSS2022 生成 SIP002 Shadowsocks-2022 的标准 URI、Clash Meta 节点与 sing-box outbound。
// 端口固定使用调用方传入的公网入口端口 ep.Port，绝不暴露任何内部回环转发端口。
func BuildSS2022(ep ExportEndpoint, profileID, userID, method, serverKey, userKey, obfsMode, obfsHost string, udp bool) ExportBundle {
	cleanHost := normalizeHost(ep.Host)
	hostPort := formatHostPort(cleanHost, ep.Port)
	label := resolveLabel(ep.Label, profileID, "shadowsocks-2022")

	password := serverKey
	if userKey != "" {
		password = serverKey + ":" + userKey
	}
	userInfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))

	mode := strings.ToLower(strings.TrimSpace(obfsMode))
	hasObfs := mode == "http" || mode == "tls"
	host := strings.TrimSpace(obfsHost)
	if hasObfs && host == "" {
		host = "www.bing.com"
	}

	var shareURI string
	if hasObfs {
		pluginVal := fmt.Sprintf("obfs-local;obfs=%s;obfs-host=%s", mode, host)
		shareURI = fmt.Sprintf("ss://%s@%s/?plugin=%s#%s",
			userInfo,
			hostPort,
			url.QueryEscape(pluginVal),
			url.PathEscape(label),
		)
	} else {
		shareURI = fmt.Sprintf("ss://%s@%s#%s",
			userInfo,
			hostPort,
			url.PathEscape(label),
		)
	}

	clashNode := map[string]any{
		"name":     label,
		"type":     "ss",
		"server":   cleanHost,
		"port":     int(ep.Port),
		"cipher":   method,
		"password": password,
		"udp":      udp,
	}
	if hasObfs {
		clashNode["plugin"] = "obfs"
		clashNode["plugin-opts"] = map[string]any{
			"mode": mode,
			"host": host,
		}
	}

	singboxOutbound := map[string]any{
		"type":        "shadowsocks",
		"tag":         label,
		"server":      cleanHost,
		"server_port": int(ep.Port),
		"method":      method,
		"password":    password,
	}
	if !udp {
		singboxOutbound["network"] = "tcp"
	}
	if hasObfs {
		singboxOutbound["plugin"] = "obfs-local"
		singboxOutbound["plugin_opts"] = fmt.Sprintf("obfs=%s;obfs-host=%s", mode, host)
	}

	return ExportBundle{
		ProfileID:       profileID,
		UserID:          userID,
		Protocol:        "shadowsocks-2022",
		ShareURI:        shareURI,
		ClashNode:       clashNode,
		ClashYAML:       renderClashYAML(clashNode),
		SingboxOutbound: singboxOutbound,
	}
}

// ======================== 地址规范化、查询编码与无依赖确定性 YAML 渲染 ========================

type queryParam struct {
	key string
	val string
}

func encodeQueryParams(params []queryParam) string {
	parts := make([]string, 0, len(params))
	for _, p := range params {
		parts = append(parts, url.QueryEscape(p.key)+"="+url.QueryEscape(p.val))
	}
	return strings.Join(parts, "&")
}

func normalizeHost(host string) string {
	return strings.Trim(strings.TrimSpace(host), "[]")
}

func formatHostPort(cleanHost string, port uint16) string {
	return net.JoinHostPort(cleanHost, strconv.Itoa(int(port)))
}

func resolveLabel(label, profileID, fallback string) string {
	if trimmed := strings.TrimSpace(label); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(profileID); trimmed != "" {
		return trimmed
	}
	return fallback
}

// renderClashYAML 无第三方依赖地将节点字典渲染为键序稳定的规范缩进 Clash YAML。
func renderClashYAML(node map[string]any) string {
	var b strings.Builder
	writeYAMLMap(&b, node, 0)
	return b.String()
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
			b.WriteString(":\n")
			for _, item := range val {
				b.WriteString(prefix)
				b.WriteString("  - ")
				b.WriteString(formatYAMLScalar(item))
				b.WriteByte('\n')
			}
		default:
			b.WriteString(prefix)
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(formatYAMLScalar(val))
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
	case uint16:
		return strconv.FormatUint(uint64(val), 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
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
	lower := strings.ToLower(s)
	switch lower {
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
