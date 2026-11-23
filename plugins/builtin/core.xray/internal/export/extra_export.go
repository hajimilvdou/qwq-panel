// SPDX-License-Identifier: AGPL-3.0-only

package export

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ======================== 全协议扩展客户端导出（VLESS 扩展 / VMess / Trojan / SS / Hy2 Obfs / AnyTLS / SOCKS5 / HTTP） ========================

// VLESSOptions 描述全传输/全安全模式的 VLESS 导出参数。
type VLESSOptions struct {
	Transport     string // raw/tcp, grpc, ws, xhttp
	Flow          string
	SecurityMode  string // reality, tls, none
	ServerName    string
	PublicKey     string
	ShortID       string
	PublicTrusted bool
	Path          string
	Host          string
	ServiceName   string
	XHTTPMode     string
	Encryption    string
}

// BuildVLESS 支持 raw/grpc/ws/xhttp × reality/tls/none × encryption 的 VLESS 客户端导出。
func BuildVLESS(ep ExportEndpoint, profileID, userID, uuid string, opts VLESSOptions) ExportBundle {
	cleanHost := normalizeHost(ep.Host)
	hostPort := formatHostPort(cleanHost, ep.Port)
	label := resolveLabel(ep.Label, profileID, "vless")

	transport := strings.ToLower(strings.TrimSpace(opts.Transport))
	if transport == "" || transport == "raw" {
		transport = "tcp"
	}
	secMode := strings.ToLower(strings.TrimSpace(opts.SecurityMode))
	if secMode == "" {
		secMode = "reality"
	}
	encryption := strings.TrimSpace(opts.Encryption)
	if encryption == "" {
		encryption = "none"
	}

	params := []queryParam{
		{key: "encryption", val: encryption},
	}
	if opts.Flow != "" {
		params = append(params, queryParam{key: "flow", val: opts.Flow})
	}
	params = append(params, queryParam{key: "security", val: secMode})
	switch secMode {
	case "reality":
		params = append(params,
			queryParam{key: "sni", val: opts.ServerName},
			queryParam{key: "fp", val: "chrome"},
			queryParam{key: "pbk", val: opts.PublicKey},
		)
		if sid := strings.TrimSpace(opts.ShortID); sid != "" {
			params = append(params, queryParam{key: "sid", val: sid})
		}
	case "tls":
		if opts.ServerName != "" {
			params = append(params, queryParam{key: "sni", val: opts.ServerName})
		}
		if !opts.PublicTrusted {
			params = append(params, queryParam{key: "allowInsecure", val: "1"})
		}
	}
	params = append(params, queryParam{key: "type", val: transport})
	switch transport {
	case "ws":
		if opts.Path != "" {
			params = append(params, queryParam{key: "path", val: opts.Path})
		}
		if opts.Host != "" {
			params = append(params, queryParam{key: "host", val: opts.Host})
		}
	case "grpc":
		if opts.ServiceName != "" {
			params = append(params, queryParam{key: "serviceName", val: opts.ServiceName})
		}
	case "xhttp":
		if opts.Path != "" {
			params = append(params, queryParam{key: "path", val: opts.Path})
		}
		if opts.Host != "" {
			params = append(params, queryParam{key: "host", val: opts.Host})
		}
		if opts.XHTTPMode != "" {
			params = append(params, queryParam{key: "mode", val: opts.XHTTPMode})
		}
	}

	shareURI := fmt.Sprintf("vless://%s@%s?%s#%s",
		url.User(uuid).String(),
		hostPort,
		encodeQueryParams(params),
		url.PathEscape(label),
	)

	clashNet := transport
	clashNode := map[string]any{
		"name":    label,
		"type":    "vless",
		"server":  cleanHost,
		"port":    int(ep.Port),
		"uuid":    uuid,
		"network": clashNet,
		"tls":     secMode == "reality" || secMode == "tls",
		"udp":     true,
	}
	if encryption != "" && encryption != "none" {
		clashNode["encryption"] = encryption
	}
	if opts.Flow != "" {
		clashNode["flow"] = opts.Flow
	}
	if secMode == "reality" {
		ro := map[string]any{"public-key": opts.PublicKey}
		if sid := strings.TrimSpace(opts.ShortID); sid != "" {
			ro["short-id"] = sid
		}
		clashNode["servername"] = opts.ServerName
		clashNode["client-fingerprint"] = "chrome"
		clashNode["reality-opts"] = ro
	} else if secMode == "tls" {
		if opts.ServerName != "" {
			clashNode["servername"] = opts.ServerName
		}
		clashNode["skip-cert-verify"] = !opts.PublicTrusted
	}
	applyClashTransport(clashNode, transport, opts.Path, opts.Host, opts.ServiceName, opts.XHTTPMode)

	var singboxOutbound map[string]any
	// sing-box 原生不支持 Xray xhttp 或 VLESS Encryption，避免输出不可用伪造结构
	if transport != "xhttp" && (encryption == "" || encryption == "none") {
		singboxOutbound = map[string]any{
			"type":        "vless",
			"tag":         label,
			"server":      cleanHost,
			"server_port": int(ep.Port),
			"uuid":        uuid,
		}
		if opts.Flow != "" {
			singboxOutbound["flow"] = opts.Flow
		}
		if secMode == "reality" {
			sbReality := map[string]any{"enabled": true, "public_key": opts.PublicKey}
			if sid := strings.TrimSpace(opts.ShortID); sid != "" {
				sbReality["short_id"] = sid
			}
			singboxOutbound["tls"] = map[string]any{
				"enabled":     true,
				"server_name": opts.ServerName,
				"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality":     sbReality,
			}
		} else if secMode == "tls" {
			singboxOutbound["tls"] = map[string]any{
				"enabled":     true,
				"server_name": opts.ServerName,
				"insecure":    !opts.PublicTrusted,
			}
		}
		applySingboxTransport(singboxOutbound, transport, opts.Path, opts.Host, opts.ServiceName)
	}

	protoTag := "vless"
	if secMode == "reality" {
		protoTag = "vless-reality"
	} else if secMode == "tls" {
		protoTag = "vless-tls"
	}
	return ExportBundle{
		ProfileID:       profileID,
		UserID:          userID,
		Protocol:        protoTag,
		ShareURI:        shareURI,
		ClashNode:       clashNode,
		ClashYAML:       renderClashYAML(clashNode),
		SingboxOutbound: singboxOutbound,
	}
}

// VMessOptions 描述 VMess 客户端导出参数。
type VMessOptions struct {
	Transport     string
	SecurityMode  string // none, tls
	ServerName    string
	PublicTrusted bool
	Path          string
	Host          string
	ServiceName   string
}

// BuildVMess 生成标准 v2rayN vmess:// Base64 JSON、Clash Meta 与 sing-box outbound。
func BuildVMess(ep ExportEndpoint, profileID, userID, uuid string, opts VMessOptions) ExportBundle {
	cleanHost := normalizeHost(ep.Host)
	label := resolveLabel(ep.Label, profileID, "vmess")
	transport := strings.ToLower(strings.TrimSpace(opts.Transport))
	if transport == "" || transport == "raw" {
		transport = "tcp"
	}
	isTLS := strings.EqualFold(strings.TrimSpace(opts.SecurityMode), "tls")
	tlsStr := ""
	if isTLS {
		tlsStr = "tls"
	}
	vmessPath := opts.Path
	if transport == "grpc" && opts.ServiceName != "" {
		vmessPath = opts.ServiceName
	}
	v2n := map[string]any{
		"v":    "2",
		"ps":   label,
		"add":  cleanHost,
		"port": strconv.Itoa(int(ep.Port)),
		"id":   uuid,
		"aid":  "0",
		"scy":  "auto",
		"net":  transport,
		"type": "none",
		"host": opts.Host,
		"path": vmessPath,
		"tls":  tlsStr,
		"sni":  opts.ServerName,
	}
	rawJSON, _ := json.Marshal(v2n)
	shareURI := "vmess://" + base64.StdEncoding.EncodeToString(rawJSON)

	clashNode := map[string]any{
		"name":    label,
		"type":    "vmess",
		"server":  cleanHost,
		"port":    int(ep.Port),
		"uuid":    uuid,
		"alterId": 0,
		"cipher":  "auto",
		"network": transport,
		"tls":     isTLS,
		"udp":     true,
	}
	if isTLS {
		if opts.ServerName != "" {
			clashNode["servername"] = opts.ServerName
		}
		clashNode["skip-cert-verify"] = !opts.PublicTrusted
	}
	applyClashTransport(clashNode, transport, opts.Path, opts.Host, opts.ServiceName, "")

	singboxOutbound := map[string]any{
		"type":        "vmess",
		"tag":         label,
		"server":      cleanHost,
		"server_port": int(ep.Port),
		"uuid":        uuid,
		"security":    "auto",
		"alter_id":    0,
	}
	if isTLS {
		singboxOutbound["tls"] = map[string]any{
			"enabled":     true,
			"server_name": opts.ServerName,
			"insecure":    !opts.PublicTrusted,
		}
	}
	applySingboxTransport(singboxOutbound, transport, opts.Path, opts.Host, opts.ServiceName)

	return ExportBundle{
		ProfileID:       profileID,
		UserID:          userID,
		Protocol:        "vmess",
		ShareURI:        shareURI,
		ClashNode:       clashNode,
		ClashYAML:       renderClashYAML(clashNode),
		SingboxOutbound: singboxOutbound,
	}
}

// TrojanOptions 描述 Trojan 客户端导出参数。
type TrojanOptions struct {
	Transport     string
	SecurityMode  string // tls, reality
	ServerName    string
	PublicKey     string
	ShortID       string
	PublicTrusted bool
	Path          string
	Host          string
	ServiceName   string
}

// BuildTrojan 生成 trojan:// 标准 URI、Clash Meta 与 sing-box outbound。
func BuildTrojan(ep ExportEndpoint, profileID, userID, password string, opts TrojanOptions) ExportBundle {
	cleanHost := normalizeHost(ep.Host)
	hostPort := formatHostPort(cleanHost, ep.Port)
	label := resolveLabel(ep.Label, profileID, "trojan")
	transport := strings.ToLower(strings.TrimSpace(opts.Transport))
	if transport == "" || transport == "raw" {
		transport = "tcp"
	}
	secMode := strings.ToLower(strings.TrimSpace(opts.SecurityMode))
	if secMode == "" {
		secMode = "tls"
	}

	params := []queryParam{{key: "security", val: secMode}}
	if opts.ServerName != "" {
		params = append(params, queryParam{key: "sni", val: opts.ServerName})
	}
	if secMode == "reality" {
		params = append(params,
			queryParam{key: "fp", val: "chrome"},
			queryParam{key: "pbk", val: opts.PublicKey},
		)
		if sid := strings.TrimSpace(opts.ShortID); sid != "" {
			params = append(params, queryParam{key: "sid", val: sid})
		}
	} else if !opts.PublicTrusted {
		params = append(params, queryParam{key: "allowInsecure", val: "1"})
	}
	params = append(params, queryParam{key: "type", val: transport})
	switch transport {
	case "ws":
		if opts.Path != "" {
			params = append(params, queryParam{key: "path", val: opts.Path})
		}
		if opts.Host != "" {
			params = append(params, queryParam{key: "host", val: opts.Host})
		}
	case "grpc":
		if opts.ServiceName != "" {
			params = append(params, queryParam{key: "serviceName", val: opts.ServiceName})
		}
	}

	shareURI := fmt.Sprintf("trojan://%s@%s?%s#%s",
		url.User(password).String(),
		hostPort,
		encodeQueryParams(params),
		url.PathEscape(label),
	)

	clashNode := map[string]any{
		"name":     label,
		"type":     "trojan",
		"server":   cleanHost,
		"port":     int(ep.Port),
		"password": password,
		"network":  transport,
		"sni":      opts.ServerName,
		"udp":      true,
	}
	if secMode == "reality" {
		ro := map[string]any{"public-key": opts.PublicKey}
		if sid := strings.TrimSpace(opts.ShortID); sid != "" {
			ro["short-id"] = sid
		}
		clashNode["client-fingerprint"] = "chrome"
		clashNode["reality-opts"] = ro
	} else {
		clashNode["skip-cert-verify"] = !opts.PublicTrusted
	}
	applyClashTransport(clashNode, transport, opts.Path, opts.Host, opts.ServiceName, "")

	singboxOutbound := map[string]any{
		"type":        "trojan",
		"tag":         label,
		"server":      cleanHost,
		"server_port": int(ep.Port),
		"password":    password,
	}
	if secMode == "reality" {
		sbReality := map[string]any{"enabled": true, "public_key": opts.PublicKey}
		if sid := strings.TrimSpace(opts.ShortID); sid != "" {
			sbReality["short_id"] = sid
		}
		singboxOutbound["tls"] = map[string]any{
			"enabled":     true,
			"server_name": opts.ServerName,
			"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality":     sbReality,
		}
	} else {
		singboxOutbound["tls"] = map[string]any{
			"enabled":     true,
			"server_name": opts.ServerName,
			"insecure":    !opts.PublicTrusted,
		}
	}
	applySingboxTransport(singboxOutbound, transport, opts.Path, opts.Host, opts.ServiceName)

	return ExportBundle{
		ProfileID:       profileID,
		UserID:          userID,
		Protocol:        "trojan",
		ShareURI:        shareURI,
		ClashNode:       clashNode,
		ClashYAML:       renderClashYAML(clashNode),
		SingboxOutbound: singboxOutbound,
	}
}

// BuildShadowsocks 生成传统 AEAD Shadowsocks 导出。
func BuildShadowsocks(ep ExportEndpoint, profileID, userID, method, password string, udp bool) ExportBundle {
	bundle := BuildSS2022(ep, profileID, userID, method, password, "", "", "", udp)
	bundle.Protocol = "shadowsocks"
	return bundle
}

// BuildHysteria2WithOptions 在基础 Hysteria2 导出上附带 Salamander 混淆与端口跳跃参数。
func BuildHysteria2WithOptions(ep ExportEndpoint, profileID, userID, authPassword, serverName string, publicTrusted bool, certPinSHA256, obfsPassword, portHopping string) ExportBundle {
	bundle := BuildHysteria2(ep, profileID, userID, authPassword, serverName, publicTrusted, certPinSHA256)
	obfs := strings.TrimSpace(obfsPassword)
	ports := strings.TrimSpace(portHopping)
	if obfs == "" && ports == "" {
		return bundle
	}
	// 重新构建 ShareURI 与节点配置以附带 obfs 与 mport
	cleanHost := normalizeHost(ep.Host)
	hostPort := formatHostPort(cleanHost, ep.Port)
	label := resolveLabel(ep.Label, profileID, "hysteria2")
	insecureStr := "0"
	if !publicTrusted {
		insecureStr = "1"
	}
	params := []queryParam{
		{key: "sni", val: serverName},
		{key: "insecure", val: insecureStr},
	}
	if !publicTrusted && strings.TrimSpace(certPinSHA256) != "" {
		params = append(params, queryParam{key: "pinSHA256", val: strings.TrimSpace(certPinSHA256)})
	}
	if obfs != "" {
		params = append(params,
			queryParam{key: "obfs", val: "salamander"},
			queryParam{key: "obfs-password", val: obfs},
		)
		bundle.ClashNode["obfs"] = "salamander"
		bundle.ClashNode["obfs-password"] = obfs
		bundle.SingboxOutbound["obfs"] = map[string]any{
			"type":     "salamander",
			"password": obfs,
		}
	}
	if ports != "" {
		params = append(params, queryParam{key: "mport", val: ports})
		bundle.ClashNode["ports"] = ports
		var sbPorts []string
		for _, seg := range strings.Split(ports, ",") {
			seg = strings.TrimSpace(seg)
			if seg != "" {
				sbPorts = append(sbPorts, strings.ReplaceAll(seg, "-", ":"))
			}
		}
		if len(sbPorts) > 0 {
			bundle.SingboxOutbound["server_ports"] = sbPorts
		}
	}
	bundle.ShareURI = fmt.Sprintf("hysteria2://%s@%s?%s#%s",
		url.User(authPassword).String(),
		hostPort,
		encodeQueryParams(params),
		url.PathEscape(label),
	)
	bundle.ClashYAML = renderClashYAML(bundle.ClashNode)
	return bundle
}

// BuildAnyTLS 生成 anytls:// 标准 URI、Clash Meta（Mihomo）与 sing-box outbound。
func BuildAnyTLS(ep ExportEndpoint, profileID, userID, password, serverName string, publicTrusted bool) ExportBundle {
	cleanHost := normalizeHost(ep.Host)
	hostPort := formatHostPort(cleanHost, ep.Port)
	label := resolveLabel(ep.Label, profileID, "anytls")
	skipVerify := !publicTrusted
	insecureStr := "0"
	if skipVerify {
		insecureStr = "1"
	}
	params := []queryParam{
		{key: "sni", val: serverName},
		{key: "insecure", val: insecureStr},
	}
	shareURI := fmt.Sprintf("anytls://%s@%s?%s#%s",
		url.User(password).String(),
		hostPort,
		encodeQueryParams(params),
		url.PathEscape(label),
	)
	clashNode := map[string]any{
		"name":             label,
		"type":             "anytls",
		"server":           cleanHost,
		"port":             int(ep.Port),
		"password":         password,
		"sni":              serverName,
		"skip-cert-verify": skipVerify,
		"udp":              true,
	}
	singboxOutbound := map[string]any{
		"type":        "anytls",
		"tag":         label,
		"server":      cleanHost,
		"server_port": int(ep.Port),
		"password":    password,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": serverName,
			"insecure":    skipVerify,
		},
	}
	return ExportBundle{
		ProfileID:       profileID,
		UserID:          userID,
		Protocol:        "anytls",
		ShareURI:        shareURI,
		ClashNode:       clashNode,
		ClashYAML:       renderClashYAML(clashNode),
		SingboxOutbound: singboxOutbound,
	}
}

// BuildSOCKS5 生成 socks5:// 标准 URI、Clash Meta 与 sing-box outbound。
func BuildSOCKS5(ep ExportEndpoint, profileID, userID, username, password string, udp bool) ExportBundle {
	cleanHost := normalizeHost(ep.Host)
	hostPort := formatHostPort(cleanHost, ep.Port)
	label := resolveLabel(ep.Label, profileID, "socks5")
	if username == "" {
		username = userID
	}
	shareURI := fmt.Sprintf("socks5://%s@%s#%s",
		url.UserPassword(username, password).String(),
		hostPort,
		url.PathEscape(label),
	)
	clashNode := map[string]any{
		"name":     label,
		"type":     "socks5",
		"server":   cleanHost,
		"port":     int(ep.Port),
		"username": username,
		"password": password,
		"udp":      udp,
	}
	singboxOutbound := map[string]any{
		"type":        "socks",
		"tag":         label,
		"server":      cleanHost,
		"server_port": int(ep.Port),
		"version":     "5",
		"username":    username,
		"password":    password,
	}
	return ExportBundle{
		ProfileID:       profileID,
		UserID:          userID,
		Protocol:        "socks5",
		ShareURI:        shareURI,
		ClashNode:       clashNode,
		ClashYAML:       renderClashYAML(clashNode),
		SingboxOutbound: singboxOutbound,
	}
}

// BuildHTTP 生成 http:// 标准 URI、Clash Meta 与 sing-box outbound。
func BuildHTTP(ep ExportEndpoint, profileID, userID, username, password string) ExportBundle {
	cleanHost := normalizeHost(ep.Host)
	hostPort := formatHostPort(cleanHost, ep.Port)
	label := resolveLabel(ep.Label, profileID, "http")
	if username == "" {
		username = userID
	}
	shareURI := fmt.Sprintf("http://%s@%s#%s",
		url.UserPassword(username, password).String(),
		hostPort,
		url.PathEscape(label),
	)
	clashNode := map[string]any{
		"name":     label,
		"type":     "http",
		"server":   cleanHost,
		"port":     int(ep.Port),
		"username": username,
		"password": password,
	}
	singboxOutbound := map[string]any{
		"type":        "http",
		"tag":         label,
		"server":      cleanHost,
		"server_port": int(ep.Port),
		"username":    username,
		"password":    password,
	}
	return ExportBundle{
		ProfileID:       profileID,
		UserID:          userID,
		Protocol:        "http",
		ShareURI:        shareURI,
		ClashNode:       clashNode,
		ClashYAML:       renderClashYAML(clashNode),
		SingboxOutbound: singboxOutbound,
	}
}

func applyClashTransport(node map[string]any, transport, path, host, serviceName, xhttpMode string) {
	switch transport {
	case "ws":
		wsOpts := map[string]any{"path": nonEmptyOr(path, "/")}
		if host != "" {
			wsOpts["headers"] = map[string]any{"Host": host}
		}
		node["ws-opts"] = wsOpts
	case "grpc":
		node["grpc-opts"] = map[string]any{"grpc-service-name": nonEmptyOr(serviceName, "grpc")}
	case "xhttp":
		xOpts := map[string]any{"path": nonEmptyOr(path, "/")}
		if host != "" {
			xOpts["host"] = host
		}
		if xhttpMode != "" {
			xOpts["mode"] = xhttpMode
		}
		node["xhttp-opts"] = xOpts
	}
}

func applySingboxTransport(out map[string]any, transport, path, host, serviceName string) {
	switch transport {
	case "ws":
		tr := map[string]any{"type": "ws", "path": nonEmptyOr(path, "/")}
		if host != "" {
			tr["headers"] = map[string]any{"Host": host}
		}
		out["transport"] = tr
	case "grpc":
		out["transport"] = map[string]any{"type": "grpc", "service_name": nonEmptyOr(serviceName, "grpc")}
	case "xhttp":
		tr := map[string]any{"type": "http", "path": nonEmptyOr(path, "/")}
		if host != "" {
			tr["host"] = []string{host}
		}
		out["transport"] = tr
	}
}

func nonEmptyOr(v, fallback string) string {
	if s := strings.TrimSpace(v); s != "" {
		return s
	}
	return fallback
}
