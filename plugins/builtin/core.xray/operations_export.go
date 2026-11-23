// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/export"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/secretmap"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xrayconfig"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 受控客户端配置导出（仅运行快照） ========================

type exportClientRequest struct {
	Host        string `json:"host,omitempty"`
	ProfileID   string `json:"profile_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	LabelPrefix string `json:"label_prefix,omitempty"`
}

type exportClientResponse struct {
	RunningRevision string                `json:"running_revision"`
	APIVersion      string                `json:"api_version"`
	Items           []export.ExportBundle `json:"items"`
}

func (i *instance) exportClient(ctx context.Context, request pluginsdk.Request) (pluginsdk.Response, error) {
	var req exportClientRequest
	trimmed := bytes.TrimSpace(request.Payload)
	if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("{}")) {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_REQUEST", "导出请求参数格式无效")
		}
	}
	req.Host = strings.TrimSpace(req.Host)
	req.ProfileID = strings.TrimSpace(req.ProfileID)
	req.UserID = strings.TrimSpace(req.UserID)
	req.LabelPrefix = strings.TrimSpace(req.LabelPrefix)
	if len(req.Host) > 253 || len(req.LabelPrefix) > 64 {
		return pluginsdk.Response{}, pluginsdk.Errorf("VALIDATION_FAILED", "host 或 label_prefix 超出长度限制")
	}
	if req.Host != "" {
		cleanHost, herr := ResolveExportHostStrict(req.Host, "")
		if herr != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("VALIDATION_FAILED", "host 必须是合法域名或非通配公网 IP，禁止包含 URI 注入字符")
		}
		req.Host = cleanHost
	}

	snap, err := i.runtime.Snapshot(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if snap.metadata == nil || snap.metadata.Current == nil || !snap.metadata.Current.Enabled ||
		snap.processState != "RUNNING" || snap.apiState != "READY" {
		return pluginsdk.Response{}, pluginsdk.Errorf("CORE_NOT_RUNNING", "核心尚未健康运行，拒绝导出客户端配置")
	}

	desired := i.desired.Load()
	if desired == nil || desired.revision != snap.metadata.Current.Revision {
		return pluginsdk.Response{}, pluginsdk.Errorf("PENDING_APPLY_EXPORT_DENIED", "当前存在未应用的配置草稿，仅允许导出已生效运行快照")
	}

	hostClient := i.Host()
	if hostClient == nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("HOST_UNAVAILABLE", "宿主凭据服务不可用")
	}

	if desired.intent != nil {
		items, err := i.exportV1(ctx, hostClient, desired.intent, req)
		if err != nil {
			return pluginsdk.Response{}, err
		}
		return readResponse(exportClientResponse{
			RunningRevision: snap.metadata.Current.Revision,
			APIVersion:      "v1",
			Items:           items,
		})
	}
	if desired.intentV2 != nil {
		items, err := i.exportV2(ctx, hostClient, desired.intentV2, req)
		if err != nil {
			return pluginsdk.Response{}, err
		}
		return readResponse(exportClientResponse{
			RunningRevision: snap.metadata.Current.Revision,
			APIVersion:      "v2",
			Items:           items,
		})
	}
	return pluginsdk.Response{}, pluginsdk.Errorf("CORE_NOT_RUNNING", "运行配置快照不可用")
}

func revealExportSecret(ctx context.Context, revealer secretmap.Revealer, ref string) (string, error) {
	raw, err := revealer.RevealSecret(ctx, ref, "core.export_client")
	if err != nil {
		return "", err
	}
	defer clear(raw)
	var decoded string
	if json.Unmarshal(raw, &decoded) == nil {
		return decoded, nil
	}
	return string(raw), nil
}

// ResolveExportHostStrict 严格校验客户端导出时的覆盖域名或公网 IP，彻底阻断 ?allowInsecure=1# 等 URI 参数劫持注入。
func ResolveExportHostStrict(overrideHost, fallbackListen string) (string, error) {
	trimmedOverride := strings.TrimSpace(overrideHost)
	raw := strings.Trim(trimmedOverride, "[]")
	if raw == "" {
		raw = strings.Trim(strings.TrimSpace(fallbackListen), "[]")
	}
	if raw == "" || len(raw) > 253 {
		return "", pluginsdk.Errorf("VALIDATION_FAILED", "当前监听地址为通配或回环地址，请在请求中显式指定合法 host")
	}
	if strings.ContainsAny(raw, "?#@/\\ \t\r\n%&=") {
		return "", pluginsdk.Errorf("VALIDATION_FAILED", "导出 host 包含非法字符")
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		if ip.Zone() != "" || ip.IsUnspecified() || (trimmedOverride == "" && ip.IsLoopback()) {
			return "", pluginsdk.Errorf("VALIDATION_FAILED", "当前监听地址为通配或回环地址，请在请求中显式指定合法 host")
		}
		return ip.Unmap().String(), nil
	}
	if !coreapi.ValidDNSName(raw) {
		return "", pluginsdk.Errorf("VALIDATION_FAILED", "导出 host 必须是合法 DNS 域名或 IP 地址")
	}
	return strings.ToLower(raw), nil
}

func formatExportLabel(prefix, profileID, userID string) string {
	base := profileID + "-" + userID
	if prefix != "" {
		return prefix + "-" + base
	}
	return base
}

func (i *instance) exportV1(ctx context.Context, host secretmap.Revealer, intent *coreapi.Intent, req exportClientRequest) ([]export.ExportBundle, error) {
	if intent.Inbound == nil || (req.ProfileID != "" && req.ProfileID != intent.Inbound.ID) {
		return []export.ExportBundle{}, nil
	}
	epHost, err := ResolveExportHostStrict(req.Host, intent.Inbound.Listen)
	if err != nil {
		return nil, err
	}
	privKey, err := revealExportSecret(ctx, host, intent.Inbound.Security.PrivateKey.ID)
	if err != nil {
		return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 REALITY 私钥以派生公钥")
	}
	pubKey, err := xrayconfig.DeriveRealityPublicKey(privKey)
	if err != nil {
		return nil, pluginsdk.Errorf("CORE_CONFIG_INVALID", "无法派生 REALITY 公钥")
	}
	serverName := intent.Inbound.Security.ServerNames[0]
	shortID := ""
	if len(intent.Inbound.Security.ShortIDs) > 0 {
		shortID = intent.Inbound.Security.ShortIDs[0]
	}

	users := slices.Clone(intent.Inbound.Users)
	slices.SortFunc(users, func(a, b coreapi.User) int { return strings.Compare(a.ID, b.ID) })
	items := make([]export.ExportBundle, 0, len(users))
	for _, u := range users {
		if req.UserID != "" && req.UserID != u.ID {
			continue
		}
		uuidStr, err := revealExportSecret(ctx, host, u.UUID.ID)
		if err != nil {
			return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取用户认证凭据")
		}
		ep := export.ExportEndpoint{
			Host:  epHost,
			Port:  uint16(intent.Inbound.Port),
			Label: formatExportLabel(req.LabelPrefix, intent.Inbound.ID, u.ID),
		}
		items = append(items, export.BuildVLESSReality(ep, intent.Inbound.ID, u.ID, uuidStr, serverName, pubKey, shortID))
	}
	return items, nil
}

func (i *instance) exportV2(ctx context.Context, host secretmap.Revealer, intent *corev2.Intent, req exportClientRequest) ([]export.ExportBundle, error) {
	profiles := slices.Clone(intent.Profiles)
	slices.SortFunc(profiles, func(a, b corev2.Profile) int { return strings.Compare(a.ID, b.ID) })

	items := make([]export.ExportBundle, 0)
	for _, p := range profiles {
		if p.Enabled == nil || !*p.Enabled {
			continue
		}
		if req.ProfileID != "" && req.ProfileID != p.ID {
			continue
		}
		epHost, err := ResolveExportHostStrict(req.Host, p.Listen)
		if err != nil {
			return nil, err
		}
		users := slices.Clone(p.Users)
		slices.SortFunc(users, func(a, b corev2.User) int { return strings.Compare(a.ID, b.ID) })

		switch p.Protocol {
		case corev2.ProtocolVLESS:
			secMode := p.VLESS.EffectiveSecurityMode()
			var serverName, pubKey, shortID string
			publicTrusted := false
			switch secMode {
			case "reality":
				privKey, err := revealExportSecret(ctx, host, p.VLESS.Security.PrivateKey.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 REALITY 私钥以派生公钥")
				}
				pubKey, err = xrayconfig.DeriveRealityPublicKey(privKey)
				if err != nil {
					return nil, pluginsdk.Errorf("CORE_CONFIG_INVALID", "无法派生 REALITY 公钥")
				}
				serverName = p.VLESS.Security.ServerNames[0]
				if len(p.VLESS.Security.ShortIDs) > 0 {
					shortID = p.VLESS.Security.ShortIDs[0]
				}
			case "tls":
				serverName = p.VLESS.TLS.ServerName
				if i.driver != nil && i.driver.controller != nil {
					if st, ok := i.driver.controller.TLSBindingInfo(p.VLESS.TLS.BindingRef); ok {
						publicTrusted = st.PublicTrusted
					}
				}
			}
			for _, u := range users {
				if req.UserID != "" && req.UserID != u.ID {
					continue
				}
				uuidStr, err := revealExportSecret(ctx, host, u.UUID.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取用户认证凭据")
				}
				ep := export.ExportEndpoint{
					Host:  epHost,
					Port:  uint16(p.Port),
					Label: formatExportLabel(req.LabelPrefix, p.ID, u.ID),
				}
				if p.VLESS.NormalizedTransport() == "raw" && secMode == "reality" && p.VLESS.Flow == "xtls-rprx-vision" && p.VLESS.Encryption == "" {
					items = append(items, export.BuildVLESSReality(ep, p.ID, u.ID, uuidStr, serverName, pubKey, shortID))
				} else {
					items = append(items, export.BuildVLESS(ep, p.ID, u.ID, uuidStr, export.VLESSOptions{
						Transport:     p.VLESS.NormalizedTransport(),
						Flow:          p.VLESS.Flow,
						SecurityMode:  secMode,
						ServerName:    serverName,
						PublicKey:     pubKey,
						ShortID:       shortID,
						PublicTrusted: publicTrusted,
						Path:          p.VLESS.Path,
						Host:          p.VLESS.Host,
						ServiceName:   p.VLESS.ServiceName,
						XHTTPMode:     p.VLESS.XHTTPMode,
						Encryption:    p.VLESS.Encryption,
					}))
				}
			}

		case corev2.ProtocolVMess:
			serverName := ""
			publicTrusted := false
			if p.VMess.SecurityMode == "tls" && p.VMess.TLS != nil {
				serverName = p.VMess.TLS.ServerName
				if i.driver != nil && i.driver.controller != nil {
					if st, ok := i.driver.controller.TLSBindingInfo(p.VMess.TLS.BindingRef); ok {
						publicTrusted = st.PublicTrusted
					}
				}
			}
			for _, u := range users {
				if req.UserID != "" && req.UserID != u.ID {
					continue
				}
				uuidStr, err := revealExportSecret(ctx, host, u.UUID.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 VMess 用户凭据")
				}
				ep := export.ExportEndpoint{Host: epHost, Port: uint16(p.Port), Label: formatExportLabel(req.LabelPrefix, p.ID, u.ID)}
				items = append(items, export.BuildVMess(ep, p.ID, u.ID, uuidStr, export.VMessOptions{
					Transport:     p.VMess.NormalizedTransport(),
					SecurityMode:  p.VMess.SecurityMode,
					ServerName:    serverName,
					PublicTrusted: publicTrusted,
					Path:          p.VMess.Path,
					Host:          p.VMess.Host,
					ServiceName:   p.VMess.ServiceName,
				}))
			}

		case corev2.ProtocolTrojan:
			var serverName, pubKey, shortID string
			publicTrusted := false
			if p.Trojan.SecurityMode == "reality" && p.Trojan.Reality != nil {
				privKey, err := revealExportSecret(ctx, host, p.Trojan.Reality.PrivateKey.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 Trojan REALITY 私钥")
				}
				pubKey, err = xrayconfig.DeriveRealityPublicKey(privKey)
				if err != nil {
					return nil, pluginsdk.Errorf("CORE_CONFIG_INVALID", "无法派生 REALITY 公钥")
				}
				serverName = p.Trojan.Reality.ServerNames[0]
				if len(p.Trojan.Reality.ShortIDs) > 0 {
					shortID = p.Trojan.Reality.ShortIDs[0]
				}
			} else if p.Trojan.TLS != nil {
				serverName = p.Trojan.TLS.ServerName
				if i.driver != nil && i.driver.controller != nil {
					if st, ok := i.driver.controller.TLSBindingInfo(p.Trojan.TLS.BindingRef); ok {
						publicTrusted = st.PublicTrusted
					}
				}
			}
			for _, u := range users {
				if req.UserID != "" && req.UserID != u.ID {
					continue
				}
				authStr, err := revealExportSecret(ctx, host, u.Auth.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 Trojan 认证口令")
				}
				ep := export.ExportEndpoint{Host: epHost, Port: uint16(p.Port), Label: formatExportLabel(req.LabelPrefix, p.ID, u.ID)}
				items = append(items, export.BuildTrojan(ep, p.ID, u.ID, authStr, export.TrojanOptions{
					Transport:     p.Trojan.NormalizedTransport(),
					SecurityMode:  p.Trojan.SecurityMode,
					ServerName:    serverName,
					PublicKey:     pubKey,
					ShortID:       shortID,
					PublicTrusted: publicTrusted,
					Path:          p.Trojan.Path,
					Host:          p.Trojan.Host,
					ServiceName:   p.Trojan.ServiceName,
				}))
			}

		case corev2.ProtocolShadowsocks:
			for _, u := range users {
				if req.UserID != "" && req.UserID != u.ID {
					continue
				}
				authStr, err := revealExportSecret(ctx, host, u.Auth.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 Shadowsocks 用户密码")
				}
				ep := export.ExportEndpoint{Host: epHost, Port: uint16(p.Port), Label: formatExportLabel(req.LabelPrefix, p.ID, u.ID)}
				items = append(items, export.BuildShadowsocks(ep, p.ID, u.ID, p.Shadowsocks.Method, authStr, p.Shadowsocks.UDP))
			}

		case corev2.ProtocolHysteria2:
			publicTrusted := false
			certPin := ""
			if i.driver != nil && i.driver.controller != nil && p.Hysteria2 != nil && p.Hysteria2.TLS != nil {
				if st, ok := i.driver.controller.TLSBindingInfo(p.Hysteria2.TLS.BindingRef); ok {
					publicTrusted = st.PublicTrusted
					certPin = st.LeafFingerprint
				}
			}
			obfsPwd := ""
			if p.Hysteria2.ObfsPassword != nil {
				var oerr error
				obfsPwd, oerr = revealExportSecret(ctx, host, p.Hysteria2.ObfsPassword.ID)
				if oerr != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 Hysteria2 混淆密码")
				}
			}
			serverName := p.Hysteria2.TLS.ServerName
			for _, u := range users {
				if req.UserID != "" && req.UserID != u.ID {
					continue
				}
				authStr, err := revealExportSecret(ctx, host, u.Auth.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 Hysteria2 认证口令")
				}
				ep := export.ExportEndpoint{
					Host:  epHost,
					Port:  uint16(p.Port),
					Label: formatExportLabel(req.LabelPrefix, p.ID, u.ID),
				}
				items = append(items, export.BuildHysteria2WithOptions(ep, p.ID, u.ID, authStr, serverName, publicTrusted, certPin, obfsPwd, p.Hysteria2.PortHopping))
			}

		case corev2.ProtocolShadowsocks2022:
			srvKeyStr, err := revealExportSecret(ctx, host, p.Shadowsocks2022.ServerKey.ID)
			if err != nil {
				return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 SS2022 服务端主密钥")
			}
			obfsMode, obfsHost := "", ""
			if p.Shadowsocks2022.Obfs != nil && p.Shadowsocks2022.Obfs.Mode != corev2.ObfsNone {
				obfsMode = p.Shadowsocks2022.Obfs.Mode
				obfsHost = p.Shadowsocks2022.Obfs.Host
			}
			for _, u := range users {
				if req.UserID != "" && req.UserID != u.ID {
					continue
				}
				pskStr := ""
				if p.Shadowsocks2022.Method != corev2.MethodChaCha20 {
					pskStr, err = revealExportSecret(ctx, host, u.PSK.ID)
					if err != nil {
						return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 SS2022 用户密钥")
					}
				}
				// 始终使用公网监听端口 p.Port，严禁暴露内部 30000..30999 混淆桥接端口。
				ep := export.ExportEndpoint{
					Host:  epHost,
					Port:  uint16(p.Port),
					Label: formatExportLabel(req.LabelPrefix, p.ID, u.ID),
				}
				items = append(items, export.BuildSS2022(ep, p.ID, u.ID, p.Shadowsocks2022.Method, srvKeyStr, pskStr, obfsMode, obfsHost, p.Shadowsocks2022.UDP))
			}

		case corev2.ProtocolAnyTLS:
			publicTrusted := false
			if i.driver != nil && i.driver.controller != nil && p.AnyTLS != nil && p.AnyTLS.TLS != nil {
				if st, ok := i.driver.controller.TLSBindingInfo(p.AnyTLS.TLS.BindingRef); ok {
					publicTrusted = st.PublicTrusted
				}
			}
			serverName := p.AnyTLS.TLS.ServerName
			for _, u := range users {
				if req.UserID != "" && req.UserID != u.ID {
					continue
				}
				authStr, err := revealExportSecret(ctx, host, u.Auth.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 AnyTLS 认证口令")
				}
				ep := export.ExportEndpoint{Host: epHost, Port: uint16(p.Port), Label: formatExportLabel(req.LabelPrefix, p.ID, u.ID)}
				items = append(items, export.BuildAnyTLS(ep, p.ID, u.ID, authStr, serverName, publicTrusted))
			}

		case corev2.ProtocolSOCKS5:
			for _, u := range users {
				if req.UserID != "" && req.UserID != u.ID {
					continue
				}
				authStr, err := revealExportSecret(ctx, host, u.Auth.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 SOCKS5 用户密码")
				}
				ep := export.ExportEndpoint{Host: epHost, Port: uint16(p.Port), Label: formatExportLabel(req.LabelPrefix, p.ID, u.ID)}
				items = append(items, export.BuildSOCKS5(ep, p.ID, u.ID, u.Username, authStr, p.SOCKS5.UDP))
			}

		case corev2.ProtocolHTTP:
			for _, u := range users {
				if req.UserID != "" && req.UserID != u.ID {
					continue
				}
				authStr, err := revealExportSecret(ctx, host, u.Auth.ID)
				if err != nil {
					return nil, pluginsdk.Errorf("SECRET_UNAVAILABLE", "无法读取 HTTP 用户密码")
				}
				ep := export.ExportEndpoint{Host: epHost, Port: uint16(p.Port), Label: formatExportLabel(req.LabelPrefix, p.ID, u.ID)}
				items = append(items, export.BuildHTTP(ep, p.ID, u.ID, u.Username, authStr))
			}
		}
	}
	return items, nil
}
