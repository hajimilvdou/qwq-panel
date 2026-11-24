// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 默认 Reality SNI 候选池与可测探针钩子 ========================

var defaultRealitySNICandidates = []string{
	"www.microsoft.com",
	"www.apple.com",
	"dl.google.com",
	"www.icloud.com",
	"swdist.apple.com",
	"addons.mozilla.org",
	"www.lovelive-anime.jp",
}

// sniProbeFunc 可在单元测试中替换，生产环境执行真实 TLS 1.3 握手探测。
var sniProbeFunc = probeSNIDomainReal

type sniProbeResult struct {
	Domain     string `json:"domain"`
	OK         bool   `json:"ok"`
	LatencyMS  int64  `json:"latency_ms"`
	TLSVersion string `json:"tls_version,omitempty"`
	TLS13      bool   `json:"tls13"`
	ALPN       string `json:"alpn,omitempty"`
	Error      string `json:"error,omitempty"`
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "unknown"
	}
}

func probeSNIDomainReal(ctx context.Context, domain string, timeout time.Duration) sniProbeResult {
	res := sniProbeResult{Domain: domain, LatencyMS: -1}
	cleanDomain, ok := ValidatePublicSNIDomain(domain)
	if !ok {
		res.Error = "仅允许探测合法公网域名（禁止端口、IP 字面量或内网主机名）"
		return res
	}
	res.Domain = cleanDomain
	addr := net.JoinHostPort(cleanDomain, "443")

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	dialer := NewPublicProbeDialer(timeout)
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: cleanDomain,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		res.Error = err.Error()
		return res
	}
	elapsed := time.Since(start).Milliseconds()
	if elapsed < 1 {
		elapsed = 1
	}
	st := tlsConn.ConnectionState()
	res.OK = true
	res.LatencyMS = elapsed
	res.TLSVersion = tlsVersionName(st.Version)
	res.TLS13 = st.Version == tls.VersionTLS13
	res.ALPN = st.NegotiatedProtocol
	return res
}

// ======================== 节点草稿归一化（Simplified / Expert 模式） ========================

type nodeUpsertRequest struct {
	ID           string      `json:"id"`
	Mode         string      `json:"mode"` // "simplified" | "expert"
	Name         string      `json:"name"`
	Protocol     string      `json:"protocol"`
	Transport    string      `json:"transport"`
	SecurityMode string      `json:"security_mode"`
	Listen       string      `json:"listen"`
	Server       string      `json:"server"`
	Port         int         `json:"port"`
	Enabled      *bool       `json:"enabled"`
	Tags         []string    `json:"tags"`
	Config       *nodeConfig `json:"config"`
	SyncCore     *bool       `json:"sync_core"`
}

func normalizeNodeDraft(in nodeUpsertRequest, existing *proxyNodeRecord, usedPorts map[int]bool, publicHost string) (proxyNodeRecord, error) {
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = "simplified"
	}
	if mode != "simplified" && mode != "expert" {
		return proxyNodeRecord{}, invalidField("/mode", "INVALID_VALUE", "mode 仅支持 simplified 或 expert")
	}

	proto := strings.ToLower(strings.TrimSpace(in.Protocol))
	if proto == "" && existing != nil {
		proto = existing.Protocol
	}
	if !isValidManagedProtocol(proto) {
		return proxyNodeRecord{}, invalidField("/protocol", "INVALID_VALUE", "仅支持 vless、vmess、trojan、shadowsocks、shadowsocks2022、hysteria2、anytls、socks5 或 http")
	}

	id := strings.ToLower(strings.TrimSpace(in.ID))
	if id == "" {
		if existing != nil {
			id = existing.ID
		} else {
			id = generateNodeID(proto)
		}
	}
	if !validEntityIDPattern.MatchString(id) {
		return proxyNodeRecord{}, invalidField("/id", "INVALID_ID", "节点 ID 必须是 1 至 32 位小写字母开头的合法标识")
	}

	listen := strings.TrimSpace(in.Listen)
	if listen == "" {
		if existing != nil && existing.Listen != "" {
			listen = existing.Listen
		} else {
			listen = "0.0.0.0"
		}
	}
	if addr, err := netip.ParseAddr(listen); err != nil || addr.Zone() != "" {
		return proxyNodeRecord{}, invalidField("/listen", "INVALID_VALUE", "listen 必须是无 zone 的合法 IPv4/IPv6 地址")
	}

	port := in.Port
	if port == 0 {
		if existing != nil && existing.Port > 0 {
			port = existing.Port
		} else {
			port = pickUnusedHighPort(usedPorts)
		}
	}
	if port < 1 || port > 65535 {
		return proxyNodeRecord{}, invalidField("/port", "OUT_OF_RANGE", "port 必须在 1..65535 之间")
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	} else if existing != nil {
		enabled = existing.Enabled
	}

	server := strings.TrimSpace(in.Server)
	if idx := strings.Index(server, "://"); idx >= 0 {
		server = server[idx+3:]
	}
	if slash := strings.IndexByte(server, '/'); slash >= 0 {
		server = server[:slash]
	}
	server = strings.TrimSpace(server)
	if server == "" {
		if existing != nil && existing.Server != "" {
			server = existing.Server
		} else {
			server = publicHost
		}
	}

	transport := strings.ToLower(strings.TrimSpace(in.Transport))
	if transport == "" && existing != nil {
		transport = existing.Transport
	}
	if transport == "tcp" {
		transport = "raw"
	}
	secMode := strings.ToLower(strings.TrimSpace(in.SecurityMode))
	if secMode == "" && existing != nil {
		secMode = existing.SecurityMode
	}

	var cfg nodeConfig
	if existing != nil {
		cfg = existing.Config
	}
	if in.Config != nil {
		mergeNodeConfig(&cfg, *in.Config, mode, transport != "" && transport != "raw")
	} else if transport != "" && transport != "raw" {
		cfg.Flow = ""
	}

	// 按协议补齐极简模式默认值与密钥，并校验专家模式合法组合
	switch proto {
	case corev2.ProtocolVLESS:
		if transport == "" {
			transport = "raw"
		}
		if transport != "raw" && transport != "grpc" && transport != "ws" && transport != "xhttp" {
			return proxyNodeRecord{}, invalidField("/transport", "INVALID_VALUE", "VLESS 传输仅支持 raw/tcp、grpc、ws 或 xhttp")
		}
		if secMode == "" {
			secMode = "reality"
		}
		if secMode != "reality" && secMode != "tls" && secMode != "none" {
			return proxyNodeRecord{}, invalidField("/security_mode", "INVALID_VALUE", "VLESS 安全模式仅支持 reality、tls 或 none")
		}
		if cfg.UUID == "" {
			cfg.UUID = generateNodeUUIDv4()
		}
		if transport == "raw" && (secMode == "reality" || secMode == "tls") {
			if cfg.Flow == "" && mode == "simplified" {
				cfg.Flow = "xtls-rprx-vision"
			}
		} else if cfg.Flow == "xtls-rprx-vision" {
			if mode == "simplified" {
				cfg.Flow = ""
			} else {
				return proxyNodeRecord{}, invalidField("/config/flow", "INVALID_VALUE", "xtls-rprx-vision 仅支持 raw/tcp + reality/tls")
			}
		}
		if secMode == "reality" {
			if err := fillRealityDefaults(&cfg); err != nil {
				return proxyNodeRecord{}, err
			}
		}
		if transport == "ws" && cfg.Path == "" {
			cfg.Path = "/vless"
		}
		if transport == "grpc" && cfg.ServiceName == "" {
			cfg.ServiceName = "vless-grpc"
		}
		if transport == "xhttp" {
			if cfg.Path == "" {
				cfg.Path = "/xhttp"
			}
			if cfg.XHTTPMode == "" {
				cfg.XHTTPMode = "auto"
			}
		}

	case corev2.ProtocolVMess:
		if transport == "" {
			transport = "ws"
		}
		if transport != "raw" && transport != "ws" && transport != "grpc" {
			return proxyNodeRecord{}, invalidField("/transport", "INVALID_VALUE", "VMess 传输仅支持 raw/tcp、ws 或 grpc")
		}
		if secMode == "" {
			secMode = "none"
		}
		if secMode != "none" && secMode != "tls" {
			return proxyNodeRecord{}, invalidField("/security_mode", "INVALID_VALUE", "VMess 安全模式仅支持 none 或 tls")
		}
		if cfg.UUID == "" {
			cfg.UUID = generateNodeUUIDv4()
		}
		if transport == "ws" && cfg.Path == "" {
			cfg.Path = "/vmess"
		}
		if transport == "grpc" && cfg.ServiceName == "" {
			cfg.ServiceName = "vmess-grpc"
		}

	case corev2.ProtocolTrojan:
		if transport == "" {
			transport = "raw"
		}
		if transport != "raw" && transport != "grpc" && transport != "ws" {
			return proxyNodeRecord{}, invalidField("/transport", "INVALID_VALUE", "Trojan 传输仅支持 raw/tcp、grpc 或 ws")
		}
		if secMode == "" {
			secMode = "tls"
		}
		if secMode != "tls" && secMode != "reality" {
			return proxyNodeRecord{}, invalidField("/security_mode", "INVALID_VALUE", "Trojan 安全模式仅支持 tls 或 reality")
		}
		if cfg.Password == "" {
			cfg.Password = randomAlphaNum(24)
		}
		if secMode == "reality" {
			if err := fillRealityDefaults(&cfg); err != nil {
				return proxyNodeRecord{}, err
			}
		}
		if transport == "ws" && cfg.Path == "" {
			cfg.Path = "/trojan"
		}
		if transport == "grpc" && cfg.ServiceName == "" {
			cfg.ServiceName = "trojan-grpc"
		}

	case corev2.ProtocolShadowsocks:
		transport = "raw"
		secMode = "none"
		if cfg.Method == "" {
			cfg.Method = corev2.MethodAEADAES256GCM
		}
		if cfg.Method != corev2.MethodAEADAES256GCM && cfg.Method != corev2.MethodAEADAES128GCM && cfg.Method != corev2.MethodAEADChaCha20 {
			return proxyNodeRecord{}, invalidField("/config/method", "INVALID_VALUE", "传统 Shadowsocks 仅支持 aes-256-gcm、aes-128-gcm 或 chacha20-ietf-poly1305")
		}
		if cfg.Password == "" {
			cfg.Password = randomAlphaNum(24)
		}
		if cfg.UDP == nil {
			cfg.UDP = boolPtr(true)
		}

	case corev2.ProtocolShadowsocks2022:
		transport = "raw"
		secMode = "none"
		if cfg.Method == "" {
			cfg.Method = corev2.MethodAES128
		}
		if cfg.Method != corev2.MethodAES128 && cfg.Method != corev2.MethodAES256 && cfg.Method != corev2.MethodChaCha20 {
			return proxyNodeRecord{}, invalidField("/config/method", "INVALID_VALUE", "SS2022 仅支持 2022-blake3-aes-128-gcm、2022-blake3-aes-256-gcm 或 2022-blake3-chacha20-poly1305")
		}
		wantKeyBytes := 16
		if cfg.Method == corev2.MethodAES256 || cfg.Method == corev2.MethodChaCha20 {
			wantKeyBytes = 32
		}
		if cfg.ServerKey == "" {
			cfg.ServerKey = generateNodeSS2022Key(cfg.Method)
		} else if rawKey, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.ServerKey)); derr != nil || len(rawKey) != wantKeyBytes {
			return proxyNodeRecord{}, invalidField("/config/server_key", "INVALID_VALUE", fmt.Sprintf("SS2022 (%s) server_key 必须为 %d 字节 Base64 密钥", cfg.Method, wantKeyBytes))
		}
		if cfg.UserKey == "" {
			cfg.UserKey = generateNodeSS2022Key(cfg.Method)
		} else if rawKey, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.UserKey)); derr != nil || len(rawKey) != wantKeyBytes {
			return proxyNodeRecord{}, invalidField("/config/user_key", "INVALID_VALUE", fmt.Sprintf("SS2022 (%s) user_key 必须为 %d 字节 Base64 密钥", cfg.Method, wantKeyBytes))
		}
		if cfg.ObfsMode == "" {
			cfg.ObfsMode = corev2.ObfsNone
		}
		if cfg.UDP == nil {
			cfg.UDP = boolPtr(cfg.ObfsMode == corev2.ObfsNone)
		}

	case corev2.ProtocolHysteria2:
		transport = "udp"
		secMode = "tls"
		if cfg.Password == "" {
			cfg.Password = randomAlphaNum(24)
		}
		if cfg.SNI == "" {
			cfg.SNI = firstNonEmpty(server, "hy2.example.com")
		}

	case corev2.ProtocolAnyTLS:
		transport = "raw"
		secMode = "tls"
		if cfg.Password == "" {
			cfg.Password = randomAlphaNum(24)
		}
		if cfg.SNI == "" {
			cfg.SNI = firstNonEmpty(server, "anytls.example.com")
		}
		cfg.PaddingScheme = normalizePaddingScheme(cfg.PaddingScheme)

	case corev2.ProtocolSOCKS5:
		transport = "raw"
		secMode = "none"
		if cfg.Username == "" {
			cfg.Username = "user"
		}
		if cfg.Password == "" {
			cfg.Password = randomAlphaNum(16)
		}
		if cfg.UDP == nil {
			cfg.UDP = boolPtr(true)
		}

	case corev2.ProtocolHTTP:
		transport = "raw"
		secMode = "none"
		if cfg.Username == "" {
			cfg.Username = "user"
		}
		if cfg.Password == "" {
			cfg.Password = randomAlphaNum(16)
		}
	}

	if cfg.Sniffing == nil {
		cfg.Sniffing = boolPtr(true)
	}

	name := strings.TrimSpace(in.Name)
	if name == "" {
		if existing != nil && existing.Name != "" {
			name = existing.Name
		} else {
			name = fmt.Sprintf("%s-%s-%d", strings.ToUpper(proto), transport, port)
		}
	}
	if len(name) > 96 {
		return proxyNodeRecord{}, invalidField("/name", "INVALID_VALUE", "节点名称不能超过 96 字符")
	}

	tags := in.Tags
	if tags == nil && existing != nil {
		tags = existing.Tags
	}
	if len(tags) == 0 {
		tags = []string{proto}
		if secMode != "" && secMode != "none" {
			tags = append(tags, secMode)
		}
	}

	return proxyNodeRecord{
		ID:            id,
		Source:        "managed",
		Name:          name,
		Protocol:      proto,
		Transport:     transport,
		SecurityMode:  secMode,
		Listen:        listen,
		Server:        server,
		Port:          port,
		Config:        cfg,
		Tags:          normalizeNodeTags(tags),
		Enabled:       enabled,
		LastLatencyMS: -1,
	}, nil
}

func fillRealityDefaults(cfg *nodeConfig) error {
	if cfg.SNI == "" {
		cfg.SNI = defaultRealitySNICandidates[0]
	}
	if cfg.Target == "" {
		cfg.Target = cfg.SNI + ":443"
	}
	if cfg.PrivateKey == "" {
		priv, pub, err := generateRealityKeyPair()
		if err != nil {
			return err
		}
		cfg.PrivateKey = priv
		cfg.PublicKey = pub
	} else {
		// 统一归一化为 RawURLEncoding，兼容直接粘贴 x-ui / 3x-ui 的标准 Base64 私钥并自动推导公钥。
		normPriv, pub, err := normalizeRealityPrivateKey(cfg.PrivateKey)
		if err != nil {
			return err
		}
		cfg.PrivateKey = normPriv
		if cfg.PublicKey == "" {
			cfg.PublicKey = pub
		}
	}
	if cfg.ShortID == "" {
		cfg.ShortID = generateShortIDHex(4)
	}
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = "chrome"
	}
	return nil
}

func mergeNodeConfig(dst *nodeConfig, src nodeConfig, mode string, nonRawTransport bool) {
	if src.Flow != "" {
		dst.Flow = src.Flow
	} else if mode == "expert" || nonRawTransport {
		dst.Flow = ""
	}
	if src.UUID != "" {
		dst.UUID = src.UUID
	}
	if src.Password != "" {
		dst.Password = src.Password
	}
	if src.Username != "" {
		dst.Username = src.Username
	}
	if src.Method != "" {
		dst.Method = src.Method
	}
	if src.ServerKey != "" {
		dst.ServerKey = src.ServerKey
	}
	if src.UserKey != "" {
		dst.UserKey = src.UserKey
	}
	if src.SNI != "" {
		dst.SNI = src.SNI
	}
	if src.Target != "" {
		dst.Target = src.Target
	}
	if src.PrivateKey != "" {
		dst.PrivateKey = src.PrivateKey
		if src.PublicKey == "" {
			dst.PublicKey = ""
		}
	}
	if src.PublicKey != "" {
		dst.PublicKey = src.PublicKey
	}
	if src.ShortID != "" {
		dst.ShortID = src.ShortID
	}
	if src.Fingerprint != "" {
		dst.Fingerprint = src.Fingerprint
	}
	if src.BindingRef != "" {
		dst.BindingRef = src.BindingRef
	}
	if src.Path != "" {
		dst.Path = src.Path
	}
	if src.Host != "" {
		dst.Host = src.Host
	}
	if src.ServiceName != "" {
		dst.ServiceName = src.ServiceName
	}
	if src.XHTTPMode != "" {
		dst.XHTTPMode = src.XHTTPMode
	}
	if src.Decryption != "" {
		dst.Decryption = src.Decryption
	}
	if src.Encryption != "" {
		dst.Encryption = src.Encryption
	}
	if src.ObfsMode != "" {
		dst.ObfsMode = src.ObfsMode
	}
	if src.ObfsHost != "" {
		dst.ObfsHost = src.ObfsHost
	}
	if src.ObfsPassword != "" {
		dst.ObfsPassword = src.ObfsPassword
	}
	if src.PortHopping != "" {
		dst.PortHopping = src.PortHopping
	}
	if len(src.PaddingScheme) > 0 {
		dst.PaddingScheme = slices.Clone(src.PaddingScheme)
	}
	if src.UDP != nil {
		dst.UDP = src.UDP
	}
	if src.Sniffing != nil {
		dst.Sniffing = src.Sniffing
	}
	if src.Insecure != nil {
		dst.Insecure = src.Insecure
	}
}

func redactNodeConfig(cfg *nodeConfig) {
	if cfg == nil {
		return
	}
	cfg.PrivateKey = ""
	cfg.ServerKey = ""
	cfg.Decryption = ""
	cfg.Password = ""
	cfg.ObfsPassword = ""
}

// ======================== 7 项节点构建与管理 Operation 处理器 ========================

func (i *instance) handleNodesList(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		Source      string `json:"source"`
		Protocol    string `json:"protocol"`
		Tag         string `json:"tag"`
		Search      string `json:"search"`
		EnabledOnly bool   `json:"enabled_only"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	nodes, err := i.store.ListNodes(ctx, in.Source, in.Protocol, in.Tag, in.Search, in.EnabledOnly)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	cfg := i.configSnapshot()
	activePorts := map[string]bool{}
	for _, p := range i.discoverCoreXrayInboundPorts(ctx, nil) {
		if p.Enabled {
			activePorts[p.ProfileID] = true
		}
	}
	managedCount, externalCount := 0, 0
	for idx := range nodes {
		if nodes[idx].Source == "managed" {
			managedCount++
			if nodes[idx].Enabled {
				if nodes[idx].Protocol == corev2.ProtocolHysteria2 {
					nodes[idx].Listening = activePorts[nodes[idx].ID]
				} else {
					nodes[idx].Listening = probeLocalPortListening(nodes[idx].Port)
				}
			}
		} else {
			externalCount++
		}
		if sn, ok := buildSubNodeFromRecord(nodes[idx], cfg.PublicHost, nil); ok {
			nodes[idx].ShareURI = sn.ShareURI
		}
		if nodes[idx].Source != "managed" {
			nodes[idx].RawURI = ""
		}
		redactNodeConfig(&nodes[idx].Config)
	}
	return marshalResponse(map[string]any{
		"nodes":          nodes,
		"total":          len(nodes),
		"managed_count":  managedCount,
		"external_count": externalCount,
	})
}

func probeLocalPortListening(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 120*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (i *instance) handleNodesUpsert(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in nodeUpsertRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	var existing *proxyNodeRecord
	if id := strings.ToLower(strings.TrimSpace(in.ID)); id != "" {
		var err error
		existing, err = i.store.GetNode(ctx, id)
		if err != nil {
			return pluginsdk.Response{}, err
		}
	}
	excludeID := ""
	if existing != nil {
		excludeID = existing.ID
	}
	usedPorts, err := i.store.UsedManagedPorts(ctx, excludeID)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	cfg := i.configSnapshot()
	rec, err := normalizeNodeDraft(in, existing, usedPorts, cfg.PublicHost)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	saved, created, err := i.store.UpsertNode(ctx, rec)
	if err != nil {
		return pluginsdk.Response{}, err
	}

	syncCore := in.SyncCore == nil || *in.SyncCore
	coreSynced := false
	coreRev := ""
	coreNote := ""
	if syncCore {
		coreSynced, coreRev, coreNote = i.trySyncManagedNodesToCore(ctx, req.Host())
	}

	_, previewDoc := buildNativeInboundPreview(saved)
	redactNativePreviewSecrets(previewDoc)
	previewBytes, _ := json.MarshalIndent(previewDoc, "", "  ")
	shareURI := ""
	if sn, ok := buildSubNodeFromRecord(saved, cfg.PublicHost, nil); ok {
		shareURI = sn.ShareURI
		saved.ShareURI = shareURI
	}
	RedactServerOnlySecrets(&saved.Config)

	return marshalResponse(map[string]any{
		"node":           saved,
		"created":        created,
		"core_synced":    coreSynced,
		"core_revision":  coreRev,
		"core_sync_note": coreNote,
		"xray_json":      string(previewBytes),
		"share_uri":      shareURI,
	})
}

func (i *instance) handleNodesDelete(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		ID       string `json:"id"`
		SyncCore *bool  `json:"sync_core"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return pluginsdk.Response{}, invalidField("/id", "REQUIRED", "缺少节点 id")
	}
	existing, err := i.store.GetNode(ctx, id)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	deleted, err := i.store.DeleteNode(ctx, id)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	coreSynced := false
	coreRev := ""
	syncCore := in.SyncCore == nil || *in.SyncCore
	if deleted && syncCore && existing != nil && existing.Source == "managed" {
		coreSynced, coreRev, _ = i.trySyncManagedNodesToCore(ctx, req.Host(), id)
	}
	return marshalResponse(map[string]any{
		"deleted":       deleted,
		"id":            id,
		"core_synced":   coreSynced,
		"core_revision": coreRev,
	})
}

func (i *instance) handleNodesProbeSNI(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		Domains   []string `json:"domains"`
		TimeoutMS int      `json:"timeout_ms"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	timeout := 3 * time.Second
	if in.TimeoutMS >= 500 && in.TimeoutMS <= 10000 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
	}

	seen := make(map[string]struct{})
	domains := make([]string, 0, len(defaultRealitySNICandidates)+len(in.Domains))
	addDomain := func(raw string) {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" || len(d) > 253 || strings.ContainsAny(d, " \t\r\n/\\@?#") {
			return
		}
		if _, dup := seen[d]; dup {
			return
		}
		seen[d] = struct{}{}
		domains = append(domains, d)
	}
	if len(in.Domains) > 0 {
		for _, d := range in.Domains {
			addDomain(d)
			if len(domains) >= 24 {
				break
			}
		}
	} else {
		for _, d := range defaultRealitySNICandidates {
			addDomain(d)
		}
	}
	if len(domains) == 0 {
		return pluginsdk.Response{}, invalidField("/domains", "INVALID_VALUE", "没有可探测的有效域名")
	}

	results := make([]sniProbeResult, len(domains))
	var wg sync.WaitGroup
	for idx, domain := range domains {
		wg.Add(1)
		go func(k int, d string) {
			defer wg.Done()
			results[k] = sniProbeFunc(ctx, d, timeout)
		}(idx, domain)
	}
	wg.Wait()

	slices.SortFunc(results, func(a, b sniProbeResult) int {
		score := func(r sniProbeResult) int {
			if r.OK && r.TLS13 {
				return 0
			}
			if r.OK {
				return 1
			}
			return 2
		}
		sa, sb := score(a), score(b)
		if sa != sb {
			return sa - sb
		}
		if a.OK && b.OK && a.LatencyMS != b.LatencyMS {
			if a.LatencyMS < b.LatencyMS {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Domain, b.Domain)
	})

	recommended := defaultRealitySNICandidates[0]
	for _, r := range results {
		if r.OK && r.TLS13 {
			recommended = r.Domain
			break
		}
	}
	return marshalResponse(map[string]any{
		"results":     results,
		"recommended": recommended,
	})
}

func (i *instance) handleNodesPreviewJSON(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in nodeUpsertRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	var existing *proxyNodeRecord
	if id := strings.ToLower(strings.TrimSpace(in.ID)); id != "" {
		existing, _ = i.store.GetNode(ctx, id)
	}
	cfg := i.configSnapshot()
	rec, err := normalizeNodeDraft(in, existing, map[int]bool{}, cfg.PublicHost)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	engine, nativeDoc := buildNativeInboundPreview(rec)
	redactNativePreviewSecrets(nativeDoc)
	var prettyBuf bytes.Buffer
	enc := json.NewEncoder(&prettyBuf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(nativeDoc)
	prettyJSON := strings.TrimRight(prettyBuf.String(), "\n")
	sn, _ := buildSubNodeFromRecord(rec, cfg.PublicHost, nil)
	var clashBuf strings.Builder
	if sn.ClashNode != nil {
		writeYAMLMap(&clashBuf, sn.ClashNode, 0)
	}
	return marshalResponse(map[string]any{
		"engine":           engine,
		"protocol":         rec.Protocol,
		"transport":        rec.Transport,
		"security_mode":    rec.SecurityMode,
		"port":             rec.Port,
		"native_inbound":   nativeDoc,
		"native_json":      prettyJSON,
		"share_uri":        sn.ShareURI,
		"clash_yaml":       clashBuf.String(),
		"singbox_outbound": sn.SingboxOutbound,
	})
}

func (i *instance) handleNodesImportURI(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		URIs    string   `json:"uris"`
		Tags    []string `json:"tags"`
		Enabled *bool    `json:"enabled"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	raw := strings.TrimSpace(in.URIs)
	if raw == "" {
		return pluginsdk.Response{}, invalidField("/uris", "REQUIRED", "请提供至少一条节点链接")
	}
	// 如果整段文本不含 "://"，尝试按 Base64 订阅内容解码。
	if !strings.Contains(raw, "://") {
		if decoded, err := decodeFlexibleBase64(raw); err == nil && strings.Contains(string(decoded), "://") {
			raw = string(decoded)
		}
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	extraTags := normalizeNodeTags(in.Tags)

	type importErr struct {
		Line  int    `json:"line"`
		URI   string `json:"uri"`
		Error string `json:"error"`
	}
	imported := make([]proxyNodeRecord, 0)
	errList := make([]importErr, 0)
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if len(imported) >= 200 {
			errList = append(errList, importErr{Line: idx + 1, URI: trimmed, Error: "单次最多导入 200 条外部节点"})
			break
		}
		parsed, err := parseExternalNodeURI(trimmed)
		if err != nil {
			errList = append(errList, importErr{Line: idx + 1, URI: trimmed, Error: err.Error()})
			continue
		}
		parsed.Enabled = enabled
		parsed.Tags = normalizeNodeTags(append([]string{parsed.Protocol, "external"}, extraTags...))
		saved, _, serr := i.store.UpsertNode(ctx, parsed)
		if serr != nil {
			errList = append(errList, importErr{Line: idx + 1, URI: trimmed, Error: serr.Error()})
			continue
		}
		saved.ShareURI = saved.RawURI
		imported = append(imported, saved)
	}
	return marshalResponse(map[string]any{
		"imported":       imported,
		"imported_count": len(imported),
		"errors":         errList,
	})
}

func (i *instance) handleNodesTest(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		ID        string `json:"id"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return pluginsdk.Response{}, invalidField("/id", "REQUIRED", "缺少节点 id")
	}
	node, err := i.store.GetNode(ctx, id)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if node == nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("NOT_FOUND", "节点 %s 不存在", id)
	}

	timeout := 3 * time.Second
	if in.TimeoutMS >= 300 && in.TimeoutMS <= 10000 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
	}

	cfg := i.configSnapshot()
	host := strings.TrimSpace(node.Server)
	if node.Source == "managed" {
		if host == "" {
			host = strings.TrimSpace(cfg.PublicHost)
		}
		if host == "" || node.Listen == "127.0.0.1" || node.Listen == "::1" {
			host = "127.0.0.1"
		}
	}
	if host == "" {
		host = "127.0.0.1"
	}
	target := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(node.Port))

	start := time.Now()
	testedAt := i.now().UTC().UnixMilli()
	ok := false
	tlsVer := ""
	errMsg := ""
	var latencyMS int64 = -1

	if node.Protocol == corev2.ProtocolHysteria2 || node.Protocol == "tuic" || node.Protocol == "wireguard" {
		// UDP 协议执行可控安全探测（外部节点严禁探测回环/私网/IMDS）
		conn, derr := ProbeExternalOrManagedNode(ctx, *node, target, timeout)
		if derr != nil {
			errMsg = derr.Error()
		} else {
			_ = conn.SetDeadline(time.Now().Add(timeout))
			_, werr := conn.Write([]byte{0x00})
			_ = conn.Close()
			if werr != nil {
				errMsg = werr.Error()
			} else {
				ok = true
				latencyMS = max(time.Since(start).Milliseconds(), 1)
			}
		}
	} else {
		conn, derr := ProbeExternalOrManagedNode(ctx, *node, target, timeout)
		if derr != nil {
			errMsg = derr.Error()
		} else {
			if node.SecurityMode == "tls" {
				sni := firstNonEmpty(node.Config.SNI, host)
				tc := tls.Client(conn, &tls.Config{
					ServerName:         sni,
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
				})
				_ = tc.SetDeadline(time.Now().Add(timeout))
				if herr := tc.HandshakeContext(ctx); herr == nil {
					tlsVer = tlsVersionName(tc.ConnectionState().Version)
				}
				_ = tc.Close()
			} else {
				_ = conn.Close()
			}
			ok = true
			latencyMS = max(time.Since(start).Milliseconds(), 1)
		}
	}

	_ = i.store.UpdateNodeLatency(ctx, node.ID, latencyMS, testedAt)
	return marshalResponse(map[string]any{
		"id":          node.ID,
		"ok":          ok,
		"latency_ms":  latencyMS,
		"protocol":    node.Protocol,
		"target":      target,
		"tls_version": tlsVer,
		"error":       errMsg,
		"tested_at":   testedAt,
	})
}

// ======================== 托管节点同步至 core.xray v2 Intent ========================

func (i *instance) trySyncManagedNodesToCore(ctx context.Context, host *pluginsdk.Host, removedIDs ...string) (bool, string, string) {
	if host == nil || host.Conn() == nil {
		return false, "", "当前处于独立模式，节点已保存到本地数据库，待接入 core.xray 后自动生效"
	}
	i.syncMu.Lock()
	defer i.syncMu.Unlock()

	readMeta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return false, "", "读取 core.xray 配置权限不可用：" + err.Error()
	}
	client := pluginconfigv1.NewPluginConfigServiceClient(host.Conn())
	getResp, err := client.GetConfig(ctx, &pluginconfigv1.GetConfigRequest{
		Context:        readMeta,
		TargetPluginId: "core.xray",
	})
	if err != nil || protoError(getResp.GetError()) != nil {
		reason := ""
		if pErr := protoError(getResp.GetError()); pErr != nil {
			reason = pErr.Error()
		} else if err != nil {
			reason = err.Error()
		}
		if reason != "" {
			return false, "", "读取 core.xray 当前配置失败，节点已持久化至本地：" + reason
		}
		return false, "", "读取 core.xray 当前配置失败，节点已持久化至本地"
	}

	managedNodes, err := i.store.ListNodes(ctx, "managed", "", "", "", false)
	if err != nil {
		return false, "", err.Error()
	}
	activeUsers, err := i.store.ListUsers(ctx, "active", "", 10000)
	if err != nil {
		return false, "", err.Error()
	}
	warpCfg, _ := i.store.GetWARP(ctx)

	var doc map[string]any
	trimmed := bytes.TrimSpace(getResp.GetRedactedConfigJson())
	if len(trimmed) > 0 {
		_ = json.Unmarshal(trimmed, &doc)
	}
	if doc == nil {
		doc = map[string]any{
			"schema_version": "2",
			"enabled":        true,
			"outbound":       map[string]any{"type": "direct"},
		}
	}
	replaceSecretPresentWithKeep(doc)

	var prevProfiles []any
	prevUserSlotsByID := make(map[string]map[string]map[string]bool)
	if rawPrev, ok := doc["profiles"].([]any); ok {
		prevProfiles = rawPrev
		for _, item := range rawPrev {
			if pm, ok := item.(map[string]any); ok {
				if pid, _ := pm["id"].(string); pid != "" {
					prevUserSlotsByID[pid] = indexExistingSecretSlots(pm["users"])
				}
			}
		}
	}

	removedSet := make(map[string]bool, len(removedIDs))
	for _, rid := range removedIDs {
		if rid != "" {
			removedSet[rid] = true
		}
	}
	managedIDSet := make(map[string]bool, len(managedNodes))
	profiles := make([]any, 0, len(managedNodes))
	existingProfileIDs := make(map[string]bool, len(managedNodes))
	skippedTLS := 0
	for _, n := range managedNodes {
		managedIDSet[n.ID] = true
		prof, ok := buildCoreV2ProfileFromNodeWithSlots(n, activeUsers, prevUserSlotsByID[n.ID])
		if !ok {
			skippedTLS++
			continue
		}
		profiles = append(profiles, prof)
		existingProfileIDs[n.ID] = true
	}

	// 保留 core.xray 中非 proxy_nodes 托管且未被删除的既有 profile。
	preservedNonManaged := make([]any, 0)
	for _, item := range prevProfiles {
		pm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		pid, _ := pm["id"].(string)
		if pid == "" || managedIDSet[pid] || removedSet[pid] {
			continue
		}
		preservedNonManaged = append(preservedNonManaged, pm)
		existingProfileIDs[pid] = true
	}

	finalProfiles := append(profiles, preservedNonManaged...)
	topEnabled := ComputeDesiredCoreEnabled(activeUsers, managedNodes) || len(preservedNonManaged) > 0
	if len(finalProfiles) == 0 {
		if len(removedSet) > 0 && len(prevProfiles) > 0 {
			// 删除最后一个托管节点且无其他非托管 profile：按 v2 契约保留至少 1 个已停用骨架并关闭顶层 enabled。
			if first, ok := prevProfiles[0].(map[string]any); ok {
				first["enabled"] = false
				finalProfiles = []any{first}
				topEnabled = false
			}
		}
		if len(finalProfiles) == 0 {
			if skippedTLS > 0 {
				return false, "", "已保存本地节点，部分 TLS 协议节点尚缺宿主证书 binding_ref，绑定证书后将自动同步至核心"
			}
			return false, "", "当前无可同步至 core.xray 的托管节点"
		}
	}

	doc["schema_version"] = "2"
	doc["enabled"] = topEnabled
	doc["profiles"] = finalProfiles
	if _, ok := doc["outbound"]; !ok {
		doc["outbound"] = map[string]any{"type": "direct"}
	}
	if warpCfg != nil && warpCfg.Registered {
		existingWARPHasSecret := false
		if prevW, ok := doc["warp"].(map[string]any); ok {
			if slot, ok := prevW["private_key"].(map[string]any); ok {
				if keep, ok := slot["$keep_secret"].(bool); ok && keep {
					existingWARPHasSecret = true
				}
			}
		}
		doc["warp"] = buildCoreXrayWARPSection(warpCfg, existingProfileIDs, existingWARPHasSecret, false)
	}

	mergedJSON, err := json.Marshal(doc)
	if err != nil {
		return false, "", err.Error()
	}
	writeMeta, err := host.CapabilityContext(ctx)
	if err != nil {
		return false, "", err.Error()
	}
	putResp, err := client.PutConfig(ctx, &pluginconfigv1.PutConfigRequest{
		Context:          writeMeta,
		TargetPluginId:   "core.xray",
		ConfigJson:       mergedJSON,
		ExpectedRevision: getResp.GetRevision(),
		TriggerApply:     true,
	})
	if err != nil || protoError(putResp.GetError()) != nil {
		reason := ""
		if pErr := protoError(putResp.GetError()); pErr != nil {
			reason = pErr.Error()
		} else if err != nil {
			reason = err.Error()
		}
		if reason != "" {
			return false, "", "节点已保存本地，但同步至 core.xray 失败：" + reason
		}
		return false, "", "节点已保存本地，同步至 core.xray 时被拒绝"
	}
	note := ""
	if skippedTLS > 0 {
		note = fmt.Sprintf("已同步至 core.xray；另有 %d 个需绑定宿主 TLS 证书的节点暂未下发", skippedTLS)
	}
	return true, putResp.GetRevision(), note
}

func buildCoreV2ProfileFromNodeWithSlots(n proxyNodeRecord, activeUsers []userRecord, existingSlots map[string]map[string]bool) (map[string]any, bool) {
	needTLS := (n.Protocol == corev2.ProtocolHysteria2 || n.Protocol == corev2.ProtocolAnyTLS) ||
		((n.Protocol == corev2.ProtocolVLESS || n.Protocol == corev2.ProtocolVMess || n.Protocol == corev2.ProtocolTrojan) && n.SecurityMode == "tls")
	if needTLS && strings.TrimSpace(n.Config.BindingRef) == "" {
		return nil, false
	}

	users := BuildUnifiedProfileUsers(&n, n.Protocol, activeUsers, existingSlots)
	if len(users) == 0 {
		return nil, false
	}
	if n.Protocol == corev2.ProtocolShadowsocks2022 && n.Config.Method == corev2.MethodChaCha20 && len(users) > 1 {
		users = users[:1]
	}

	prof := map[string]any{
		"id":       n.ID,
		"enabled":  n.Enabled,
		"listen":   n.Listen,
		"port":     n.Port,
		"protocol": n.Protocol,
		"users":    users,
	}

	tlsObj := func() map[string]any {
		return map[string]any{
			"binding_ref": n.Config.BindingRef,
			"server_name": firstNonEmpty(n.Config.SNI, n.Server),
		}
	}
	realityObj := func() map[string]any {
		sni := firstNonEmpty(n.Config.SNI, defaultRealitySNICandidates[0])
		return map[string]any{
			"mode":         "reality",
			"target":       firstNonEmpty(n.Config.Target, sni+":443"),
			"server_names": []string{sni},
			"private_key":  n.Config.PrivateKey,
			"short_ids":    []string{firstNonEmpty(n.Config.ShortID, "01234567")},
		}
	}
	udpEnabled := n.Config.UDP == nil || *n.Config.UDP

	switch n.Protocol {
	case corev2.ProtocolVLESS:
		v := map[string]any{
			"transport":     n.Transport,
			"security_mode": n.SecurityMode,
		}
		if n.Config.Flow != "" {
			v["flow"] = n.Config.Flow
		}
		if n.SecurityMode == "reality" {
			v["security"] = realityObj()
		} else if n.SecurityMode == "tls" {
			v["tls"] = tlsObj()
		}
		if n.Config.Path != "" {
			v["path"] = n.Config.Path
		}
		if n.Config.Host != "" {
			v["host"] = n.Config.Host
		}
		if n.Config.ServiceName != "" {
			v["service_name"] = n.Config.ServiceName
		}
		if n.Config.XHTTPMode != "" {
			v["xhttp_mode"] = n.Config.XHTTPMode
		}
		if n.Config.Decryption != "" {
			v["decryption"] = n.Config.Decryption
		}
		if n.Config.Encryption != "" {
			v["encryption"] = n.Config.Encryption
		}
		if n.Config.Sniffing != nil {
			v["sniffing"] = *n.Config.Sniffing
		}
		prof["vless"] = v

	case corev2.ProtocolVMess:
		v := map[string]any{
			"transport":     n.Transport,
			"security_mode": n.SecurityMode,
		}
		if n.SecurityMode == "tls" {
			v["tls"] = tlsObj()
		}
		if n.Config.Path != "" {
			v["path"] = n.Config.Path
		}
		if n.Config.Host != "" {
			v["host"] = n.Config.Host
		}
		if n.Config.ServiceName != "" {
			v["service_name"] = n.Config.ServiceName
		}
		prof["vmess"] = v

	case corev2.ProtocolTrojan:
		v := map[string]any{
			"transport":     n.Transport,
			"security_mode": n.SecurityMode,
		}
		if n.SecurityMode == "tls" {
			v["tls"] = tlsObj()
		} else {
			v["reality"] = realityObj()
		}
		if n.Config.Path != "" {
			v["path"] = n.Config.Path
		}
		if n.Config.Host != "" {
			v["host"] = n.Config.Host
		}
		if n.Config.ServiceName != "" {
			v["service_name"] = n.Config.ServiceName
		}
		prof["trojan"] = v

	case corev2.ProtocolShadowsocks:
		prof["shadowsocks"] = map[string]any{
			"method": n.Config.Method,
			"udp":    udpEnabled,
		}

	case corev2.ProtocolShadowsocks2022:
		obfs := map[string]any{"mode": firstNonEmpty(n.Config.ObfsMode, corev2.ObfsNone)}
		if n.Config.ObfsMode == corev2.ObfsHTTP || n.Config.ObfsMode == corev2.ObfsTLS {
			obfs["host"] = n.Config.ObfsHost
		}
		prof["shadowsocks2022"] = map[string]any{
			"method":     n.Config.Method,
			"server_key": n.Config.ServerKey,
			"obfs":       obfs,
			"udp":        udpEnabled && obfs["mode"] == corev2.ObfsNone,
		}

	case corev2.ProtocolHysteria2:
		h := map[string]any{"tls": tlsObj()}
		if n.Config.ObfsPassword != "" {
			h["obfs_password"] = n.Config.ObfsPassword
		}
		if n.Config.PortHopping != "" {
			h["port_hopping"] = n.Config.PortHopping
		}
		prof["hysteria2"] = h

	case corev2.ProtocolAnyTLS:
		prof["anytls"] = map[string]any{
			"tls":            tlsObj(),
			"padding_scheme": normalizePaddingScheme(n.Config.PaddingScheme),
		}

	case corev2.ProtocolSOCKS5:
		prof["socks5"] = map[string]any{"udp": udpEnabled}

	case corev2.ProtocolHTTP:
		prof["http"] = map[string]any{}
	}

	return prof, true
}
