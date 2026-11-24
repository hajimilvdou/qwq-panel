// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 全协议节点构建与存储模型（Managed + External） ========================

// nodeConfig 描述单个托管或外部导入节点的完整协议参数集合。
type nodeConfig struct {
	Flow          string   `json:"flow,omitempty"`
	UUID          string   `json:"uuid,omitempty"`
	Password      string   `json:"password,omitempty"`
	Username      string   `json:"username,omitempty"`
	Method        string   `json:"method,omitempty"`
	ServerKey     string   `json:"server_key,omitempty"`
	UserKey       string   `json:"user_key,omitempty"`
	SNI           string   `json:"sni,omitempty"`
	Target        string   `json:"target,omitempty"`
	PrivateKey    string   `json:"private_key,omitempty"`
	PublicKey     string   `json:"public_key,omitempty"`
	ShortID       string   `json:"short_id,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	BindingRef    string   `json:"binding_ref,omitempty"`
	Path          string   `json:"path,omitempty"`
	Host          string   `json:"host,omitempty"`
	ServiceName   string   `json:"service_name,omitempty"`
	XHTTPMode     string   `json:"xhttp_mode,omitempty"`
	Decryption    string   `json:"decryption,omitempty"`
	Encryption    string   `json:"encryption,omitempty"`
	ObfsMode      string   `json:"obfs_mode,omitempty"`
	ObfsHost      string   `json:"obfs_host,omitempty"`
	ObfsPassword  string   `json:"obfs_password,omitempty"`
	PortHopping   string   `json:"port_hopping,omitempty"`
	PaddingScheme []string `json:"padding_scheme,omitempty"`
	UDP           *bool    `json:"udp,omitempty"`
	Sniffing      *bool    `json:"sniffing,omitempty"`
	Insecure      *bool    `json:"insecure,omitempty"`
	// TUIC / WireGuard 外部导入节点扩展字段
	CongestionControl string   `json:"congestion_control,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	AddressV4         string   `json:"address_v4,omitempty"`
	AddressV6         string   `json:"address_v6,omitempty"`
	PeerPublicKey     string   `json:"peer_public_key,omitempty"`
	MTU               int      `json:"mtu,omitempty"`
	Reserved          []int    `json:"reserved,omitempty"`
}

func (c nodeConfig) isInsecure() bool {
	return c.Insecure != nil && *c.Insecure
}

// proxyNodeRecord 是持久化在 proxy_nodes 表中的统一节点视图。
type proxyNodeRecord struct {
	ID            string     `json:"id"`
	Source        string     `json:"source"`
	Name          string     `json:"name"`
	Protocol      string     `json:"protocol"`
	Transport     string     `json:"transport"`
	SecurityMode  string     `json:"security_mode"`
	Listen        string     `json:"listen"`
	Server        string     `json:"server"`
	Port          int        `json:"port"`
	Config        nodeConfig `json:"config"`
	RawURI        string     `json:"raw_uri,omitempty"`
	ShareURI      string     `json:"share_uri,omitempty"`
	Tags          []string   `json:"tags"`
	Enabled       bool       `json:"enabled"`
	Listening     bool       `json:"listening"`
	LastLatencyMS int64      `json:"last_latency_ms"`
	LastTestedAt  int64      `json:"last_tested_at"`
	Revision      int64      `json:"revision"`
	CreatedAt     int64      `json:"created_at"`
	UpdatedAt     int64      `json:"updated_at"`
}

func isValidManagedProtocol(p string) bool {
	switch p {
	case corev2.ProtocolVLESS, corev2.ProtocolVMess, corev2.ProtocolTrojan,
		corev2.ProtocolShadowsocks, corev2.ProtocolShadowsocks2022,
		corev2.ProtocolHysteria2, corev2.ProtocolAnyTLS,
		corev2.ProtocolSOCKS5, corev2.ProtocolHTTP:
		return true
	default:
		return false
	}
}

func isValidNodeProtocol(p string) bool {
	if isValidManagedProtocol(p) {
		return true
	}
	return p == "tuic" || p == "wireguard"
}

func generateNodeUUIDv4() string {
	var b [16]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func generateRealityKeyPair() (privRawURL, pubRawURL string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privBytes := priv.Bytes()
	defer clear(privBytes)
	pubBytes := priv.PublicKey().Bytes()
	return base64.RawURLEncoding.EncodeToString(privBytes), base64.RawURLEncoding.EncodeToString(pubBytes), nil
}

func normalizeRealityPrivateKey(privEncoded string) (privRawURL, pubRawURL string, err error) {
	trimmed := strings.TrimSpace(privEncoded)
	var raw []byte
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if decoded, derr := enc.DecodeString(trimmed); derr == nil {
			raw = decoded
			break
		}
	}
	if raw == nil {
		return "", "", pluginsdk.Errorf("INVALID_ARGUMENT", "Reality 私钥必须是合法 Base64 编码")
	}
	defer clear(raw)
	if len(raw) != 32 {
		return "", "", pluginsdk.Errorf("INVALID_ARGUMENT", "Reality 私钥必须为 32 字节")
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", "", pluginsdk.Errorf("INVALID_ARGUMENT", "Reality X25519 私钥无效")
	}
	return base64.RawURLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func generateShortIDHex(byteLen int) string {
	if byteLen < 1 || byteLen > 8 {
		byteLen = 4
	}
	buf := make([]byte, byteLen)
	_, _ = io.ReadFull(rand.Reader, buf)
	return hex.EncodeToString(buf)
}

func generateNodeSS2022Key(method string) string {
	n := 16
	if method == corev2.MethodAES256 || method == corev2.MethodChaCha20 {
		n = 32
	}
	buf := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func pickUnusedHighPort(used map[int]bool) int {
	for attempt := 0; attempt < 64; attempt++ {
		var b [2]byte
		_, _ = io.ReadFull(rand.Reader, b[:])
		port := 20000 + int(binary.BigEndian.Uint16(b[:]))%40000
		if !used[port] {
			return port
		}
	}
	for port := 20000; port <= 59999; port++ {
		if !used[port] {
			return port
		}
	}
	return 28443
}

func generateNodeID(prefix string) string {
	clean := strings.ToLower(strings.TrimSpace(prefix))
	var b strings.Builder
	for _, r := range clean {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() >= 18 {
			break
		}
	}
	base := strings.Trim(b.String(), "-")
	if base == "" || base[0] < 'a' || base[0] > 'z' {
		base = "node"
	}
	suffix := strings.ToLower(randomAlphaNum(6))
	id := base + "-" + suffix
	if len(id) > 32 {
		id = id[:32]
	}
	return id
}

func normalizeNodeTags(tags []string) []string {
	if len(tags) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		s := strings.TrimSpace(t)
		if s == "" || len(s) > 32 {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if len(out) >= 16 {
			break
		}
	}
	return out
}

func boolPtr(v bool) *bool { return &v }

func (s *proxyStore) ListNodes(ctx context.Context, source, protocol, tag, search string, enabledOnly bool) ([]proxyNodeRecord, error) {
	rows, err := s.readDB().QueryContext(ctx, `
		SELECT id, source, name, protocol, transport, security_mode, listen, server, port,
		       config_json, raw_uri, tags_json, enabled, last_latency_ms, last_tested_at,
		       revision, created_at, updated_at
		FROM proxy_nodes
		ORDER BY source ASC, created_at DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	srcFilter := strings.ToLower(strings.TrimSpace(source))
	protoFilter := strings.ToLower(strings.TrimSpace(protocol))
	tagFilter := strings.ToLower(strings.TrimSpace(tag))
	searchFilter := strings.ToLower(strings.TrimSpace(search))

	out := make([]proxyNodeRecord, 0)
	for rows.Next() {
		rec, err := s.scanNodeRow(rows)
		if err != nil {
			return nil, err
		}
		if srcFilter != "" && rec.Source != srcFilter {
			continue
		}
		if protoFilter != "" && rec.Protocol != protoFilter {
			continue
		}
		if enabledOnly && !rec.Enabled {
			continue
		}
		if tagFilter != "" {
			matched := false
			for _, t := range rec.Tags {
				if strings.ToLower(t) == tagFilter {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if searchFilter != "" {
			hay := strings.ToLower(rec.ID + " " + rec.Name + " " + rec.Protocol + " " + rec.Server + " " + strings.Join(rec.Tags, " "))
			if !strings.Contains(hay, searchFilter) {
				continue
			}
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *proxyStore) GetNode(ctx context.Context, id string) (*proxyNodeRecord, error) {
	row := s.readDB().QueryRowContext(ctx, `
		SELECT id, source, name, protocol, transport, security_mode, listen, server, port,
		       config_json, raw_uri, tags_json, enabled, last_latency_ms, last_tested_at,
		       revision, created_at, updated_at
		FROM proxy_nodes WHERE id = ?`, id)
	rec, err := s.scanNodeRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

type encryptedNodeConfigEnvelope struct {
	Enc string `json:"$enc"`
}

func (s *proxyStore) encryptNodeConfig(cfg nodeConfig) (string, error) {
	plain, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	defer clear(plain)
	if len(s.masterKey) != 32 {
		return string(plain), nil
	}
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plain, nil)
	env, err := json.Marshal(encryptedNodeConfigEnvelope{
		Enc: "enc:" + base64.StdEncoding.EncodeToString(sealed),
	})
	if err != nil {
		return "", err
	}
	return string(env), nil
}

func (s *proxyStore) decryptNodeConfig(raw string) (nodeConfig, error) {
	var cfg nodeConfig
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" {
		return cfg, nil
	}
	encToken := ""
	if strings.HasPrefix(trimmed, "enc:") {
		encToken = trimmed
	} else {
		var env encryptedNodeConfigEnvelope
		if json.Unmarshal([]byte(trimmed), &env) == nil && strings.HasPrefix(env.Enc, "enc:") {
			encToken = env.Enc
		}
	}
	if encToken == "" {
		// 向后兼容历史明文 JSON 行。
		_ = json.Unmarshal([]byte(trimmed), &cfg)
		return cfg, nil
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encToken, "enc:"))
	if err != nil {
		return cfg, errors.New("corrupt encrypted node config encoding")
	}
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return cfg, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return cfg, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return cfg, errors.New("corrupt encrypted node config payload")
	}
	plain, err := gcm.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return cfg, err
	}
	defer clear(plain)
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (s *proxyStore) scanNodeRow(sc rowScanner) (proxyNodeRecord, error) {
	var (
		rec        proxyNodeRecord
		cfgRaw     string
		tagsRaw    string
		enabledInt int
	)
	err := sc.Scan(
		&rec.ID, &rec.Source, &rec.Name, &rec.Protocol, &rec.Transport, &rec.SecurityMode,
		&rec.Listen, &rec.Server, &rec.Port, &cfgRaw, &rec.RawURI, &tagsRaw,
		&enabledInt, &rec.LastLatencyMS, &rec.LastTestedAt, &rec.Revision,
		&rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	rec.Enabled = enabledInt == 1
	cfg, err := s.decryptNodeConfig(cfgRaw)
	if err != nil {
		return proxyNodeRecord{}, err
	}
	rec.Config = cfg
	_ = json.Unmarshal([]byte(tagsRaw), &rec.Tags)
	if rec.Tags == nil {
		rec.Tags = []string{}
	}
	return rec, nil
}

func (s *proxyStore) UsedManagedPorts(ctx context.Context, excludeID string) (map[int]bool, error) {
	rows, err := s.readDB().QueryContext(ctx, `SELECT id, port FROM proxy_nodes WHERE source = 'managed'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := make(map[int]bool)
	for rows.Next() {
		var id string
		var port int
		if err := rows.Scan(&id, &port); err == nil && id != excludeID {
			used[port] = true
		}
	}
	return used, rows.Err()
}

func (s *proxyStore) UpsertNode(ctx context.Context, rec proxyNodeRecord) (proxyNodeRecord, bool, error) {
	if !validEntityIDPattern.MatchString(rec.ID) {
		return proxyNodeRecord{}, false, invalidField("/id", "INVALID_ID", "节点 ID 必须是 1 至 32 位小写字母开头的标识")
	}
	if !isValidNodeProtocol(rec.Protocol) {
		return proxyNodeRecord{}, false, invalidField("/protocol", "INVALID_VALUE", "不支持的代理协议")
	}
	if rec.Port < 1 || rec.Port > 65535 {
		return proxyNodeRecord{}, false, invalidField("/port", "OUT_OF_RANGE", "端口必须在 1..65535 之间")
	}
	if rec.Source == "managed" {
		if _, err := netip.ParseAddr(rec.Listen); err != nil {
			return proxyNodeRecord{}, false, invalidField("/listen", "INVALID_VALUE", "listen 必须是合法 IPv4 或 IPv6 地址")
		}
	}
	rec.Tags = normalizeNodeTags(rec.Tags)
	cfgJSON, err := s.encryptNodeConfig(rec.Config)
	if err != nil {
		return proxyNodeRecord{}, false, err
	}
	tagsJSON, _ := json.Marshal(rec.Tags)
	nowMs := s.now().UTC().UnixMilli()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return proxyNodeRecord{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var existingRev, existingCreated int64
	err = tx.QueryRowContext(ctx, `SELECT revision, created_at FROM proxy_nodes WHERE id = ?`, rec.ID).
		Scan(&existingRev, &existingCreated)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return proxyNodeRecord{}, false, err
	}

	if created {
		rec.Revision = 1
		rec.CreatedAt = nowMs
		rec.UpdatedAt = nowMs
		if rec.LastLatencyMS == 0 {
			rec.LastLatencyMS = -1
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO proxy_nodes(
				id, source, name, protocol, transport, security_mode, listen, server, port,
				config_json, raw_uri, tags_json, enabled, last_latency_ms, last_tested_at,
				revision, created_at, updated_at
			) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			rec.ID, rec.Source, rec.Name, rec.Protocol, rec.Transport, rec.SecurityMode,
			rec.Listen, rec.Server, rec.Port, string(cfgJSON), rec.RawURI, string(tagsJSON),
			boolToInt(rec.Enabled), rec.LastLatencyMS, rec.LastTestedAt, nowMs, nowMs,
		)
	} else {
		rec.Revision = existingRev + 1
		rec.CreatedAt = existingCreated
		rec.UpdatedAt = nowMs
		_, err = tx.ExecContext(ctx, `
			UPDATE proxy_nodes SET
				source = ?, name = ?, protocol = ?, transport = ?, security_mode = ?,
				listen = ?, server = ?, port = ?, config_json = ?, raw_uri = ?, tags_json = ?,
				enabled = ?, revision = ?, updated_at = ?
			WHERE id = ?`,
			rec.Source, rec.Name, rec.Protocol, rec.Transport, rec.SecurityMode,
			rec.Listen, rec.Server, rec.Port, string(cfgJSON), rec.RawURI, string(tagsJSON),
			boolToInt(rec.Enabled), rec.Revision, nowMs, rec.ID,
		)
	}
	if err != nil {
		return proxyNodeRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return proxyNodeRecord{}, false, err
	}
	return rec, created, nil
}

func (s *proxyStore) DeleteNode(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM proxy_nodes WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *proxyStore) UpdateNodeLatency(ctx context.Context, id string, latencyMS, testedAt int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE proxy_nodes SET last_latency_ms = ?, last_tested_at = ? WHERE id = ?`,
		latencyMS, testedAt, id,
	)
	return err
}

func normalizePaddingScheme(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		s := strings.TrimSpace(line)
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return corev2.DefaultAnyTLSPaddingScheme()
	}
	return slices.Clone(out)
}
