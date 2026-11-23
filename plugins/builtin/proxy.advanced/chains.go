// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/sdk/coreapi"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

const (
	maxProxyChains   = 64
	maxChainHopDepth = 4
)

// chainSecretConfig 保存链式代理落地节点的敏感认证凭据（AES-256-GCM 落盘加密，永不原样回传前端）。
type chainSecretConfig struct {
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Method     string `json:"method,omitempty"`
	SNI        string `json:"sni,omitempty"`
	Flow       string `json:"flow,omitempty"`
	TLS        bool   `json:"tls,omitempty"`
	SkipVerify bool   `json:"skip_verify,omitempty"`
}

// chainRecord 是面向管理端/UI 的脱敏链式代理节点视图。
type chainRecord struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Enabled      bool           `json:"enabled"`
	Mode         string         `json:"mode"`     // server_forward | client_dialer | both
	Protocol     string         `json:"protocol"` // socks5 | http | vless | trojan | shadowsocks
	Server       string         `json:"server"`
	Port         int            `json:"port"`
	ConfigMasked map[string]any `json:"config_masked"`
	NextHopID    string         `json:"next_hop_id,omitempty"`
	ApplyDefault bool           `json:"apply_default"`
	Notes        string         `json:"notes,omitempty"`
	Revision     int64          `json:"revision"`
	CreatedAt    int64          `json:"created_at"`
	UpdatedAt    int64          `json:"updated_at"`
}

type chainWithSecret struct {
	chainRecord
	Secret chainSecretConfig
}

type chainUpsertRequest struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Enabled          *bool             `json:"enabled"`
	Mode             string            `json:"mode"`
	Protocol         string            `json:"protocol"`
	Server           string            `json:"server"`
	Port             int               `json:"port"`
	Config           chainSecretConfig `json:"config"`
	NextHopID        string            `json:"next_hop_id"`
	ApplyDefault     bool              `json:"apply_default"`
	Notes            string            `json:"notes"`
	ExpectedRevision string            `json:"expected_revision"`
}

func loadOrCreateMasterKey(dataDir string) ([]byte, error) {
	if strings.TrimSpace(dataDir) == "" {
		key := make([]byte, 32)
		_, _ = io.ReadFull(rand.Reader, key)
		return key, nil
	}
	path := filepath.Join(dataDir, "proxy.key")
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) == 32 {
		return raw, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	return key, nil
}

func (s *proxyStore) encryptChainConfig(cfg chainSecretConfig) ([]byte, error) {
	plain, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func (s *proxyStore) decryptChainConfig(blob []byte) (chainSecretConfig, error) {
	var cfg chainSecretConfig
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
		return cfg, errors.New("corrupt encrypted chain config")
	}
	plain, err := gcm.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func maskChainSecret(proto string, cfg chainSecretConfig) map[string]any {
	out := map[string]any{
		"tls":         cfg.TLS,
		"skip_verify": cfg.SkipVerify,
	}
	if cfg.SNI != "" {
		out["sni"] = cfg.SNI
	}
	if cfg.Method != "" {
		out["method"] = cfg.Method
	}
	if cfg.Flow != "" {
		out["flow"] = cfg.Flow
	}
	switch proto {
	case "socks5", "http":
		out["username"] = cfg.Username
		out["has_password"] = cfg.Password != ""
	case "vless":
		out["has_uuid"] = cfg.UUID != ""
	default:
		out["has_password"] = cfg.Password != ""
	}
	return out
}

func validateChainServer(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" || len(server) > 253 || strings.ContainsAny(server, " \t\r\n\x00/\\;{}\"'`") {
		return "", pluginsdk.Errorf("INVALID_ARGUMENT", "落地服务器地址格式非法")
	}
	if ip, err := netip.ParseAddr(server); err == nil {
		ip = ip.Unmap()
		if ip.IsLinkLocalUnicast() || ip == netip.MustParseAddr("169.254.169.254") || ip == netip.MustParseAddr("fd00:ec2::254") {
			return "", pluginsdk.Errorf("INVALID_ARGUMENT", "禁止将云元数据地址配置为链式代理节点")
		}
	} else if strings.EqualFold(server, "metadata.google.internal") {
		return "", pluginsdk.Errorf("INVALID_ARGUMENT", "禁止将云元数据主机配置为链式代理节点")
	}
	return server, nil
}

func validateChainSecret(proto string, cfg chainSecretConfig) error {
	for _, v := range []string{cfg.Username, cfg.Password, cfg.UUID, cfg.Method, cfg.SNI, cfg.Flow} {
		if strings.ContainsAny(v, "\r\n\x00") {
			return pluginsdk.Errorf("INVALID_ARGUMENT", "链式代理配置包含非法控制字符")
		}
	}
	switch proto {
	case "socks5", "http":
		return nil
	case "vless":
		if strings.TrimSpace(cfg.UUID) == "" {
			return pluginsdk.Errorf("INVALID_ARGUMENT", "VLESS 落地节点必须提供 uuid")
		}
		return nil
	case "trojan":
		if strings.TrimSpace(cfg.Password) == "" {
			return pluginsdk.Errorf("INVALID_ARGUMENT", "Trojan 落地节点必须提供 password")
		}
		return nil
	case "shadowsocks":
		if strings.TrimSpace(cfg.Method) == "" || strings.TrimSpace(cfg.Password) == "" {
			return pluginsdk.Errorf("INVALID_ARGUMENT", "Shadowsocks 落地节点必须提供 method 与 password")
		}
		return nil
	default:
		return pluginsdk.Errorf("INVALID_ARGUMENT", "不支持的链式代理协议 %q", proto)
	}
}

func detectChainCycle(nextMap map[string]string, startID string) error {
	visited := map[string]bool{startID: true}
	cur := nextMap[startID]
	depth := 1
	for cur != "" {
		if visited[cur] {
			return pluginsdk.Errorf("INVALID_ARGUMENT", "检测到链式代理环路引用（%s）", cur)
		}
		depth++
		if depth > maxChainHopDepth {
			return pluginsdk.Errorf("INVALID_ARGUMENT", "链式代理最大支持 %d 跳转发", maxChainHopDepth)
		}
		visited[cur] = true
		cur = nextMap[cur]
	}
	return nil
}

func (s *proxyStore) UpsertChain(ctx context.Context, in chainUpsertRequest) (chainRecord, bool, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" || !validEntityIDPattern.MatchString(id) {
		return chainRecord{}, false, pluginsdk.Errorf("INVALID_ARGUMENT", "链式代理 id 必须符合小写标识规范")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 64 {
		return chainRecord{}, false, pluginsdk.Errorf("INVALID_ARGUMENT", "链式代理名称须为 1-64 字符")
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = "both"
	}
	if mode != "server_forward" && mode != "client_dialer" && mode != "both" {
		return chainRecord{}, false, pluginsdk.Errorf("INVALID_ARGUMENT", "mode 仅支持 server_forward / client_dialer / both")
	}
	server, err := validateChainServer(in.Server)
	if err != nil {
		return chainRecord{}, false, err
	}
	if in.Port < 1 || in.Port > 65535 {
		return chainRecord{}, false, pluginsdk.Errorf("INVALID_ARGUMENT", "port 须在 1..65535 之间")
	}
	nextHop := strings.TrimSpace(in.NextHopID)
	if nextHop == id {
		return chainRecord{}, false, pluginsdk.Errorf("INVALID_ARGUMENT", "链式代理不能将自身设为下一跳")
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return chainRecord{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	// 加载已有节点关系用于环路校验与既有凭据保留。
	nextMap := make(map[string]string)
	rows, err := tx.QueryContext(ctx, `SELECT id, next_hop_id FROM proxy_chains`)
	if err != nil {
		return chainRecord{}, false, err
	}
	for rows.Next() {
		var cid, nh string
		if rows.Scan(&cid, &nh) == nil {
			nextMap[cid] = nh
		}
	}
	_ = rows.Close()

	if nextHop != "" {
		if _, ok := nextMap[nextHop]; !ok {
			return chainRecord{}, false, pluginsdk.Errorf("NOT_FOUND", "下一跳链式节点 %s 不存在", nextHop)
		}
	}
	nextMap[id] = nextHop
	if err := detectChainCycle(nextMap, id); err != nil {
		return chainRecord{}, false, err
	}

	var existingRev int64
	var existingCreated int64
	var existingEnc []byte
	err = tx.QueryRowContext(ctx, `SELECT revision, created_at, config_enc FROM proxy_chains WHERE id = ?`, id).
		Scan(&existingRev, &existingCreated, &existingEnc)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return chainRecord{}, false, err
	}

	cfg := in.Config
	if !created && len(existingEnc) > 0 {
		if in.ExpectedRevision != "" && in.ExpectedRevision != strconv.FormatInt(existingRev, 10) {
			return chainRecord{}, false, pluginsdk.PreconditionFailed("chains/"+id, strconv.FormatInt(existingRev, 10))
		}
		if prev, derr := s.decryptChainConfig(existingEnc); derr == nil {
			if cfg.Password == "" {
				cfg.Password = prev.Password
			}
			if cfg.UUID == "" {
				cfg.UUID = prev.UUID
			}
		}
	} else if created {
		if in.ExpectedRevision != "" {
			return chainRecord{}, false, pluginsdk.PreconditionFailed("chains/"+id, "")
		}
		if len(nextMap)-1 >= maxProxyChains {
			return chainRecord{}, false, pluginsdk.Errorf("RESOURCE_EXHAUSTED", "链式代理节点数已达上限 (%d)", maxProxyChains)
		}
	}

	if err := validateChainSecret(in.Protocol, cfg); err != nil {
		return chainRecord{}, false, err
	}
	enc, err := s.encryptChainConfig(cfg)
	if err != nil {
		return chainRecord{}, false, err
	}
	masked := maskChainSecret(in.Protocol, cfg)
	maskedJSON, _ := json.Marshal(masked)
	nowMs := s.now().UTC().UnixMilli()

	if in.ApplyDefault {
		_, _ = tx.ExecContext(ctx, `UPDATE proxy_chains SET apply_default = 0 WHERE id <> ?`, id)
	}

	var rev int64
	if created {
		rev = 1
		existingCreated = nowMs
		_, err = tx.ExecContext(ctx, `
			INSERT INTO proxy_chains(id, name, enabled, mode, protocol, server, port, config_enc, config_masked_json,
			                         next_hop_id, apply_default, notes, revision, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			id, name, boolToInt(enabled), mode, in.Protocol, server, in.Port, enc, string(maskedJSON),
			nextHop, boolToInt(in.ApplyDefault), strings.TrimSpace(in.Notes), nowMs, nowMs)
	} else {
		rev = existingRev + 1
		_, err = tx.ExecContext(ctx, `
			UPDATE proxy_chains
			SET name = ?, enabled = ?, mode = ?, protocol = ?, server = ?, port = ?, config_enc = ?, config_masked_json = ?,
			    next_hop_id = ?, apply_default = ?, notes = ?, revision = ?, updated_at = ?
			WHERE id = ?`,
			name, boolToInt(enabled), mode, in.Protocol, server, in.Port, enc, string(maskedJSON),
			nextHop, boolToInt(in.ApplyDefault), strings.TrimSpace(in.Notes), rev, nowMs, id)
	}
	if err != nil {
		return chainRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return chainRecord{}, false, err
	}
	return chainRecord{
		ID:           id,
		Name:         name,
		Enabled:      enabled,
		Mode:         mode,
		Protocol:     in.Protocol,
		Server:       server,
		Port:         in.Port,
		ConfigMasked: masked,
		NextHopID:    nextHop,
		ApplyDefault: in.ApplyDefault,
		Notes:        strings.TrimSpace(in.Notes),
		Revision:     rev,
		CreatedAt:    existingCreated,
		UpdatedAt:    nowMs,
	}, created, nil
}

func (s *proxyStore) ListChains(ctx context.Context) ([]chainRecord, error) {
	rows, err := s.readDB().QueryContext(ctx, `
		SELECT id, name, enabled, mode, protocol, server, port, config_masked_json,
		       next_hop_id, apply_default, notes, revision, created_at, updated_at
		FROM proxy_chains ORDER BY apply_default DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]chainRecord, 0)
	for rows.Next() {
		var r chainRecord
		var en, def int
		var maskedRaw string
		if err := rows.Scan(&r.ID, &r.Name, &en, &r.Mode, &r.Protocol, &r.Server, &r.Port, &maskedRaw,
			&r.NextHopID, &def, &r.Notes, &r.Revision, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		r.ApplyDefault = def == 1
		_ = json.Unmarshal([]byte(maskedRaw), &r.ConfigMasked)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *proxyStore) ListChainsWithSecrets(ctx context.Context) ([]chainWithSecret, error) {
	rows, err := s.readDB().QueryContext(ctx, `
		SELECT id, name, enabled, mode, protocol, server, port, config_enc, config_masked_json,
		       next_hop_id, apply_default, notes, revision, created_at, updated_at
		FROM proxy_chains ORDER BY apply_default DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]chainWithSecret, 0)
	for rows.Next() {
		var r chainWithSecret
		var en, def int
		var enc []byte
		var maskedRaw string
		if err := rows.Scan(&r.ID, &r.Name, &en, &r.Mode, &r.Protocol, &r.Server, &r.Port, &enc, &maskedRaw,
			&r.NextHopID, &def, &r.Notes, &r.Revision, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		r.ApplyDefault = def == 1
		_ = json.Unmarshal([]byte(maskedRaw), &r.ConfigMasked)
		if dec, derr := s.decryptChainConfig(enc); derr == nil {
			r.Secret = dec
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *proxyStore) DeleteChain(ctx context.Context, id string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	_, _ = tx.ExecContext(ctx, `UPDATE proxy_chains SET next_hop_id = '' WHERE next_hop_id = ?`, id)
	_, _ = tx.ExecContext(ctx, `UPDATE proxy_users SET chain_id = '' WHERE chain_id = ?`, id)
	res, err := tx.ExecContext(ctx, `DELETE FROM proxy_chains WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// renderXrayChainOutbounds 生成 Xray 服务端多跳出口链 JSON：
// 遵循 Xray proxySettings.tag 语义——落地节点通过 proxySettings.tag 指向前置跳 tag，
// 路由规则使用 coreapi.UserEmail(u.ID)（即 "qwq-user-" + u.ID）并将流量导向链路末端的落地出站 tag。
func renderXrayChainOutbounds(chains []chainWithSecret, users []userRecord) map[string]any {
	outbounds := make([]map[string]any, 0, len(chains))
	enabledByID := make(map[string]chainWithSecret)
	prevHopByID := make(map[string]string)
	var defaultTag string

	for _, c := range chains {
		if !c.Enabled || (c.Mode != "server_forward" && c.Mode != "both") {
			continue
		}
		enabledByID[c.ID] = c
	}
	for _, c := range chains {
		if _, ok := enabledByID[c.ID]; !ok || c.NextHopID == "" {
			continue
		}
		if _, ok := enabledByID[c.NextHopID]; ok {
			prevHopByID[c.NextHopID] = c.ID
		}
	}

	resolveTerminalID := func(startID string) string {
		cur := startID
		visited := map[string]bool{cur: true}
		for {
			node, ok := enabledByID[cur]
			if !ok || node.NextHopID == "" {
				return cur
			}
			if _, nextOK := enabledByID[node.NextHopID]; !nextOK || visited[node.NextHopID] {
				return cur
			}
			visited[node.NextHopID] = true
			cur = node.NextHopID
		}
	}

	for _, c := range chains {
		if _, ok := enabledByID[c.ID]; !ok {
			continue
		}
		tag := "chain-" + c.ID
		if c.ApplyDefault && defaultTag == "" {
			defaultTag = "chain-" + resolveTerminalID(c.ID)
		}
		ob := map[string]any{
			"tag":      tag,
			"protocol": c.Protocol,
		}
		switch c.Protocol {
		case "socks5":
			ob["protocol"] = "socks"
			srv := map[string]any{"address": c.Server, "port": c.Port}
			if c.Secret.Username != "" {
				srv["users"] = []map[string]any{{"user": c.Secret.Username, "pass": "<REDACTED>"}}
			}
			ob["settings"] = map[string]any{"servers": []map[string]any{srv}}
		case "http":
			srv := map[string]any{"address": c.Server, "port": c.Port}
			if c.Secret.Username != "" {
				srv["users"] = []map[string]any{{"user": c.Secret.Username, "pass": "<REDACTED>"}}
			}
			ob["settings"] = map[string]any{"servers": []map[string]any{srv}}
		case "vless":
			uObj := map[string]any{"id": "<REDACTED>", "encryption": "none"}
			if c.Secret.Flow != "" {
				uObj["flow"] = c.Secret.Flow
			}
			ob["settings"] = map[string]any{
				"vnext": []map[string]any{{"address": c.Server, "port": c.Port, "users": []map[string]any{uObj}}},
			}
		case "trojan":
			ob["settings"] = map[string]any{
				"servers": []map[string]any{{"address": c.Server, "port": c.Port, "password": "<REDACTED>"}},
			}
		case "shadowsocks":
			ob["settings"] = map[string]any{
				"servers": []map[string]any{{"address": c.Server, "port": c.Port, "method": c.Secret.Method, "password": "<REDACTED>"}},
			}
		}
		if c.Secret.TLS {
			tlsCfg := map[string]any{"allowInsecure": c.Secret.SkipVerify}
			if c.Secret.SNI != "" {
				tlsCfg["serverName"] = c.Secret.SNI
			}
			ob["streamSettings"] = map[string]any{"security": "tls", "tlsSettings": tlsCfg}
		}
		if prevID, ok := prevHopByID[c.ID]; ok {
			ob["proxySettings"] = map[string]any{"tag": "chain-" + prevID}
		}
		outbounds = append(outbounds, ob)
	}

	rules := make([]map[string]any, 0)
	for _, u := range users {
		if u.Status != "active" || u.ChainID == "" {
			continue
		}
		if _, ok := enabledByID[u.ChainID]; ok {
			userEmail, err := coreapi.UserEmail(u.ID)
			if err != nil {
				userEmail = "qwq-user-" + u.ID
			}
			rules = append(rules, map[string]any{
				"type":        "field",
				"user":        []string{userEmail},
				"outboundTag": "chain-" + resolveTerminalID(u.ChainID),
			})
		}
	}
	if defaultTag != "" {
		rules = append(rules, map[string]any{
			"type":        "field",
			"network":     "tcp,udp",
			"outboundTag": defaultTag,
		})
	}
	return map[string]any{
		"outbounds": outbounds,
		"routing":   map[string]any{"rules": rules},
	}
}

func probeChainTCP(ctx context.Context, server string, port int) (bool, int64, string) {
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start := time.Now()
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(pctx, "tcp", net.JoinHostPort(server, strconv.Itoa(port)))
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return false, latency, err.Error()
	}
	_ = conn.Close()
	return true, latency, ""
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
