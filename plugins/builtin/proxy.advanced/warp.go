// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

const (
	defaultWARPAPIBase     = "https://api.cloudflareclient.com/v0a2158"
	defaultWARPTraceURL    = "https://www.cloudflare.com/cdn-cgi/trace"
	defaultWARPPeerPubKey  = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	defaultWARPEndpoint    = "engage.cloudflareclient.com:2408"
	defaultWARPAddressV4   = "172.16.0.2/32"
	defaultWARPMTU         = 1280
	maxWARPDomainsCount    = 128
	maxWARPBoundPortsCount = 8
)

var (
	warpAPIBaseOverride  string
	warpTraceURLOverride string
)

// warpUnlockPresets 提供常见脏 IP 解锁场景的一键域名集。
var warpUnlockPresets = map[string][]string{
	"ai": {
		"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
		"anthropic.com", "claude.ai", "gemini.google.com", "generativelanguage.googleapis.com",
		"perplexity.ai", "x.ai",
	},
	"streaming": {
		"netflix.com", "nflxvideo.net", "disneyplus.com", "bamgrid.com",
		"hulu.com", "hbomax.com", "max.com", "spotify.com",
		"tiktok.com", "tiktokv.com", "youtube.com",
	},
	"google": {
		"google.com", "googleapis.com", "gstatic.com", "googlevideo.com", "scholar.google.com",
	},
}

var warpCandidateEndpoints = []string{
	"engage.cloudflareclient.com:2408",
	"162.159.192.1:2408",
	"162.159.193.10:2408",
	"162.159.195.1:2408",
	"162.159.192.8:2408",
	"[2606:4700:d0::a29f:c001]:2408",
}

// warpRecord 是面向管理端与前端的脱敏 Cloudflare WARP 视图（绝不回传私钥或访问令牌）。
type warpRecord struct {
	Registered       bool     `json:"registered"`
	AccountID        string   `json:"account_id,omitempty"`
	AccountType      string   `json:"account_type,omitempty"`
	PublicKey        string   `json:"public_key,omitempty"`
	PeerPublicKey    string   `json:"peer_public_key,omitempty"`
	Endpoint         string   `json:"endpoint,omitempty"`
	AddressV4        string   `json:"address_v4,omitempty"`
	AddressV6        string   `json:"address_v6,omitempty"`
	ClientID         string   `json:"client_id,omitempty"`
	Reserved         []int    `json:"reserved,omitempty"`
	MTU              int      `json:"mtu,omitempty"`
	Enabled          bool     `json:"enabled"`
	RoutingMode      string   `json:"routing_mode"`
	BoundProfileIDs  []string `json:"bound_profile_ids"`
	Domains          []string `json:"domains"`
	LicenseKeyMasked string   `json:"license_key_masked,omitempty"`
	HasPrivateKey    bool     `json:"has_private_key"`
	LastSyncedRev    string   `json:"last_synced_rev,omitempty"`
	Revision         int64    `json:"revision"`
	CreatedAt        int64    `json:"created_at,omitempty"`
	UpdatedAt        int64    `json:"updated_at,omitempty"`
}

type warpWithSecrets struct {
	warpRecord
	PrivateKey  string
	AccessToken string
}

type xrayInboundPortInfo struct {
	ProfileID string `json:"profile_id"`
	Protocol  string `json:"protocol"`
	Listen    string `json:"listen"`
	Port      int    `json:"port"`
	Enabled   bool   `json:"enabled"`
	Bound     bool   `json:"bound"`
	Label     string `json:"label"`
}

type warpRegisterRequest struct {
	LicenseKey      SecretOrPlainField `json:"license_key"`
	Endpoint        string             `json:"endpoint"`
	MTU             int                `json:"mtu"`
	Enabled         *bool              `json:"enabled"`
	RoutingMode     string             `json:"routing_mode"`
	BoundProfileIDs []string           `json:"bound_profile_ids"`
	Domains         []string           `json:"domains"`
	SyncCore        *bool              `json:"sync_core"`
}

type warpConfigureRequest struct {
	Enabled         *bool     `json:"enabled"`
	RoutingMode     *string   `json:"routing_mode"`
	BoundProfileIDs *[]string `json:"bound_profile_ids"`
	Domains         *[]string `json:"domains"`
	Endpoint        *string   `json:"endpoint"`
	MTU             *int      `json:"mtu"`
	// 可选手动导入 WireGuard / WARP / Zero Trust 凭据：
	PrivateKey    SecretOrPlainField `json:"private_key"`
	PeerPublicKey string             `json:"peer_public_key"`
	AddressV4     string             `json:"address_v4"`
	AddressV6     string             `json:"address_v6"`
	ClientID      string             `json:"client_id"`
	Reserved      []int              `json:"reserved"`
	SyncCore      *bool              `json:"sync_core"`
}

func (s *proxyStore) encryptSecretBytes(plain string) ([]byte, error) {
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
	return gcm.Seal(nonce, nonce, []byte(plain), nil), nil
}

func (s *proxyStore) decryptSecretBytes(blob []byte) (string, error) {
	if len(blob) == 0 {
		return "", nil
	}
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return "", errors.New("corrupt encrypted warp secret")
	}
	plain, err := gcm.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *proxyStore) GetWARP(ctx context.Context) (*warpWithSecrets, error) {
	var (
		rec             warpWithSecrets
		privEnc, tokEnc []byte
		reservedRaw     string
		boundRaw        string
		domainsRaw      string
		enabledInt      int
	)
	err := s.readDB().QueryRowContext(ctx, `
		SELECT account_id, account_type, private_key_enc, access_token_enc, public_key, peer_public_key,
		       endpoint, address_v4, address_v6, client_id, reserved_json, mtu, enabled,
		       routing_mode, bound_ports_json, domains_json, license_key_masked, last_synced_rev,
		       revision, created_at, updated_at
		FROM warp_config WHERE id = 'default'`).Scan(
		&rec.AccountID, &rec.AccountType, &privEnc, &tokEnc, &rec.PublicKey, &rec.PeerPublicKey,
		&rec.Endpoint, &rec.AddressV4, &rec.AddressV6, &rec.ClientID, &reservedRaw, &rec.MTU, &enabledInt,
		&rec.RoutingMode, &boundRaw, &domainsRaw, &rec.LicenseKeyMasked, &rec.LastSyncedRev,
		&rec.Revision, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rec.Registered = true
	rec.Enabled = enabledInt == 1
	_ = json.Unmarshal([]byte(reservedRaw), &rec.Reserved)
	_ = json.Unmarshal([]byte(boundRaw), &rec.BoundProfileIDs)
	_ = json.Unmarshal([]byte(domainsRaw), &rec.Domains)
	if rec.BoundProfileIDs == nil {
		rec.BoundProfileIDs = []string{}
	}
	if rec.Domains == nil {
		rec.Domains = []string{}
	}
	if rec.Reserved == nil {
		rec.Reserved = []int{}
	}
	priv, err := s.decryptSecretBytes(privEnc)
	if err != nil {
		return nil, err
	}
	tok, err := s.decryptSecretBytes(tokEnc)
	if err != nil {
		return nil, err
	}
	rec.PrivateKey = priv
	rec.AccessToken = tok
	rec.HasPrivateKey = priv != ""
	return &rec, nil
}

func (s *proxyStore) SaveWARP(ctx context.Context, w warpWithSecrets) (warpRecord, error) {
	privEnc, err := s.encryptSecretBytes(w.PrivateKey)
	if err != nil {
		return warpRecord{}, err
	}
	tokEnc, err := s.encryptSecretBytes(w.AccessToken)
	if err != nil {
		return warpRecord{}, err
	}
	if w.Reserved == nil {
		w.Reserved = []int{}
	}
	if w.BoundProfileIDs == nil {
		w.BoundProfileIDs = []string{}
	}
	if w.Domains == nil {
		w.Domains = []string{}
	}
	reservedJSON, _ := json.Marshal(w.Reserved)
	boundJSON, _ := json.Marshal(w.BoundProfileIDs)
	domainsJSON, _ := json.Marshal(w.Domains)

	nowMs := s.now().UTC().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return warpRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var existingRev, existingCreated int64
	err = tx.QueryRowContext(ctx, `SELECT revision, created_at FROM warp_config WHERE id = 'default'`).
		Scan(&existingRev, &existingCreated)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return warpRecord{}, err
	}

	var rev int64
	if created {
		rev = 1
		existingCreated = nowMs
		_, err = tx.ExecContext(ctx, `
			INSERT INTO warp_config(
				id, account_id, account_type, private_key_enc, access_token_enc, public_key, peer_public_key,
				endpoint, address_v4, address_v6, client_id, reserved_json, mtu, enabled,
				routing_mode, bound_ports_json, domains_json, license_key_masked, last_synced_rev,
				revision, created_at, updated_at
			) VALUES('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			w.AccountID, w.AccountType, privEnc, tokEnc, w.PublicKey, w.PeerPublicKey,
			w.Endpoint, w.AddressV4, w.AddressV6, w.ClientID, string(reservedJSON), w.MTU, boolToInt(w.Enabled),
			w.RoutingMode, string(boundJSON), string(domainsJSON), w.LicenseKeyMasked, w.LastSyncedRev,
			nowMs, nowMs,
		)
	} else {
		rev = existingRev + 1
		_, err = tx.ExecContext(ctx, `
			UPDATE warp_config SET
				account_id = ?, account_type = ?, private_key_enc = ?, access_token_enc = ?,
				public_key = ?, peer_public_key = ?, endpoint = ?, address_v4 = ?, address_v6 = ?,
				client_id = ?, reserved_json = ?, mtu = ?, enabled = ?, routing_mode = ?,
				bound_ports_json = ?, domains_json = ?, license_key_masked = ?, last_synced_rev = ?,
				revision = ?, updated_at = ?
			WHERE id = 'default'`,
			w.AccountID, w.AccountType, privEnc, tokEnc,
			w.PublicKey, w.PeerPublicKey, w.Endpoint, w.AddressV4, w.AddressV6,
			w.ClientID, string(reservedJSON), w.MTU, boolToInt(w.Enabled), w.RoutingMode,
			string(boundJSON), string(domainsJSON), w.LicenseKeyMasked, w.LastSyncedRev,
			rev, nowMs,
		)
	}
	if err != nil {
		return warpRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return warpRecord{}, err
	}
	w.Registered = true
	w.HasPrivateKey = w.PrivateKey != ""
	w.Revision = rev
	w.CreatedAt = existingCreated
	w.UpdatedAt = nowMs
	return w.warpRecord, nil
}

func (s *proxyStore) DeleteWARP(ctx context.Context) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM warp_config WHERE id = 'default'`)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ======================== Cloudflare WARP 一键注册与密钥派生 ========================

func generateWireGuardKeyPair() (privB64, pubB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privBytes := priv.Bytes()
	defer clear(privBytes)
	pubBytes := priv.PublicKey().Bytes()
	return base64.StdEncoding.EncodeToString(privBytes), base64.StdEncoding.EncodeToString(pubBytes), nil
}

func deriveWGPublicKey(privB64 string) (string, error) {
	raw, err := decodeWGKey(privB64)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func decodeWGKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil || len(raw) != 32 {
		return nil, pluginsdk.Errorf("INVALID_ARGUMENT", "WireGuard 密钥必须是 32 字节 Base64 编码")
	}
	return raw, nil
}

func decodeWARPClientIDReserved(clientID string) []int {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(clientID)
		if err != nil {
			return nil
		}
	}
	if len(raw) < 3 {
		return nil
	}
	raw = raw[:3]
	out := make([]int, 3)
	for i, b := range raw {
		out[i] = int(b)
	}
	return out
}

func randomAlphaNum(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, buf)
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf)
}

func warpAPIBase() string {
	if warpAPIBaseOverride != "" {
		return strings.TrimRight(warpAPIBaseOverride, "/")
	}
	return defaultWARPAPIBase
}

func warpTraceURL() string {
	if warpTraceURLOverride != "" {
		return warpTraceURLOverride
	}
	return defaultWARPTraceURL
}

type cfRegResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		AccountType string `json:"account_type"`
		License     string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID  string `json:"client_id"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
				V4   string `json:"v4"`
				V6   string `json:"v6"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

func registerCloudflareWARP(ctx context.Context, client *http.Client, licenseKey string) (warpWithSecrets, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	privKey, pubKey, err := generateWireGuardKeyPair()
	if err != nil {
		return warpWithSecrets{}, fmt.Errorf("generate WireGuard keypair: %w", err)
	}
	installID := randomAlphaNum(22)
	reqBody := map[string]any{
		"key":           pubKey,
		"install_id":    installID,
		"fcm_token":     installID + ":APA91b" + randomAlphaNum(134),
		"tos":           time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":         "PC",
		"serial_number": installID,
		"locale":        "en_US",
	}
	rawBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, warpAPIBase()+"/reg", bytes.NewReader(rawBody))
	if err != nil {
		return warpWithSecrets{}, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("CF-Client-Version", "a-6.11-2223")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := client.Do(req)
	if err != nil {
		return warpWithSecrets{}, pluginsdk.Errorf("UNAVAILABLE", "连接 Cloudflare WARP 注册接口失败：%v（若本机受限，可改用手动导入 WireGuard 密钥）", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return warpWithSecrets{}, pluginsdk.Errorf("UNAVAILABLE", "读取 Cloudflare 注册响应失败")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return warpWithSecrets{}, pluginsdk.Errorf("UNAVAILABLE", "Cloudflare WARP 注册返回 HTTP %d（可能是频率限制或 IP 受限，请稍后重试或手动导入密钥）", resp.StatusCode)
	}

	var parsed cfRegResponse
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return warpWithSecrets{}, pluginsdk.Errorf("INTERNAL", "解析 Cloudflare WARP 注册响应失败")
	}
	if parsed.ID == "" {
		return warpWithSecrets{}, pluginsdk.Errorf("INTERNAL", "Cloudflare WARP 注册未返回有效账号 ID")
	}

	addrV4 := ensureWARPCIDR(parsed.Config.Interface.Addresses.V4, "/32")
	if addrV4 == "/32" {
		addrV4 = defaultWARPAddressV4
	}
	addrV6 := ""
	if strings.TrimSpace(parsed.Config.Interface.Addresses.V6) != "" {
		addrV6 = ensureWARPCIDR(parsed.Config.Interface.Addresses.V6, "/128")
	}
	peerPub := defaultWARPPeerPubKey
	endpoint := defaultWARPEndpoint
	if len(parsed.Config.Peers) > 0 {
		if pk := strings.TrimSpace(parsed.Config.Peers[0].PublicKey); pk != "" {
			peerPub = pk
		}
		ep := strings.TrimSpace(parsed.Config.Peers[0].Endpoint.Host)
		if ep == "" {
			ep = strings.TrimSpace(parsed.Config.Peers[0].Endpoint.V4)
		}
		if ep != "" {
			if h, p, serr := net.SplitHostPort(ep); serr == nil {
				if p == "" || p == "0" {
					ep = net.JoinHostPort(h, "2408")
				}
			} else {
				ep = net.JoinHostPort(strings.Trim(ep, "[]"), "2408")
			}
			endpoint = ep
		}
	}
	clientID := strings.TrimSpace(parsed.Config.ClientID)
	reserved := decodeWARPClientIDReserved(clientID)
	acctType := "free"
	licenseMasked := ""

	licenseKey = strings.TrimSpace(licenseKey)
	if licenseKey != "" && parsed.Token != "" {
		if err := bindWARPLicense(ctx, client, parsed.ID, parsed.Token, licenseKey); err != nil {
			return warpWithSecrets{}, err
		}
		acctType = "plus"
		licenseMasked = maskLicenseKey(licenseKey)
		// 绑定 WARP+ License 后最佳努力刷新一次 /reg/{id} 以获取更新后的 client_id 与 reserved
		if refreshed, ferr := fetchCloudflareWARP(ctx, client, parsed.ID, parsed.Token); ferr == nil && refreshed != nil {
			if newCID := strings.TrimSpace(refreshed.Config.ClientID); newCID != "" {
				clientID = newCID
				if newRes := decodeWARPClientIDReserved(newCID); len(newRes) == 3 {
					reserved = newRes
				}
			}
		}
	}

	return warpWithSecrets{
		warpRecord: warpRecord{
			Registered:       true,
			AccountID:        parsed.ID,
			AccountType:      acctType,
			PublicKey:        pubKey,
			PeerPublicKey:    peerPub,
			Endpoint:         endpoint,
			AddressV4:        addrV4,
			AddressV6:        addrV6,
			ClientID:         clientID,
			Reserved:         reserved,
			MTU:              defaultWARPMTU,
			LicenseKeyMasked: licenseMasked,
			HasPrivateKey:    true,
		},
		PrivateKey:  privKey,
		AccessToken: parsed.Token,
	}, nil
}

func bindWARPLicense(ctx context.Context, client *http.Client, accountID, token, licenseKey string) error {
	payload, _ := json.Marshal(map[string]string{"license": licenseKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		fmt.Sprintf("%s/reg/%s/account", warpAPIBase(), accountID), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("CF-Client-Version", "a-6.11-2223")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := client.Do(req)
	if err != nil {
		return pluginsdk.Errorf("UNAVAILABLE", "绑定 WARP+ 许可证请求失败：%v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return pluginsdk.Errorf("INVALID_ARGUMENT", "WARP+ 许可证绑定被拒绝（HTTP %d），请检查 License Key 是否有效或超出设备上限", resp.StatusCode)
	}
	return nil
}

func fetchCloudflareWARP(ctx context.Context, client *http.Client, accountID, token string) (*cfRegResponse, error) {
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/reg/%s", warpAPIBase(), accountID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("CF-Client-Version", "a-6.11-2223")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("refresh warp reg status=%d", resp.StatusCode)
	}
	var out cfRegResponse
	if err := json.Unmarshal(bodyBytes, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func deleteCloudflareWARPBestEffort(ctx context.Context, accountID, token string) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(token) == "" {
		return
	}
	delCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(delCtx, http.MethodDelete,
		fmt.Sprintf("%s/reg/%s", warpAPIBase(), accountID), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("CF-Client-Version", "a-6.11-2223")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	client := &http.Client{Timeout: 5 * time.Second}
	if resp, err := client.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
		_ = resp.Body.Close()
	}
}

func maskLicenseKey(k string) string {
	k = strings.TrimSpace(k)
	if len(k) <= 6 {
		return "******"
	}
	return k[:4] + "****" + k[len(k)-4:]
}

func ensureWARPCIDR(addr, suffix string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.Contains(addr, "/") {
		return addr
	}
	return addr + suffix
}

func normalizeWARPEndpoint(raw string) (string, error) {
	ep := strings.TrimSpace(raw)
	if ep == "" {
		return defaultWARPEndpoint, nil
	}
	if len(ep) > 259 || strings.ContainsAny(ep, " \t\r\n\x00/\\;{}\"'`") {
		return "", pluginsdk.Errorf("INVALID_ARGUMENT", "WARP Endpoint 格式非法")
	}
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil || host == "" {
		return "", pluginsdk.Errorf("INVALID_ARGUMENT", "WARP Endpoint 必须为 host:port 格式（如 engage.cloudflareclient.com:2408）")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", pluginsdk.Errorf("INVALID_ARGUMENT", "WARP Endpoint 端口必须在 1..65535 之间")
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return "", pluginsdk.Errorf("INVALID_ARGUMENT", "WARP Endpoint 不能指向回环或链路本地地址")
		}
	}
	return ep, nil
}

func normalizeWARPDomains(raw []string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		d := strings.ToLower(strings.TrimSpace(item))
		if d == "" {
			continue
		}
		if len(d) > 253 || strings.ContainsAny(d, " \t\r\n\x00/\\;{}\"'`") {
			return nil, pluginsdk.Errorf("INVALID_ARGUMENT", "解锁域名 %q 格式无效", item)
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
		if len(out) > maxWARPDomainsCount {
			return nil, pluginsdk.Errorf("INVALID_ARGUMENT", "WARP 解锁域名最多支持 %d 条", maxWARPDomainsCount)
		}
	}
	return out, nil
}

func normalizeBoundProfiles(raw []string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		id := strings.TrimSpace(item)
		if id == "" {
			continue
		}
		if len(id) > 32 || !validEntityIDPattern.MatchString(id) {
			return nil, pluginsdk.Errorf("INVALID_ARGUMENT", "绑定的代理端口 ID %q 格式非法", item)
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
		if len(out) > maxWARPBoundPortsCount {
			return nil, pluginsdk.Errorf("INVALID_ARGUMENT", "最多同时绑定 %d 个代理入站端口", maxWARPBoundPortsCount)
		}
	}
	return out, nil
}

func normalizeWARPRoutingMode(raw string) (string, error) {
	m := strings.TrimSpace(raw)
	if m == "" {
		return "bound_ports", nil
	}
	switch m {
	case "bound_ports", "domains", "all":
		return m, nil
	default:
		return "", pluginsdk.Errorf("INVALID_ARGUMENT", "routing_mode 仅支持 bound_ports / domains / all")
	}
}

// discoverCoreXrayInboundPorts 从 core.xray 脱敏配置读取真实代理入站端口列表，方便前端一键勾选绑定。
func (i *instance) discoverCoreXrayInboundPorts(ctx context.Context, boundIDs []string) []xrayInboundPortInfo {
	boundSet := make(map[string]bool, len(boundIDs))
	for _, id := range boundIDs {
		boundSet[id] = true
	}
	host := i.Host()
	if host != nil && host.Conn() != nil {
		if readMeta, err := host.CapabilityContextReadOnly(ctx); err == nil {
			client := pluginconfigv1.NewPluginConfigServiceClient(host.Conn())
			if resp, err := client.GetConfig(ctx, &pluginconfigv1.GetConfigRequest{
				Context:        readMeta,
				TargetPluginId: "core.xray",
			}); err == nil && protoError(resp.GetError()) == nil && len(bytes.TrimSpace(resp.GetRedactedConfigJson())) > 0 {
				var doc struct {
					Profiles []struct {
						ID       string `json:"id"`
						Protocol string `json:"protocol"`
						Listen   string `json:"listen"`
						Port     int    `json:"port"`
						Enabled  bool   `json:"enabled"`
					} `json:"profiles"`
				}
				if json.Unmarshal(resp.GetRedactedConfigJson(), &doc) == nil && len(doc.Profiles) > 0 {
					out := make([]xrayInboundPortInfo, 0, len(doc.Profiles))
					for _, p := range doc.Profiles {
						out = append(out, xrayInboundPortInfo{
							ProfileID: p.ID,
							Protocol:  p.Protocol,
							Listen:    p.Listen,
							Port:      p.Port,
							Enabled:   p.Enabled,
							Bound:     boundSet[p.ID],
							Label:     fmt.Sprintf("%s · %s (:%d)", p.ID, strings.ToUpper(p.Protocol), p.Port),
						})
					}
					return out
				}
			}
		}
	}
	// 回退到插件静态端口提示（当 core.xray 尚未初始化时）。
	cfg := i.configSnapshot()
	var fallback []xrayInboundPortInfo
	if cfg.VLESSPort > 0 {
		fallback = append(fallback, xrayInboundPortInfo{
			ProfileID: "vless-main", Protocol: "vless", Listen: "0.0.0.0", Port: int(cfg.VLESSPort),
			Enabled: true, Bound: boundSet["vless-main"],
			Label: fmt.Sprintf("vless-main · VLESS REALITY (:%d)", cfg.VLESSPort),
		})
	}
	if cfg.Hy2Port > 0 {
		fallback = append(fallback, xrayInboundPortInfo{
			ProfileID: "hy2-main", Protocol: "hysteria2", Listen: "0.0.0.0", Port: int(cfg.Hy2Port),
			Enabled: true, Bound: boundSet["hy2-main"],
			Label: fmt.Sprintf("hy2-main · HYSTERIA2 (:%d)", cfg.Hy2Port),
		})
	}
	if cfg.SSPort > 0 {
		fallback = append(fallback, xrayInboundPortInfo{
			ProfileID: "ss2022-main", Protocol: "shadowsocks2022", Listen: "0.0.0.0", Port: int(cfg.SSPort),
			Enabled: true, Bound: boundSet["ss2022-main"],
			Label: fmt.Sprintf("ss2022-main · SS2022 (:%d)", cfg.SSPort),
		})
	}
	return fallback
}

func renderWARPXrayPreview(w *warpRecord) map[string]any {
	if w == nil || !w.Registered {
		return map[string]any{}
	}
	addrs := []string{ensureWARPCIDR(w.AddressV4, "/32")}
	if strings.TrimSpace(w.AddressV6) != "" {
		addrs = append(addrs, ensureWARPCIDR(w.AddressV6, "/128"))
	}
	mtu := w.MTU
	if mtu <= 0 {
		mtu = defaultWARPMTU
	}
	ob := map[string]any{
		"tag":      "qwq-warp",
		"protocol": "wireguard",
		"settings": map[string]any{
			"secretKey":  "<REDACTED>",
			"address":    addrs,
			"peers":      []map[string]any{{"publicKey": w.PeerPublicKey, "endpoint": w.Endpoint}},
			"reserved":   w.Reserved,
			"mtu":        mtu,
			"kernelMode": false,
		},
	}
	rule := map[string]any{
		"type":        "field",
		"outboundTag": "qwq-warp",
	}
	switch w.RoutingMode {
	case "bound_ports":
		rule["inboundTag"] = w.BoundProfileIDs
	case "domains":
		doms := make([]string, 0, len(w.Domains))
		for _, d := range w.Domains {
			if strings.Contains(d, ":") {
				doms = append(doms, d)
			} else {
				doms = append(doms, "domain:"+strings.TrimPrefix(d, "."))
			}
		}
		rule["domain"] = doms
		if len(w.BoundProfileIDs) > 0 {
			rule["inboundTag"] = w.BoundProfileIDs
		}
	case "all":
		rule["inboundTag"] = []string{"<all-enabled-proxy-inbounds>"}
	}
	return map[string]any{
		"outbound": ob,
		"routing":  map[string]any{"rules": []map[string]any{rule}},
	}
}

func buildCoreXrayWARPSection(w *warpWithSecrets, existingProfiles map[string]bool, existingHasSecret bool, writeNewSecret bool) map[string]any {
	if w == nil || !w.Registered {
		return nil
	}
	filteredBound := make([]string, 0, len(w.BoundProfileIDs))
	for _, pid := range w.BoundProfileIDs {
		if existingProfiles[pid] {
			filteredBound = append(filteredBound, pid)
		}
	}
	var privVal any = w.PrivateKey
	if !writeNewSecret && existingHasSecret {
		privVal = map[string]any{"$keep_secret": true}
	}
	out := map[string]any{
		"enabled":         w.Enabled,
		"private_key":     privVal,
		"peer_public_key": w.PeerPublicKey,
		"endpoint":        w.Endpoint,
		"address_v4":      ensureWARPCIDR(w.AddressV4, "/32"),
		"mtu":             w.MTU,
		"routing_mode":    w.RoutingMode,
	}
	if strings.TrimSpace(w.AddressV6) != "" {
		out["address_v6"] = ensureWARPCIDR(w.AddressV6, "/128")
	}
	if len(w.Reserved) > 0 {
		out["reserved"] = w.Reserved
	}
	if len(filteredBound) > 0 {
		out["bound_profile_ids"] = filteredBound
	}
	if len(w.Domains) > 0 {
		out["domains"] = w.Domains
	}
	return out
}

func (i *instance) syncWARPToCoreXray(ctx context.Context, writeNewSecret bool) (string, string) {
	host := i.Host()
	if host == nil || host.Conn() == nil {
		return "", "宿主连接未就绪，配置已保存在本地，待连接后可再次同步"
	}
	i.syncMu.Lock()
	defer i.syncMu.Unlock()

	rev, err := i.syncCoreXrayLockedWithWARP(ctx, host, writeNewSecret)
	if err != nil {
		return "", "WARP 已保存，但同步到 core.xray 暂未生效：" + err.Error()
	}
	if cur, gerr := i.store.GetWARP(ctx); gerr == nil && cur != nil {
		cur.LastSyncedRev = rev
		_, _ = i.store.SaveWARP(ctx, *cur)
	}
	return rev, ""
}

// ======================== Operation Handlers ========================

func (i *instance) handleWARPStatus(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	cur, err := i.store.GetWARP(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	var rec warpRecord
	if cur != nil {
		rec = cur.warpRecord
	} else {
		rec = warpRecord{
			Registered:      false,
			Endpoint:        defaultWARPEndpoint,
			MTU:             defaultWARPMTU,
			RoutingMode:     "bound_ports",
			BoundProfileIDs: []string{},
			Domains:         slices.Clone(warpUnlockPresets["ai"]),
			Reserved:        []int{},
		}
	}
	allInbounds := i.discoverCoreXrayInboundPorts(ctx, rec.BoundProfileIDs)
	// AnyTLS 由独立纯 Go 监管器承载，不经过 Xray WireGuard 路由，不列入 WARP 端口绑定候选
	inbounds := make([]xrayInboundPortInfo, 0, len(allInbounds))
	for _, p := range allInbounds {
		if strings.EqualFold(p.Protocol, "anytls") {
			continue
		}
		inbounds = append(inbounds, p)
	}
	preview := renderWARPXrayPreview(&rec)
	previewJSON, _ := json.MarshalIndent(preview, "", "  ")
	return marshalResponse(map[string]any{
		"warp":                rec,
		"inbounds":            inbounds,
		"unlock_presets":      warpUnlockPresets,
		"candidate_endpoints": warpCandidateEndpoints,
		"xray_preview":        preview,
		"xray_preview_json":   string(previewJSON),
	})
}

func (i *instance) handleWARPRegister(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in warpRegisterRequest
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	mode, err := normalizeWARPRoutingMode(in.RoutingMode)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	bound, err := normalizeBoundProfiles(in.BoundProfileIDs)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	domains, err := normalizeWARPDomains(in.Domains)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if len(domains) == 0 {
		domains = slices.Clone(warpUnlockPresets["ai"])
	}
	licenseKey, err := resolveSecretOrPlain(ctx, req.Host(), in.LicenseKey, "operation")
	if err != nil {
		return pluginsdk.Response{}, err
	}
	reg, err := registerCloudflareWARP(ctx, nil, licenseKey)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if strings.TrimSpace(in.Endpoint) != "" {
		ep, epErr := normalizeWARPEndpoint(in.Endpoint)
		if epErr != nil {
			return pluginsdk.Response{}, epErr
		}
		reg.Endpoint = ep
	}
	if in.MTU >= 1200 && in.MTU <= 1500 {
		reg.MTU = in.MTU
	}
	reg.RoutingMode = mode
	reg.BoundProfileIDs = bound
	reg.Domains = domains
	if in.Enabled != nil {
		reg.Enabled = *in.Enabled
	} else {
		// 一键注册时若同时指定了端口、域名或全局模式则默认直接启用，否则默认开启等待绑定或按已选生效。
		reg.Enabled = len(bound) > 0 || mode == "all" || mode == "domains"
	}

	saved, err := i.store.SaveWARP(ctx, reg)
	if err != nil {
		return pluginsdk.Response{}, err
	}

	syncCore := true
	if in.SyncCore != nil {
		syncCore = *in.SyncCore
	}
	var coreRev, syncWarn string
	if syncCore {
		coreRev, syncWarn = i.syncWARPToCoreXray(ctx, true)
		if coreRev != "" {
			saved.LastSyncedRev = coreRev
		}
	}
	return marshalResponse(map[string]any{
		"warp":          saved,
		"core_revision": coreRev,
		"sync_warning":  syncWarn,
	})
}

func (i *instance) handleWARPConfigure(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in warpConfigureRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	cur, err := i.store.GetWARP(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}

	privKeyRaw, err := resolveSecretOrPlain(ctx, req.Host(), in.PrivateKey, "operation")
	if err != nil {
		return pluginsdk.Response{}, err
	}
	privKeyTrim := strings.TrimSpace(privKeyRaw)

	writeNewSecret := false
	var next warpWithSecrets
	if cur != nil {
		next = *cur
	} else {
		if privKeyTrim == "" {
			return pluginsdk.Response{}, pluginsdk.Errorf("PRECONDITION_FAILED", "尚未注册 Cloudflare WARP，请先点击「一键注册」或填写手动 WireGuard 私钥导入")
		}
		next = warpWithSecrets{
			warpRecord: warpRecord{
				Registered:    true,
				AccountType:   "manual",
				PeerPublicKey: defaultWARPPeerPubKey,
				Endpoint:      defaultWARPEndpoint,
				AddressV4:     defaultWARPAddressV4,
				MTU:           defaultWARPMTU,
				RoutingMode:   "bound_ports",
			},
		}
	}

	if privKeyTrim != "" {
		pub, derr := deriveWGPublicKey(privKeyTrim)
		if derr != nil {
			return pluginsdk.Response{}, derr
		}
		next.PrivateKey = privKeyTrim
		next.PublicKey = pub
		next.HasPrivateKey = true
		if next.AccountID == "" {
			next.AccountID = "manual-" + randomAlphaNum(8)
			next.AccountType = "manual"
		}
		writeNewSecret = true
	}
	if strings.TrimSpace(in.PeerPublicKey) != "" {
		if _, derr := decodeWGKey(in.PeerPublicKey); derr != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "PeerPublicKey 必须是 32 字节 Base64 WireGuard 公钥")
		}
		next.PeerPublicKey = strings.TrimSpace(in.PeerPublicKey)
	}
	if strings.TrimSpace(in.AddressV4) != "" {
		v4 := ensureWARPCIDR(in.AddressV4, "/32")
		if pfx, perr := netip.ParsePrefix(v4); perr != nil || !pfx.Addr().Is4() {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "WARP IPv4 地址格式无效")
		}
		next.AddressV4 = v4
	}
	if strings.TrimSpace(in.AddressV6) != "" {
		v6 := ensureWARPCIDR(in.AddressV6, "/128")
		if pfx, perr := netip.ParsePrefix(v6); perr != nil || !pfx.Addr().Is6() || pfx.Addr().Is4In6() {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "WARP IPv6 地址格式无效")
		}
		next.AddressV6 = v6
	}
	if strings.TrimSpace(in.ClientID) != "" {
		next.ClientID = strings.TrimSpace(in.ClientID)
		if res := decodeWARPClientIDReserved(next.ClientID); len(res) > 0 {
			next.Reserved = res
		}
	}
	if len(in.Reserved) > 0 {
		if len(in.Reserved) != 3 {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "reserved 必须严格为 3 个 0..255 整数")
		}
		for _, b := range in.Reserved {
			if b < 0 || b > 255 {
				return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "reserved 字节值必须在 0..255 之间")
			}
		}
		next.Reserved = slices.Clone(in.Reserved)
	}
	if in.Endpoint != nil {
		ep, epErr := normalizeWARPEndpoint(*in.Endpoint)
		if epErr != nil {
			return pluginsdk.Response{}, epErr
		}
		next.Endpoint = ep
	}
	if in.MTU != nil {
		if *in.MTU < 1200 || *in.MTU > 1500 {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_ARGUMENT", "MTU 必须在 1200..1500 之间")
		}
		next.MTU = *in.MTU
	}
	if in.RoutingMode != nil {
		m, mErr := normalizeWARPRoutingMode(*in.RoutingMode)
		if mErr != nil {
			return pluginsdk.Response{}, mErr
		}
		next.RoutingMode = m
	}
	if in.BoundProfileIDs != nil {
		b, bErr := normalizeBoundProfiles(*in.BoundProfileIDs)
		if bErr != nil {
			return pluginsdk.Response{}, bErr
		}
		next.BoundProfileIDs = b
	}
	if in.Domains != nil {
		d, dErr := normalizeWARPDomains(*in.Domains)
		if dErr != nil {
			return pluginsdk.Response{}, dErr
		}
		next.Domains = d
	}
	if in.Enabled != nil {
		next.Enabled = *in.Enabled
	}

	saved, err := i.store.SaveWARP(ctx, next)
	if err != nil {
		return pluginsdk.Response{}, err
	}

	syncCore := true
	if in.SyncCore != nil {
		syncCore = *in.SyncCore
	}
	var coreRev, syncWarn string
	if syncCore {
		coreRev, syncWarn = i.syncWARPToCoreXray(ctx, writeNewSecret)
		if coreRev != "" {
			saved.LastSyncedRev = coreRev
		}
	}
	return marshalResponse(map[string]any{
		"warp":          saved,
		"core_revision": coreRev,
		"sync_warning":  syncWarn,
	})
}

func (i *instance) handleWARPProbe(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	type endpointProbe struct {
		Endpoint  string `json:"endpoint"`
		Reachable bool   `json:"reachable"`
		LatencyMS int64  `json:"latency_ms"`
		Error     string `json:"error,omitempty"`
	}
	candidates := slices.Clone(warpCandidateEndpoints)
	if cur, err := i.store.GetWARP(ctx); err == nil && cur != nil && cur.Endpoint != "" && !slices.Contains(candidates, cur.Endpoint) {
		candidates = append([]string{cur.Endpoint}, candidates...)
	}

	results := make([]endpointProbe, 0, len(candidates))
	bestEndpoint := ""
	bestLatency := int64(1<<62 - 1)
	for _, ep := range candidates {
		host, _, err := net.SplitHostPort(ep)
		if err != nil {
			continue
		}
		// 对 Cloudflare Anycast 节点执行真实公网 TLS 443 握手测 RTT（消除虚假本地 UDP dial 回退并防 SSRF）。
		start := time.Now()
		d := NewPublicProbeDialer(2500 * time.Millisecond)
		rawConn, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
		if derr != nil {
			lat := time.Since(start).Milliseconds()
			results = append(results, endpointProbe{Endpoint: ep, Reachable: false, LatencyMS: lat, Error: derr.Error()})
			continue
		}
		sni := host
		if _, parseErr := netip.ParseAddr(host); parseErr == nil {
			sni = "engage.cloudflareclient.com"
		}
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		_ = tlsConn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
		herr := tlsConn.HandshakeContext(ctx)
		lat := max(time.Since(start).Milliseconds(), 1)
		_ = tlsConn.Close()
		if herr != nil {
			results = append(results, endpointProbe{Endpoint: ep, Reachable: false, LatencyMS: lat, Error: herr.Error()})
			continue
		}
		results = append(results, endpointProbe{Endpoint: ep, Reachable: true, LatencyMS: lat})
		if lat < bestLatency {
			bestLatency = lat
			bestEndpoint = ep
		}
	}

	traceInfo := map[string]string{}
	traceClient := &http.Client{Timeout: 4 * time.Second}
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, warpTraceURL(), nil); err == nil {
		if resp, err := traceClient.Do(req); err == nil {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
			_ = resp.Body.Close()
			for _, line := range strings.Split(string(raw), "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
					switch k {
					case "ip", "loc", "colo", "warp", "gateway":
						traceInfo[k] = v
					}
				}
			}
		}
	}

	return marshalResponse(map[string]any{
		"endpoints":     results,
		"best_endpoint": bestEndpoint,
		"host_trace":    traceInfo,
	})
}

func (i *instance) handleWARPDelete(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	if cur, gerr := i.store.GetWARP(ctx); gerr == nil && cur != nil {
		deleteCloudflareWARPBestEffort(ctx, cur.AccountID, cur.AccessToken)
	}
	deleted, err := i.store.DeleteWARP(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	coreRev, syncWarn := i.syncWARPToCoreXray(ctx, false)
	return marshalResponse(map[string]any{
		"deleted":       deleted,
		"core_revision": coreRev,
		"sync_warning":  syncWarn,
	})
}
