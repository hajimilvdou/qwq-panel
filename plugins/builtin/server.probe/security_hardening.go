// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 修复 R2-BUG-08 / R2-BUG-14 / R2-BUG-15 / R2-BUG-16：
// server.probe 主题沙箱强化、双形态 $secret 解包、IPv6 /64 防爆破 LRU 锁定器与持久化一致性核心组件
// ============================================================================

const (
	// 对齐 pluginsdk 4 MiB ABI 帧上限与 server.probe 32 MiB cgroup 内存预算
	SafeMaxThemeZipArchiveBytes = 3 << 20 // 3 MiB ZIP 归档上限（100% 穿透 4 MiB gRPC 通道）
	SafeMaxThemeExtractedBytes  = 8 << 20 // 8 MiB 解压总上限
	SafeMaxThemeSingleFileBytes = 2 << 20 // 2 MiB 单文件上限
	SafeMaxCustomThemeCount     = 16      // 最多保留 16 套自定义主题，保护 128 MiB 磁盘配额
)

var rasterLQIPPattern = regexp.MustCompile(`^data:image/(?:webp|jpeg|png);base64,([A-Za-z0-9+/=]+)$`)

// SecretOrPlainField 兼容宿主 x-secret 抽取后的 `{"$secret":"sec_..."}` 引用对象与明文字符串，
// 彻底修复 config.schema.json / probe.domain.bind.request.json 因类型冲突导致的 VALIDATION_FAILED。
type SecretOrPlainField struct {
	Plain     string
	SecretRef string
	Keep      bool
}

func (f *SecretOrPlainField) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*f = SecretOrPlainField{}
		return nil
	}
	if strings.HasPrefix(trimmed, "\"") {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = SecretOrPlainField{Plain: s}
		return nil
	}
	var obj struct {
		Secret        string `json:"$secret"`
		KeepSecret    bool   `json:"$keep_secret"`
		SecretPresent bool   `json:"$secret_present"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*f = SecretOrPlainField{
		SecretRef: strings.TrimSpace(obj.Secret),
		Keep:      obj.KeepSecret || obj.SecretPresent,
	}
	return nil
}

// BuildStrictThemeSandboxCSP 根据当前请求构造零数据外泄的沙箱 CSP：
//   - 仅允许从当前宿主 Origin 加载主题脚本/样式/字体（消除原本 `script-src https: http:` 的任意远程脚本注入与外带漏洞）；
//   - 移除脚本 `'unsafe-inline'`（对齐 PROBE-THEME-GUIDE.md 安全契约）；
//   - 阻断 form-action / base-uri / connect-src。
func BuildStrictThemeSandboxCSP(scheme, host, optionalExternalBgOrigin string) string {
	cleanScheme := "https://"
	if strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "http://") {
		cleanScheme = "http://"
	}
	cleanHost := strings.TrimSpace(host)
	if strings.ContainsAny(cleanHost, " \t\r\n;\"'<>\\") || cleanHost == "" {
		return "sandbox allow-scripts; default-src 'none'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
	}
	selfOrigin := cleanScheme + cleanHost
	imgSources := "data: blob: " + selfOrigin
	if ext := sanitizeHTTPSOrigin(optionalExternalBgOrigin); ext != "" && ext != selfOrigin {
		imgSources += " " + ext
	}
	return "sandbox allow-scripts; default-src 'none'; " +
		"script-src " + selfOrigin + "; " +
		"style-src 'unsafe-inline' " + selfOrigin + "; " +
		"img-src " + imgSources + "; " +
		"font-src data: " + selfOrigin + "; " +
		"connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
}

func sanitizeHTTPSOrigin(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if !strings.HasPrefix(strings.ToLower(s), "https://") {
		return ""
	}
	rest := s[len("https://"):]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	if rest == "" || strings.ContainsAny(rest, " \t\r\n;\"'<>\\@?") {
		return ""
	}
	return "https://" + rest
}

// IsTopLevelThemeFrameNavigation 检测浏览器是否在顶层地址栏直接打开 `/theme-frame/*`（防真域名钓鱼页）。
func IsTopLevelThemeFrameNavigation(headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "Sec-Fetch-Dest") {
			dest := strings.ToLower(strings.TrimSpace(v))
			// 合法嵌入恒为 "iframe"；顶层直接打开恒为 "document"
			return dest == "document"
		}
	}
	return false
}

// CanonicalRateKey 将 IPv4 归一化为单 IP、IPv6 归并为 /64 前缀，彻底阻断利用 /64 子网轮换源地址打爆限流/防暴破表。
func CanonicalRateKey(rawIP string) string {
	s := strings.TrimSpace(rawIP)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "unknown"
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	pfx, err := addr.Prefix(64)
	if err != nil {
		return addr.String()
	}
	return pfx.Masked().String()
}

type loginAttemptEntry struct {
	fails      int
	lastFailAt int64
	lockedTill int64
}

// BoundedAuthGuard 提供不可被 `clear()` 冲刷绕过的防暴破守卫与有序淘汰会话池，
// 同时保护 `/api/admin/login` 与 `/api/public/unlock`。
type BoundedAuthGuard struct {
	mu          sync.Mutex
	maxAttempts int
	maxSessions int
	lockSeconds int64
	maxFails    int
	attempts    map[string]loginAttemptEntry
	sessions    map[[32]byte]int64
}

func NewBoundedAuthGuard() *BoundedAuthGuard {
	return &BoundedAuthGuard{
		maxAttempts: 2048,
		maxSessions: 256,
		lockSeconds: 900, // 连续错误 5 次锁定 15 分钟
		maxFails:    5,
		attempts:    make(map[string]loginAttemptEntry),
		sessions:    make(map[[32]byte]int64),
	}
}

// CheckLocked 检查该客户端网段是否处于暴破锁定期。
func (g *BoundedAuthGuard) CheckLocked(scope, rawClientIP string, nowUnix int64) bool {
	key := scope + "|" + CanonicalRateKey(rawClientIP)
	g.mu.Lock()
	defer g.mu.Unlock()
	att, ok := g.attempts[key]
	if !ok {
		return false
	}
	if att.lockedTill > nowUnix {
		return true
	}
	// 锁定期已过且距上次失败超过窗口，自动清零计数
	if att.lastFailAt > 0 && nowUnix-att.lastFailAt > g.lockSeconds {
		delete(g.attempts, key)
	}
	return false
}

// RetryAfterSeconds 返回剩余锁定时长（秒），未锁定时返回 0。
func (g *BoundedAuthGuard) RetryAfterSeconds(scope, rawClientIP string, nowUnix int64) int64 {
	key := scope + "|" + CanonicalRateKey(rawClientIP)
	g.mu.Lock()
	defer g.mu.Unlock()
	att, ok := g.attempts[key]
	if !ok || att.lockedTill <= nowUnix {
		return 0
	}
	return att.lockedTill - nowUnix
}

// RecordResult 在锁内原子累增失败次数（修复双槽并发 TOCTOU 覆盖），且容量满时绝不淘汰锁定中条目！
func (g *BoundedAuthGuard) RecordResult(scope, rawClientIP string, success bool, nowUnix int64) (locked bool) {
	key := scope + "|" + CanonicalRateKey(rawClientIP)
	g.mu.Lock()
	defer g.mu.Unlock()

	if success {
		delete(g.attempts, key)
		return false
	}

	att := g.attempts[key]
	if att.lastFailAt > 0 && nowUnix-att.lastFailAt > g.lockSeconds && att.lockedTill <= nowUnix {
		att = loginAttemptEntry{}
	}
	att.fails++
	att.lastFailAt = nowUnix
	if att.fails >= g.maxFails {
		att.lockedTill = nowUnix + g.lockSeconds
		locked = true
	}

	if _, exists := g.attempts[key]; !exists && len(g.attempts) >= g.maxAttempts {
		g.evictStaleAttemptLocked(nowUnix)
	}
	// 即便在极端全网 DDoS 下表内全是有效锁定条目，也拒绝覆盖已有锁定，仅在有空位时写入新键
	if _, exists := g.attempts[key]; exists || len(g.attempts) < g.maxAttempts {
		g.attempts[key] = att
	}
	return locked
}

func (g *BoundedAuthGuard) evictStaleAttemptLocked(nowUnix int64) {
	// 1. 优先清理所有已过锁定期或陈旧未锁定记录
	for k, v := range g.attempts {
		if v.lockedTill <= nowUnix && nowUnix-v.lastFailAt > 120 {
			delete(g.attempts, k)
		}
	}
	if len(g.attempts) < g.maxAttempts {
		return
	}
	// 2. 仍满时仅淘汰最老的未锁定（lockedTill <= nowUnix）条目，严禁解封任何 lockedTill > nowUnix 的攻击源！
	var oldestKey string
	var oldestTs int64 = 1<<62 - 1
	for k, v := range g.attempts {
		if v.lockedTill <= nowUnix && v.lastFailAt < oldestTs {
			oldestTs = v.lastFailAt
			oldestKey = k
		}
	}
	if oldestKey != "" {
		delete(g.attempts, oldestKey)
	}
}

// MintSession 签发随机管理员会话并在满额时仅淘汰最早到期会话（绝不 clear 全踢在线管理员）。
func (g *BoundedAuthGuard) MintSession(ttl time.Duration, now time.Time) (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := "prb_adm_" + hex.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(tok))
	exp := now.Add(ttl).Unix()
	nowUnix := now.Unix()

	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.sessions) >= g.maxSessions {
		for k, e := range g.sessions {
			if e <= nowUnix {
				delete(g.sessions, k)
			}
		}
	}
	if len(g.sessions) >= g.maxSessions {
		var earliestKey [32]byte
		var earliestExp int64 = 1<<62 - 1
		first := true
		for k, e := range g.sessions {
			if first || e < earliestExp {
				earliestKey = k
				earliestExp = e
				first = false
			}
		}
		if !first {
			delete(g.sessions, earliestKey)
		}
	}
	g.sessions[sum] = exp
	return tok, nil
}

// VerifySession 恒定时间核验会话令牌。
func (g *BoundedAuthGuard) VerifySession(token string, nowUnix int64) bool {
	if !strings.HasPrefix(token, "prb_adm_") {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.sessions[sum]
	if !ok {
		return false
	}
	if exp <= nowUnix {
		delete(g.sessions, sum)
		return false
	}
	return true
}

// RevokeSession 支持 `POST /api/admin/logout` 服务端立即吊销令牌。
func (g *BoundedAuthGuard) RevokeSession(token string) {
	if !strings.HasPrefix(token, "prb_adm_") {
		return
	}
	sum := sha256.Sum256([]byte(token))
	g.mu.Lock()
	delete(g.sessions, sum)
	g.mu.Unlock()
}

// EncodeAdminVerifier 生成可持久化至 probe_portal_settings.standalone_admin_argon2 列的带盐 PBKDF-HMAC 校验串。
func EncodeAdminVerifier(password string) (string, error) {
	pwd := strings.TrimSpace(password)
	if len(pwd) < 8 || len(pwd) > 128 {
		return "", errors.New("standalone admin password must be 8..128 characters")
	}
	return encodeAdminVerifierRaw(pwd)
}

func encodeAdminVerifierRaw(password string) (string, error) {
	if password == "" || len(password) > 256 {
		return "", errors.New("standalone admin password must be non-empty")
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	dk := deriveAdminHMACKey(salt[:], password)
	return fmt.Sprintf("pbkdf-hmac-sha256$64000$%s$%s", hex.EncodeToString(salt[:]), hex.EncodeToString(dk[:])), nil
}

// VerifyAdminVerifier 校验持久化管理员口令串。
func VerifyAdminVerifier(encoded, candidate string) bool {
	parts := strings.Split(strings.TrimSpace(encoded), "$")
	if len(parts) != 4 || parts[0] != "pbkdf-hmac-sha256" || parts[1] != "64000" {
		return false
	}
	salt, err1 := hex.DecodeString(parts[2])
	want, err2 := hex.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) != 16 || len(want) != 32 {
		return false
	}
	got := deriveAdminHMACKey(salt, candidate)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

func deriveAdminHMACKey(salt []byte, password string) [32]byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write([]byte("qwq-probe-admin-v2:"))
	_, _ = mac.Write([]byte(password))
	var acc [32]byte
	copy(acc[:], mac.Sum(nil))
	cur := acc
	for i := 0; i < 64000; i++ {
		hm := hmac.New(sha256.New, salt)
		_, _ = hm.Write(cur[:])
		copy(cur[:], hm.Sum(nil))
		for j := range acc {
			acc[j] ^= cur[j]
		}
	}
	return acc
}

// SanitizeRasterLQIP 仅允许 WebP/JPEG/PNG Base64 缩略图，拦截 data:image/svg+xml 注入。
func SanitizeRasterLQIP(raw string) string {
	s := strings.TrimSpace(raw)
	m := rasterLQIPPattern.FindStringSubmatch(s)
	if len(m) == 2 && len(m[1]) >= 8 && len(m[1]) <= 8192 {
		return s
	}
	return ""
}
