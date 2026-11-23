// SPDX-License-Identifier: AGPL-3.0-only

// Package store 实现 ai.relay 的本地 SQLite WAL 存储、AES-GCM 加密、Argon2id 口令哈希、
// 四大注册通道、六大虚拟统计额度来源以及热路径原子两阶段预扣费 + 1 秒微批落盘账本。
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// ======================== 常量与数据库初始化 ========================

const (
	MicrosPerDollar      int64 = 1_000_000
	DefaultReserveMicros int64 = 50_000 // 单次请求默认预冻结 $0.05 统计额度防并发击穿
	BatchFlushInterval         = 1 * time.Second
	BatchMaxRows               = 128
	defaultLinuxDoBase         = "https://connect.linux.do"
	emailOTPTTL                = 10 * time.Minute
	maxEmailOTPAttempts        = 5
	portalSessionTTL           = 24 * time.Hour
	oauthStateTTL              = 10 * time.Minute
)

// OpenDB 打开并初始化 WAL 模式 SQLite 数据库，同时加载或生成 32 字节本地 AES-256-GCM 主密钥。
func OpenDB(dataDir, schemaSQL string) (*sql.DB, []byte, error) {
	dsn := ":memory:"
	var masterKey []byte

	if strings.TrimSpace(dataDir) != "" {
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("create relay data dir: %w", err)
		}
		dsn = filepath.Join(dataDir, "relay.db")
		keyPath := filepath.Join(dataDir, "relay.key")
		rawKey, err := os.ReadFile(keyPath)
		if err == nil && len(rawKey) == 32 {
			masterKey = rawKey
		} else {
			masterKey = make([]byte, 32)
			if _, err := rand.Read(masterKey); err != nil {
				return nil, nil, fmt.Errorf("generate master key: %w", err)
			}
			if err := os.WriteFile(keyPath, masterKey, 0o600); err != nil {
				return nil, nil, fmt.Errorf("persist master key: %w", err)
			}
		}
	} else {
		masterKey = make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			return nil, nil, fmt.Errorf("generate ephemeral master key: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA cache_size=-2048;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, nil, fmt.Errorf("exec pragma %q: %w", pragma, err)
		}
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("init schema: %w", err)
	}

	nowMs := time.Now().UTC().UnixMilli()
	if _, err := db.Exec(`INSERT OR IGNORE INTO portal_settings (id, updated_at) VALUES (1, ?);`, nowMs); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("seed portal_settings: %w", err)
	}
	return db, masterKey, nil
}

// ======================== AES-256-GCM 凭据加密与 Argon2id 口令哈希 ========================

// EncryptSecret 使用 AES-256-GCM 加密上游 API Key、OAuth Token 或 SMTP 凭据。
func EncryptSecret(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("store: master key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptSecret 解密由 EncryptSecret 生成的 AES-256-GCM 密文。
func DecryptSecret(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("store: master key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("store: ciphertext too short")
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}

// HashPassword 使用带单槽并发保护与有界内存的 Argon2id 生成加盐密码哈希。
func HashPassword(password string) (string, error) {
	return HashPasswordBounded(context.Background(), password)
}

// VerifyPassword 常量时间验证明文口令与 Argon2id 哈希是否匹配（受单槽与参数上限保护）。
func VerifyPassword(password, encoded string) bool {
	ok, err := VerifyPasswordBounded(context.Background(), password, encoded)
	return err == nil && ok
}

// ======================== 数据视图模型 ========================

type LinuxDoUserProfile struct {
	ID         json.Number `json:"id"`
	Username   string      `json:"username"`
	Name       string      `json:"name"`
	TrustLevel int         `json:"trust_level"`
	Active     bool        `json:"active"`
	Silenced   bool        `json:"silenced"`
}

type LinuxDoTierRule struct {
	Group             string `json:"group"`
	InitMicros        int64  `json:"init_micros"`
	DailyRefillMicros int64  `json:"daily_refill_micros"`
}

type PortalSettingsView struct {
	SiteTitle                     string                     `json:"site_title"`
	SiteAnnouncement              string                     `json:"site_announcement"`
	AllowInviteSignup             bool                       `json:"allow_invite_signup"`
	AllowEmailSignup              bool                       `json:"allow_email_signup"`
	EmailDomainAllowlist          []string                   `json:"email_domain_allowlist"`
	AllowLinuxDoSignup            bool                       `json:"allow_linuxdo_signup"`
	LinuxDoClientID               string                     `json:"linuxdo_client_id"`
	LinuxDoClientSecretConfigured bool                       `json:"linuxdo_client_secret_configured"`
	LinuxDoMinTrustLevel          int                        `json:"linuxdo_min_trust_level"`
	LinuxDoTierRules              map[string]LinuxDoTierRule `json:"linuxdo_tier_rules"`
	DefaultSignupMicros           int64                      `json:"default_signup_micros"`
	InviterRewardMicros           int64                      `json:"inviter_reward_micros"`
	InviteeRewardMicros           int64                      `json:"invitee_reward_micros"`
	MaxInviteRewardsPerUser       int                        `json:"max_invite_rewards_per_user"`
	CheckinEnabled                bool                       `json:"checkin_enabled"`
	CheckinMinMicros              int64                      `json:"checkin_min_micros"`
	CheckinMaxMicros              int64                      `json:"checkin_max_micros"`
	CheckinDripBelowMicros        int64                      `json:"checkin_drip_below_micros"`
	SMTPConfigured                bool                       `json:"smtp_configured"`
	UpdatedAt                     int64                      `json:"updated_at"`
}

type SMTPConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	FromAddress string `json:"from_address"`
}

type SettingsPatch struct {
	SiteTitle               *string
	SiteAnnouncement        *string
	AllowInviteSignup       *bool
	AllowEmailSignup        *bool
	EmailDomainAllowlist    []string
	HasEmailDomainAllowlist bool
	AllowLinuxDoSignup      *bool
	LinuxDoClientID         *string
	LinuxDoClientSecret     string
	LinuxDoMinTrustLevel    *int
	LinuxDoTierRules        map[string]LinuxDoTierRule
	DefaultSignupMicros     *int64
	InviterRewardMicros     *int64
	InviteeRewardMicros     *int64
	MaxInviteRewardsPerUser *int
	CheckinEnabled          *bool
	CheckinMinMicros        *int64
	CheckinMaxMicros        *int64
	CheckinDripBelowMicros  *int64
	SMTP                    *SMTPConfig
}

type UserView struct {
	ID                  string `json:"id"`
	Username            string `json:"username"`
	Email               string `json:"email"`
	GroupName           string `json:"group_name"`
	Status              string `json:"status"`
	SignupSource        string `json:"signup_source"`
	BalanceMicros       int64  `json:"balance_micros"`
	UsedMicros          int64  `json:"used_micros"`
	RequestCount        int64  `json:"request_count"`
	AutoRefillCapMicros int64  `json:"auto_refill_cap_micros"`
	AutoRefillCycle     string `json:"auto_refill_cycle"`
	PersonalInviteCode  string `json:"personal_invite_code"`
	CreatedAt           int64  `json:"created_at"`
	UpdatedAt           int64  `json:"updated_at"`
}

type APITokenView struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	KeyMasked        string   `json:"key_masked"`
	PlainKey         string   `json:"plain_key,omitempty"`
	GroupOverride    string   `json:"group_override"`
	Status           string   `json:"status"`
	QuotaLimitMicros int64    `json:"quota_limit_micros"`
	UsedMicros       int64    `json:"used_micros"`
	AllowedModels    []string `json:"allowed_models"`
	AllowedIPs       []string `json:"allowed_ips"`
	RPMLimit         int      `json:"rpm_limit"`
	ExpiresAt        int64    `json:"expires_at"`
	LastUsedAt       int64    `json:"last_used_at"`
	CreatedAt        int64    `json:"created_at"`
}

type ChannelRecord struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind"`
	BaseURL       string            `json:"base_url"`
	Credential    string            `json:"-"`
	Groups        []string          `json:"groups"`
	Models        []string          `json:"models"`
	ModelMapping  map[string]string `json:"model_mapping"`
	Priority      int               `json:"priority"`
	Weight        int               `json:"weight"`
	MaxConcurrent int               `json:"max_concurrent"`
	Enabled       bool              `json:"enabled"`
	HealthState   string            `json:"health_state"`
	CooldownUntil int64             `json:"cooldown_until"`
	LastTTFTMs    int64             `json:"last_ttft_ms"`
	LastError     string            `json:"last_error"`
	UpdatedAt     int64             `json:"updated_at"`
}

type PricingRecord struct {
	ModelName         string  `json:"model_name"`
	BillingMode       string  `json:"billing_mode"`
	InputMicrosPer1K  int64   `json:"input_micros_per_1k"`
	OutputMicrosPer1K int64   `json:"output_micros_per_1k"`
	CacheReadRatio    float64 `json:"cache_read_ratio"`
	CacheWriteRatio   float64 `json:"cache_write_ratio"`
	PerCallMicros     int64   `json:"per_call_micros"`
	UpdatedAt         int64   `json:"updated_at"`
}

type UsageLogRecord struct {
	UserID           string `json:"user_id"`
	TokenID          string `json:"token_id"`
	TokenName        string `json:"token_name"`
	ModelName        string `json:"model_name"`
	ProtocolIn       string `json:"protocol_in"`
	InputTokens      int    `json:"input_tokens"`
	CachedReadTokens int    `json:"cached_read_tokens"`
	CacheWriteTokens int    `json:"cache_write_tokens"`
	OutputTokens     int    `json:"output_tokens"`
	CostMicros       int64  `json:"cost_micros"`
	TTFTMs           int64  `json:"ttft_ms"`
	DurationMs       int64  `json:"duration_ms"`
	CreatedAtMs      int64  `json:"created_at"`
}

type OverviewStats struct {
	TotalChannels    int
	HealthyChannels  int
	TotalUsers       int
	ActiveUsers      int
	WindowRequests   int64
	WindowCostMicros int64
}

// ======================== 热路径内存原子账本与两阶段预扣费 ========================

type LiveUserQuota struct {
	UserID        string
	GroupName     string
	StatusActive  atomic.Bool
	BalanceMicros atomic.Int64
	UsedMicros    atomic.Int64
}

type LiveAPIToken struct {
	TokenID          string
	TokenName        string
	User             *LiveUserQuota
	GroupOverride    string
	QuotaLimitMicros int64
	UsedMicros       atomic.Int64
	ReservedMicros   atomic.Int64
	AllowedModels    map[string]struct{}
	AllowedPrefixes  []netip.Prefix
	RPMLimit         int
	ExpiresAtUnixMs  int64

	rpmMu       sync.Mutex
	rpmWindowID int64
	rpmCount    int
}

func (t *LiveAPIToken) EffectiveGroup() string {
	if t.GroupOverride != "" {
		return t.GroupOverride
	}
	return t.User.GroupName
}

func (t *LiveAPIToken) AllowRequest(model, clientIP string, now time.Time) error {
	if !t.User.StatusActive.Load() {
		return errors.New("USER_DISABLED: account is disabled")
	}
	if t.ExpiresAtUnixMs > 0 && now.UnixMilli() > t.ExpiresAtUnixMs {
		return errors.New("TOKEN_EXPIRED: sub-key has expired")
	}
	if len(t.AllowedModels) > 0 && model != "" {
		if _, ok := t.AllowedModels[model]; !ok {
			return fmt.Errorf("MODEL_NOT_ALLOWED: key is not permitted to access model %s", model)
		}
	}
	if len(t.AllowedPrefixes) > 0 {
		addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(clientIP), "[]"))
		if err != nil {
			return errors.New("IP_DENIED: invalid client IP")
		}
		addr = addr.Unmap()
		allowed := false
		for _, pfx := range t.AllowedPrefixes {
			if pfx.Contains(addr) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("IP_DENIED: client IP %s not in key allowlist", clientIP)
		}
	}
	if t.RPMLimit > 0 {
		win := now.Unix() / 60
		t.rpmMu.Lock()
		if t.rpmWindowID != win {
			t.rpmWindowID = win
			t.rpmCount = 0
		}
		if t.rpmCount >= t.RPMLimit {
			t.rpmMu.Unlock()
			return fmt.Errorf("RATE_LIMITED: sub-key RPM limit (%d/min) exceeded", t.RPMLimit)
		}
		t.rpmCount++
		t.rpmMu.Unlock()
	}
	return nil
}

type QuotaReservation struct {
	ledger      *LedgerEngine
	token       *LiveAPIToken
	reserved    int64
	subReserved int64
	settled     atomic.Bool
}

// ReservedMicros 返回本次请求原子冻结的微点额度。
func (r *QuotaReservation) ReservedMicros() int64 {
	if r == nil {
		return 0
	}
	return r.reserved
}

// Settle 在流式响应结束或异常中断时调用（幂等只结算一次）：
// 严格保证余额 >= 0 且累计扣费不超可用余额，同时将消费记录推入微批写库器。
func (r *QuotaReservation) Settle(actualCostMicros int64, logRec UsageLogRecord) int64 {
	if r == nil || !r.settled.CompareAndSwap(false, true) {
		return 0
	}
	if actualCostMicros < 0 {
		actualCostMicros = 0
	}

	var charged int64
	if actualCostMicros <= r.reserved {
		charged = actualCostMicros
		if refund := r.reserved - actualCostMicros; refund > 0 {
			r.token.User.BalanceMicros.Add(refund)
		}
	} else {
		extraNeeded := actualCostMicros - r.reserved
		var extraTaken int64
		for {
			cur := r.token.User.BalanceMicros.Load()
			if cur <= 0 {
				break
			}
			take := min(cur, extraNeeded)
			if r.token.User.BalanceMicros.CompareAndSwap(cur, cur-take) {
				extraTaken = take
				break
			}
		}
		charged = r.reserved + extraTaken
	}

	if r.subReserved > 0 {
		r.token.ReservedMicros.Add(-r.subReserved)
	}
	if charged > 0 {
		r.token.User.UsedMicros.Add(charged)
		r.token.UsedMicros.Add(charged)
	}
	if charged > 0 || logRec.InputTokens > 0 || logRec.OutputTokens > 0 {
		logRec.CostMicros = charged
		if logRec.CreatedAtMs == 0 {
			logRec.CreatedAtMs = r.ledger.now().UTC().UnixMilli()
		}
		r.ledger.enqueueSettlement(logRec)
	}
	return charged
}

type portalSession struct {
	userID    string
	expiresAt time.Time
}

type oauthPKCEState struct {
	verifier  string
	expiresAt time.Time
}

type LedgerEngine struct {
	db             *sql.DB
	masterKey      []byte
	httpClient     *http.Client
	now            func() time.Time
	linuxDoBaseURL string

	mu          sync.RWMutex
	users       map[string]*LiveUserQuota
	tokens      map[string]*LiveAPIToken
	sessions    map[string]portalSession
	oauthStates map[string]oauthPKCEState

	batchMu   sync.Mutex
	batchStop func()
	batchCh   chan UsageLogRecord
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func NewLedgerEngine(db *sql.DB, masterKey []byte, httpClient *http.Client, now func() time.Time) *LedgerEngine {
	if now == nil {
		now = time.Now
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 12 * time.Second}
	}
	return &LedgerEngine{
		db:             db,
		masterKey:      append([]byte(nil), masterKey...),
		httpClient:     httpClient,
		now:            now,
		linuxDoBaseURL: defaultLinuxDoBase,
		users:          make(map[string]*LiveUserQuota),
		tokens:         make(map[string]*LiveAPIToken),
		sessions:       make(map[string]portalSession),
		oauthStates:    make(map[string]oauthPKCEState),
		batchCh:        make(chan UsageLogRecord, 4096),
	}
}

// SetLinuxDoBaseURL 允许测试替换 LinuxDo OAuth2 端点为本地 httptest 服务。
func (e *LedgerEngine) SetLinuxDoBaseURL(raw string) {
	e.mu.Lock()
	if strings.TrimSpace(raw) != "" {
		e.linuxDoBaseURL = strings.TrimRight(strings.TrimSpace(raw), "/")
	}
	e.mu.Unlock()
}

func (e *LedgerEngine) linuxDoEndpoint(path string) string {
	e.mu.RLock()
	base := e.linuxDoBaseURL
	e.mu.RUnlock()
	return base + path
}

// LoadFromDB 启动时将 SQLite 中既有用户与活跃子令牌预热至内存热缓存。
func (e *LedgerEngine) LoadFromDB(ctx context.Context) error {
	users := make(map[string]*LiveUserQuota)
	uRows, err := e.db.QueryContext(ctx, `
		SELECT id, group_name, status, balance_micros, used_micros FROM relay_users;`)
	if err != nil {
		return err
	}
	for uRows.Next() {
		var id, grp, st string
		var bal, used int64
		if err := uRows.Scan(&id, &grp, &st, &bal, &used); err != nil {
			_ = uRows.Close()
			return err
		}
		lu := &LiveUserQuota{UserID: id, GroupName: grp}
		lu.StatusActive.Store(st == "active")
		lu.BalanceMicros.Store(bal)
		lu.UsedMicros.Store(used)
		users[id] = lu
	}
	if err := uRows.Close(); err != nil {
		return err
	}
	if err := uRows.Err(); err != nil {
		return err
	}

	tokens := make(map[string]*LiveAPIToken)
	tRows, err := e.db.QueryContext(ctx, `
		SELECT id, user_id, name, key_sha256, group_override, status, quota_limit_micros, used_micros,
		       allowed_models_json, allowed_ips_json, rpm_limit, expires_at
		FROM api_tokens WHERE status = 'active';`)
	if err != nil {
		return err
	}
	for tRows.Next() {
		var id, uid, name, hash, grpOv, st, modelsJSON, ipsJSON string
		var limitM, usedM, expMs int64
		var rpm int
		if err := tRows.Scan(&id, &uid, &name, &hash, &grpOv, &st, &limitM, &usedM, &modelsJSON, &ipsJSON, &rpm, &expMs); err != nil {
			_ = tRows.Close()
			return err
		}
		u, ok := users[uid]
		if !ok || st != "active" {
			continue
		}
		var models []string
		var ips []string
		_ = json.Unmarshal([]byte(modelsJSON), &models)
		_ = json.Unmarshal([]byte(ipsJSON), &ips)
		lt := buildLiveToken(id, name, u, grpOv, limitM, usedM, models, ips, rpm, expMs)
		tokens[hash] = lt
	}
	if err := tRows.Close(); err != nil {
		return err
	}
	if err := tRows.Err(); err != nil {
		return err
	}

	e.mu.Lock()
	e.users = users
	e.tokens = tokens
	e.mu.Unlock()
	return nil
}

// StartBatcher 启动 1 秒 / 128 条微批写库协程；返回的停止函数阻塞直至全部缓冲记录落盘。
func (e *LedgerEngine) StartBatcher(ctx context.Context) func() {
	e.batchMu.Lock()
	if e.batchStop != nil {
		stop := e.batchStop
		e.batchMu.Unlock()
		return stop
	}
	stopCh := make(chan struct{})
	var stopOnce sync.Once
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(BatchFlushInterval)
		defer ticker.Stop()
		buf := make([]UsageLogRecord, 0, BatchMaxRows)

		flush := func() {
			if len(buf) == 0 {
				return
			}
			if err := e.flushBatchToSQLite(context.Background(), buf); err != nil {
				// Retain failed batch for next tick retry instead of dropping ledger records.
				if len(buf) > BatchMaxRows*8 {
					buf = buf[len(buf)-BatchMaxRows*8:]
				}
				return
			}
			buf = buf[:0]
		}
		drainAndExit := func() {
			for {
				select {
				case rec := <-e.batchCh:
					buf = append(buf, rec)
					if len(buf) >= BatchMaxRows {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}

		for {
			select {
			case rec := <-e.batchCh:
				buf = append(buf, rec)
				if len(buf) >= BatchMaxRows {
					flush()
				}
			case <-ticker.C:
				flush()
			case <-ctx.Done():
				drainAndExit()
				return
			case <-stopCh:
				drainAndExit()
				return
			}
		}
	}()

	stopFn := func() {
		stopOnce.Do(func() {
			close(stopCh)
			e.wg.Wait()
			e.batchMu.Lock()
			e.batchStop = nil
			e.batchMu.Unlock()
		})
	}
	e.batchStop = stopFn
	e.batchMu.Unlock()
	return stopFn
}

// FlushSync 主动排空当前微批管道并落盘（供 Deactivate / 测试零丢账核验使用）。
func (e *LedgerEngine) FlushSync(ctx context.Context) error {
	e.batchMu.Lock()
	stop := e.batchStop
	e.batchMu.Unlock()
	if stop != nil {
		stop()
		return nil
	}
	buf := make([]UsageLogRecord, 0, BatchMaxRows)
	for {
		select {
		case rec := <-e.batchCh:
			buf = append(buf, rec)
		default:
			if len(buf) == 0 {
				return nil
			}
			return e.flushBatchToSQLite(ctx, buf)
		}
	}
}

// Close 停止微批协程、刷空全部缓冲并幂等关闭 SQLite 连接。
func (e *LedgerEngine) Close() error {
	var closeErr error
	e.closeOnce.Do(func() {
		_ = e.FlushSync(context.Background())
		if e.db != nil {
			closeErr = e.db.Close()
		}
	})
	return closeErr
}

func (e *LedgerEngine) enqueueSettlement(rec UsageLogRecord) {
	select {
	case e.batchCh <- rec:
	default:
		_ = e.flushBatchToSQLite(context.Background(), []UsageLogRecord{rec})
	}
}

func (e *LedgerEngine) flushBatchToSQLite(ctx context.Context, batch []UsageLogRecord) error {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	type userDelta struct {
		cost int64
		reqs int64
	}
	userDeltas := make(map[string]userDelta)
	tokenDeltas := make(map[string]int64)

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO usage_logs (user_id, token_id, token_name, model_name, protocol_in,
		                        input_tokens, cached_read_tokens, cache_write_tokens, output_tokens,
		                        cost_micros, ttft_ms, duration_ms, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range batch {
		if _, err := stmt.ExecContext(ctx,
			r.UserID, r.TokenID, r.TokenName, r.ModelName, r.ProtocolIn,
			r.InputTokens, r.CachedReadTokens, r.CacheWriteTokens, r.OutputTokens,
			r.CostMicros, r.TTFTMs, r.DurationMs, r.CreatedAtMs,
		); err != nil {
			return err
		}
		ud := userDeltas[r.UserID]
		ud.cost += r.CostMicros
		ud.reqs++
		userDeltas[r.UserID] = ud
		tokenDeltas[r.TokenID] += r.CostMicros
	}

	nowMs := e.now().UTC().UnixMilli()
	for uid, ud := range userDeltas {
		if _, err := tx.ExecContext(ctx, `
			UPDATE relay_users
			SET balance_micros = MAX(0, balance_micros - ?),
			    used_micros    = used_micros + ?,
			    request_count  = request_count + ?,
			    updated_at     = ?
			WHERE id = ?;`, ud.cost, ud.cost, ud.reqs, nowMs, uid); err != nil {
			return err
		}
	}
	for tid, cost := range tokenDeltas {
		if _, err := tx.ExecContext(ctx, `
			UPDATE api_tokens SET used_micros = used_micros + ?, last_used_at = ? WHERE id = ?;`,
			cost, nowMs, tid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AuthorizeAndReserve 热路径零数据库锁完成 sk-qwq-* 鉴权与原子 CAS 预冻结额度。
func (e *LedgerEngine) AuthorizeAndReserve(rawBearerKey, model, clientIP string, reserveMicros int64) (*LiveAPIToken, *QuotaReservation, error) {
	if !strings.HasPrefix(rawBearerKey, "sk-qwq-") || len(rawBearerKey) < 24 {
		return nil, nil, errors.New("UNAUTHENTICATED: invalid sk-qwq-* API key")
	}
	sum := sha256.Sum256([]byte(rawBearerKey))
	keyHash := hex.EncodeToString(sum[:])

	e.mu.RLock()
	tok, exists := e.tokens[keyHash]
	e.mu.RUnlock()
	if !exists {
		return nil, nil, errors.New("UNAUTHENTICATED: API key not found or disabled")
	}

	if err := tok.AllowRequest(model, clientIP, e.now()); err != nil {
		return nil, nil, err
	}

	if reserveMicros <= 0 {
		reserveMicros = DefaultReserveMicros
	}

	var subLock int64
	if tok.QuotaLimitMicros > 0 {
		for {
			used := tok.UsedMicros.Load()
			res := tok.ReservedMicros.Load()
			rem := tok.QuotaLimitMicros - used - res
			if rem <= 0 {
				return nil, nil, errors.New("QUOTA_EXHAUSTED: sub-key quota limit reached")
			}
			want := min(rem, reserveMicros)
			if tok.ReservedMicros.CompareAndSwap(res, res+want) {
				subLock = want
				reserveMicros = want
				break
			}
		}
	}

	for {
		cur := tok.User.BalanceMicros.Load()
		if cur <= 0 {
			if subLock > 0 {
				tok.ReservedMicros.Add(-subLock)
			}
			return nil, nil, errors.New("QUOTA_EXHAUSTED: insufficient account statistical quota")
		}
		lockAmt := min(cur, reserveMicros)
		if tok.User.BalanceMicros.CompareAndSwap(cur, cur-lockAmt) {
			if subLock > lockAmt {
				tok.ReservedMicros.Add(-(subLock - lockAmt))
				subLock = lockAmt
			}
			return tok, &QuotaReservation{
				ledger:      e,
				token:       tok,
				reserved:    lockAmt,
				subReserved: subLock,
			}, nil
		}
	}
}

// MemoryBalance 返回内存热账本中用户的实时可用余额。
func (e *LedgerEngine) MemoryBalance(userID string) (balanceMicros, usedMicros int64, ok bool) {
	e.mu.RLock()
	u, exists := e.users[userID]
	e.mu.RUnlock()
	if !exists {
		return 0, 0, false
	}
	return u.BalanceMicros.Load(), u.UsedMicros.Load(), true
}

// ======================== 四种用户注册与认证（Admin / Invite / Email OTP / LinuxDo OAuth2） ========================

// CreateUserByAdmin 管理员直接发号创建分发成员并授予初始统计额度与可选周期自动回血。
func (e *LedgerEngine) CreateUserByAdmin(ctx context.Context, username, password, email, groupName string, initMicros, dailyRefillMicros int64, cycle string) (UserView, error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 32 {
		return UserView{}, errors.New("VALIDATION_FAILED: 用户名长度需在 3..32 字符之间")
	}
	pwHash, err := HashPasswordBounded(ctx, password)
	if err != nil {
		return UserView{}, err
	}
	if strings.TrimSpace(groupName) == "" {
		groupName = "default"
	}
	if initMicros < 0 {
		initMicros = 0
	}
	if dailyRefillMicros < 0 {
		dailyRefillMicros = 0
	}
	if cycle == "" || cycle == "none" {
		if dailyRefillMicros > 0 {
			cycle = "daily"
		} else {
			cycle = "none"
		}
	}
	if cycle != "none" && cycle != "daily" && cycle != "monthly" {
		return UserView{}, errors.New("VALIDATION_FAILED: invalid auto_refill_cycle")
	}

	nowMs := e.now().UTC().UnixMilli()
	userID := randomHexID("ru_", 10)
	invCode := randomHexID("INV", 5)
	var emailNull sql.NullString
	if strings.TrimSpace(email) != "" {
		emailNull = sql.NullString{String: strings.ToLower(strings.TrimSpace(email)), Valid: true}
	}

	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return UserView{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO relay_users (id, username, password_hash, email, group_name, status, signup_source,
		                         balance_micros, auto_refill_cap_micros, auto_refill_cycle, personal_invite_code, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'active', 'admin', ?, ?, ?, ?, ?, ?);`,
		userID, username, pwHash, emailNull, groupName, initMicros, dailyRefillMicros, cycle, invCode, nowMs, nowMs); err != nil {
		return UserView{}, fmt.Errorf("CONFLICT: 用户名或邮箱已被占用: %w", err)
	}
	if initMicros > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO quota_ledger (user_id, source, delta_micros, balance_after, note, created_at)
			VALUES (?, 'signup_gift', ?, ?, 'Admin created', ?);`,
			userID, initMicros, initMicros, nowMs); err != nil {
			return UserView{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return UserView{}, err
	}

	e.registerMemoryUser(userID, groupName, initMicros)
	return UserView{
		ID:                  userID,
		Username:            username,
		Email:               emailNull.String,
		GroupName:           groupName,
		Status:              "active",
		SignupSource:        "admin",
		BalanceMicros:       initMicros,
		AutoRefillCapMicros: dailyRefillMicros,
		AutoRefillCycle:     cycle,
		PersonalInviteCode:  invCode,
		CreatedAt:           nowMs,
		UpdatedAt:           nowMs,
	}, nil
}

// SignupWithInviteCode 支持管理员批次邀请码或老用户个人邀请码注册，并原子发放双方奖励。
func (e *LedgerEngine) SignupWithInviteCode(ctx context.Context, username, password, inviteCode string) (string, error) {
	username = strings.TrimSpace(username)
	inviteCode = strings.TrimSpace(inviteCode)
	if len(username) < 3 || len(username) > 32 {
		return "", errors.New("VALIDATION_FAILED: 用户名长度需在 3..32 字符之间")
	}
	pwHash, err := HashPasswordBounded(ctx, password)
	if err != nil {
		return "", err
	}

	nowMs := e.now().UTC().UnixMilli()
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var allowInvite int
	var defaultMicros, inviterBonus, inviteeBonus int64
	var maxRewards int
	if err := tx.QueryRowContext(ctx, `
		SELECT allow_invite_signup, default_signup_micros, inviter_reward_micros, invitee_reward_micros, max_invite_rewards_per_user
		FROM portal_settings WHERE id = 1;`,
	).Scan(&allowInvite, &defaultMicros, &inviterBonus, &inviteeBonus, &maxRewards); err != nil {
		return "", err
	}
	if allowInvite == 0 {
		return "", errors.New("SIGNUP_CLOSED: 当前未开放邀请码注册")
	}

	grantGroup := "default"
	initQuota := defaultMicros
	var inviterID sql.NullString
	var creditedInviterID string
	var creditedInviterDelta int64

	var codeBonus int64
	var maxUses, usedCount int
	var expMs int64
	err = tx.QueryRowContext(ctx, `
		SELECT grant_group, bonus_micros, max_uses, used_count, expires_at FROM invite_codes WHERE code = ?;`,
		inviteCode).Scan(&grantGroup, &codeBonus, &maxUses, &usedCount, &expMs)
	if err == nil {
		if (expMs > 0 && nowMs > expMs) || usedCount >= maxUses {
			return "", errors.New("INVITE_INVALID: 邀请码已过期或次数已用尽")
		}
		res, err := tx.ExecContext(ctx, `UPDATE invite_codes SET used_count = used_count + 1 WHERE code = ? AND used_count < max_uses;`, inviteCode)
		if err != nil {
			return "", err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return "", errors.New("INVITE_INVALID: 邀请码次数已用尽")
		}
		initQuota += codeBonus
	} else {
		var ownerID string
		var rewardCnt int
		if err2 := tx.QueryRowContext(ctx, `
			SELECT id, invite_reward_count FROM relay_users WHERE personal_invite_code = ? AND status = 'active';`,
			inviteCode).Scan(&ownerID, &rewardCnt); err2 != nil {
			return "", errors.New("INVITE_INVALID: 无效的邀请码")
		}
		inviterID = sql.NullString{String: ownerID, Valid: true}
		initQuota += inviteeBonus
		if rewardCnt < maxRewards && inviterBonus > 0 {
			var afterInviter int64
			if err := e.creditUserTx(ctx, tx, ownerID, "invite_bonus", inviterBonus, "Invited:"+username, nowMs, &afterInviter); err != nil {
				return "", err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE relay_users SET invite_reward_count = invite_reward_count + 1 WHERE id = ?;`, ownerID); err != nil {
				return "", err
			}
			creditedInviterID = ownerID
			creditedInviterDelta = inviterBonus
		}
	}

	userID := randomHexID("ru_", 10)
	myInvCode := randomHexID("INV", 5)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO relay_users (id, username, password_hash, group_name, status, signup_source, invited_by,
		                         balance_micros, personal_invite_code, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'active', 'invite', ?, ?, ?, ?, ?);`,
		userID, username, pwHash, grantGroup, inviterID, initQuota, myInvCode, nowMs, nowMs); err != nil {
		return "", fmt.Errorf("CONFLICT: 用户名已存在: %w", err)
	}
	if initQuota > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO quota_ledger (user_id, source, delta_micros, balance_after, note, created_at)
			VALUES (?, 'signup_gift', ?, ?, ?, ?);`,
			userID, initQuota, initQuota, "Invite:"+inviteCode, nowMs); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	e.registerMemoryUser(userID, grantGroup, initQuota)
	if creditedInviterID != "" && creditedInviterDelta > 0 {
		e.addMemoryBalance(creditedInviterID, creditedInviterDelta)
	}
	return userID, nil
}

// SendEmailOTP 校验邮箱注册开关与域名白名单，签发 6 位一次性验证码并保存 SHA-256 摘要。
func (e *LedgerEngine) SendEmailOTP(ctx context.Context, email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var allowEmail int
	var allowlistJSON string
	if err := e.db.QueryRowContext(ctx, `
		SELECT allow_email_signup, email_domain_allowlist_json FROM portal_settings WHERE id = 1;`,
	).Scan(&allowEmail, &allowlistJSON); err != nil {
		return "", err
	}
	if allowEmail == 0 {
		return "", errors.New("SIGNUP_CLOSED: 当前未开放邮箱验证码注册")
	}
	var allowlist []string
	_ = json.Unmarshal([]byte(allowlistJSON), &allowlist)
	if !ValidateEmailAllowed(email, allowlist) {
		return "", errors.New("EMAIL_DOMAIN_DENIED: 该邮箱格式无效或不在允许注册的域名白名单内")
	}

	nBig, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	otp := fmt.Sprintf("%06d", nBig.Int64())
	sum := sha256.Sum256([]byte(otp))
	codeHash := hex.EncodeToString(sum[:])

	now := e.now().UTC()
	nowMs := now.UnixMilli()
	expMs := now.Add(emailOTPTTL).UnixMilli()
	if _, err := e.db.ExecContext(ctx, `
		INSERT INTO email_verifications (email, code_sha256, attempts, expires_at, sent_at)
		VALUES (?, ?, 0, ?, ?)
		ON CONFLICT(email) DO UPDATE SET
			code_sha256 = excluded.code_sha256,
			attempts    = 0,
			expires_at  = excluded.expires_at,
			sent_at     = excluded.sent_at;`,
		email, codeHash, expMs, nowMs); err != nil {
		return "", err
	}
	return otp, nil
}

// SignupWithEmailOTP 核验邮箱 6 位验证码后创建用户并授予默认注册赠额。
func (e *LedgerEngine) SignupWithEmailOTP(ctx context.Context, username, password, email, otp string) (string, error) {
	username = strings.TrimSpace(username)
	email = strings.ToLower(strings.TrimSpace(email))
	otp = strings.TrimSpace(otp)
	if len(username) < 3 || len(username) > 32 {
		return "", errors.New("VALIDATION_FAILED: 用户名长度需在 3..32 字符之间")
	}
	pwHash, err := HashPasswordBounded(ctx, password)
	if err != nil {
		return "", err
	}

	nowMs := e.now().UTC().UnixMilli()
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var allowEmail int
	var allowlistJSON string
	var defaultMicros int64
	if err := tx.QueryRowContext(ctx, `
		SELECT allow_email_signup, email_domain_allowlist_json, default_signup_micros
		FROM portal_settings WHERE id = 1;`,
	).Scan(&allowEmail, &allowlistJSON, &defaultMicros); err != nil {
		return "", err
	}
	if allowEmail == 0 {
		return "", errors.New("SIGNUP_CLOSED: 当前未开放邮箱验证码注册")
	}
	var allowlist []string
	_ = json.Unmarshal([]byte(allowlistJSON), &allowlist)
	if !ValidateEmailAllowed(email, allowlist) {
		return "", errors.New("EMAIL_DOMAIN_DENIED: 该邮箱不在允许注册的域名白名单内")
	}

	var storedHash string
	var attempts int
	var expMs int64
	err = tx.QueryRowContext(ctx, `
		SELECT code_sha256, attempts, expires_at FROM email_verifications WHERE email = ?;`, email,
	).Scan(&storedHash, &attempts, &expMs)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("OTP_INVALID: 请先获取邮箱验证码")
	}
	if err != nil {
		return "", err
	}
	if nowMs > expMs {
		return "", errors.New("OTP_EXPIRED: 邮箱验证码已过期")
	}
	if attempts >= maxEmailOTPAttempts {
		return "", errors.New("OTP_LOCKED: 验证码错误次数过多，请重新发送")
	}
	sum := sha256.Sum256([]byte(otp))
	actualHash := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(actualHash), []byte(storedHash)) != 1 {
		_, _ = tx.ExecContext(ctx, `UPDATE email_verifications SET attempts = attempts + 1 WHERE email = ?;`, email)
		_ = tx.Commit()
		return "", errors.New("OTP_INVALID: 邮箱验证码不正确")
	}

	_, _ = tx.ExecContext(ctx, `DELETE FROM email_verifications WHERE email = ?;`, email)

	userID := randomHexID("ru_", 10)
	myInvCode := randomHexID("INV", 5)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO relay_users (id, username, password_hash, email, group_name, status, signup_source,
		                         balance_micros, personal_invite_code, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'default', 'active', 'email', ?, ?, ?, ?);`,
		userID, username, pwHash, email, defaultMicros, myInvCode, nowMs, nowMs); err != nil {
		return "", fmt.Errorf("CONFLICT: 用户名或邮箱已被占用: %w", err)
	}
	if defaultMicros > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO quota_ledger (user_id, source, delta_micros, balance_after, note, created_at)
			VALUES (?, 'signup_gift', ?, ?, ?, ?);`,
			userID, defaultMicros, defaultMicros, "Email:"+email, nowMs); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	e.registerMemoryUser(userID, "default", defaultMicros)
	return userID, nil
}

// LoginOrSignupWithLinuxDo 完成 LinuxDo OAuth2 + PKCE 换码、active/!silenced 与 trust_level 门槛校验及分级映射。
func (e *LedgerEngine) LoginOrSignupWithLinuxDo(
	ctx context.Context,
	clientID, clientSecret, redirectURI, code, codeVerifier string,
) (userID string, username string, isNewUser bool, err error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	tokReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.linuxDoEndpoint("/oauth2/token"), strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", false, err
	}
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.Header.Set("Accept", "application/json")

	tokResp, err := e.httpClient.Do(tokReq)
	if err != nil {
		return "", "", false, fmt.Errorf("LINUXDO_UNAVAILABLE: token exchange failed: %w", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		return "", "", false, fmt.Errorf("LINUXDO_AUTH_FAILED: token endpoint status %d", tokResp.StatusCode)
	}

	var tokData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tokData); err != nil || tokData.AccessToken == "" {
		return "", "", false, errors.New("LINUXDO_AUTH_FAILED: invalid token payload")
	}

	uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, e.linuxDoEndpoint("/api/user"), nil)
	if err != nil {
		return "", "", false, err
	}
	uReq.Header.Set("Authorization", "Bearer "+tokData.AccessToken)
	uResp, err := e.httpClient.Do(uReq)
	if err != nil {
		return "", "", false, err
	}
	defer uResp.Body.Close()
	if uResp.StatusCode != http.StatusOK {
		return "", "", false, fmt.Errorf("LINUXDO_AUTH_FAILED: user endpoint status %d", uResp.StatusCode)
	}

	var profile LinuxDoUserProfile
	if err := json.NewDecoder(uResp.Body).Decode(&profile); err != nil {
		return "", "", false, err
	}
	if !profile.Active || profile.Silenced {
		return "", "", false, errors.New("PERMISSION_DENIED: LinuxDo 账号未激活或处于禁言状态")
	}

	nowMs := e.now().UTC().UnixMilli()
	extID := profile.ID.String()

	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", false, err
	}
	defer func() { _ = tx.Rollback() }()

	var allowLinuxDo, minTL int
	var tierJSON string
	if err := tx.QueryRowContext(ctx, `
		SELECT allow_linuxdo_signup, linuxdo_min_trust_level, linuxdo_tier_rules_json FROM portal_settings WHERE id = 1;`,
	).Scan(&allowLinuxDo, &minTL, &tierJSON); err != nil {
		return "", "", false, err
	}

	err = tx.QueryRowContext(ctx, `
		SELECT u.id, u.username FROM user_oauth_links l JOIN relay_users u ON u.id = l.user_id
		WHERE l.provider = 'linuxdo' AND l.external_id = ?;`, extID,
	).Scan(&userID, &username)
	if err == nil {
		_, _ = tx.ExecContext(ctx, `
			UPDATE user_oauth_links SET trust_level = ?, external_login = ?, last_login_at = ?
			WHERE provider = 'linuxdo' AND external_id = ?;`,
			profile.TrustLevel, profile.Username, nowMs, extID)
		_ = tx.Commit()
		return userID, username, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", false, err
	}

	if allowLinuxDo == 0 {
		return "", "", false, errors.New("SIGNUP_CLOSED: 当前未开放 LinuxDo 新用户自助注册")
	}
	if profile.TrustLevel < minTL {
		return "", "", false, fmt.Errorf("TRUST_LEVEL_TOO_LOW: 本站要求 LinuxDo 信任等级 >= TL%d（当前 TL%d）", minTL, profile.TrustLevel)
	}

	tiers := make(map[string]LinuxDoTierRule)
	_ = json.Unmarshal([]byte(tierJSON), &tiers)
	rule, ok := tiers[strconv.Itoa(profile.TrustLevel)]
	if !ok {
		rule = LinuxDoTierRule{Group: "default", InitMicros: 5 * MicrosPerDollar}
	}
	if rule.Group == "" {
		rule.Group = "default"
	}

	userID = randomHexID("ru_", 10)
	username = "ld_" + profile.Username
	invCode := randomHexID("INV", 5)
	refillCycle := "none"
	if rule.DailyRefillMicros > 0 {
		refillCycle = "daily"
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO relay_users (id, username, group_name, status, signup_source, balance_micros,
		                         auto_refill_cap_micros, auto_refill_cycle, personal_invite_code, created_at, updated_at)
		VALUES (?, ?, ?, 'active', 'linuxdo', ?, ?, ?, ?, ?, ?);`,
		userID, username, rule.Group, rule.InitMicros, rule.DailyRefillMicros, refillCycle, invCode, nowMs, nowMs); err != nil {
		return "", "", false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_oauth_links (provider, external_id, user_id, external_login, trust_level, last_login_at)
		VALUES ('linuxdo', ?, ?, ?, ?, ?);`,
		extID, userID, profile.Username, profile.TrustLevel, nowMs); err != nil {
		return "", "", false, err
	}
	if rule.InitMicros > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO quota_ledger (user_id, source, delta_micros, balance_after, note, created_at)
			VALUES (?, 'signup_gift', ?, ?, ?, ?);`,
			userID, rule.InitMicros, rule.InitMicros, fmt.Sprintf("LinuxDo TL%d initial quota", profile.TrustLevel), nowMs); err != nil {
			return "", "", false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", "", false, err
	}
	e.registerMemoryUser(userID, rule.Group, rule.InitMicros)
	return userID, username, true, nil
}

// AuthenticatePassword 校验分发用户密码并返回用户 ID。
func (e *LedgerEngine) AuthenticatePassword(ctx context.Context, username, password string) (string, error) {
	var id, hash, status string
	err := e.db.QueryRowContext(ctx, `
		SELECT id, password_hash, status FROM relay_users WHERE username = ?;`, strings.TrimSpace(username),
	).Scan(&id, &hash, &status)
	if errors.Is(err, sql.ErrNoRows) || hash == "" {
		return "", errors.New("UNAUTHENTICATED: 用户名或密码错误")
	}
	if err != nil {
		return "", err
	}
	matched, verifyErr := VerifyPasswordBounded(ctx, password, hash)
	if verifyErr != nil {
		if strings.HasPrefix(verifyErr.Error(), "RATE_LIMITED") {
			return "", verifyErr
		}
		return "", errors.New("UNAUTHENTICATED: 用户名或密码错误")
	}
	if !matched {
		return "", errors.New("UNAUTHENTICATED: 用户名或密码错误")
	}
	if status != "active" {
		return "", errors.New("USER_DISABLED: 该分发账号已被停用")
	}
	return id, nil
}

// ======================== 门户隔离会话（rly_sess_*）与 PKCE 状态 ========================

const (
	maxPortalSessions = 2048
	maxOAuthStates    = 1024
)

func (e *LedgerEngine) CreateSession(userID string) string {
	token := "rly_sess_" + randomBase64Token(24)
	now := e.now()
	exp := now.Add(portalSessionTTL)
	e.mu.Lock()
	if len(e.sessions) >= maxPortalSessions {
		for k, v := range e.sessions {
			if now.After(v.expiresAt) {
				delete(e.sessions, k)
			}
		}
		if len(e.sessions) >= maxPortalSessions {
			var oldestKey string
			var oldestExp time.Time
			for k, v := range e.sessions {
				if oldestKey == "" || v.expiresAt.Before(oldestExp) {
					oldestKey, oldestExp = k, v.expiresAt
				}
			}
			if oldestKey != "" {
				delete(e.sessions, oldestKey)
			}
		}
	}
	e.sessions[token] = portalSession{userID: userID, expiresAt: exp}
	e.mu.Unlock()
	return token
}

func (e *LedgerEngine) ValidateSession(token string) (string, bool) {
	if !strings.HasPrefix(token, "rly_sess_") {
		return "", false
	}
	now := e.now()
	e.mu.RLock()
	sess, ok := e.sessions[token]
	e.mu.RUnlock()
	if !ok {
		return "", false
	}
	if now.After(sess.expiresAt) {
		e.mu.Lock()
		delete(e.sessions, token)
		e.mu.Unlock()
		return "", false
	}
	return sess.userID, true
}

func (e *LedgerEngine) DeleteSession(token string) {
	e.mu.Lock()
	delete(e.sessions, token)
	e.mu.Unlock()
}

func (e *LedgerEngine) CreateOAuthState() (state, verifier, challenge string) {
	state = randomHexID("st_", 12)
	verifier = randomBase64Token(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	now := e.now()
	e.mu.Lock()
	if len(e.oauthStates) >= maxOAuthStates {
		for k, v := range e.oauthStates {
			if now.After(v.expiresAt) {
				delete(e.oauthStates, k)
			}
		}
		if len(e.oauthStates) >= maxOAuthStates {
			var oldestKey string
			var oldestExp time.Time
			for k, v := range e.oauthStates {
				if oldestKey == "" || v.expiresAt.Before(oldestExp) {
					oldestKey, oldestExp = k, v.expiresAt
				}
			}
			if oldestKey != "" {
				delete(e.oauthStates, oldestKey)
			}
		}
	}
	e.oauthStates[state] = oauthPKCEState{verifier: verifier, expiresAt: now.Add(oauthStateTTL)}
	e.mu.Unlock()
	return state, verifier, challenge
}

func (e *LedgerEngine) ConsumeOAuthState(state string) (string, bool) {
	e.mu.Lock()
	st, ok := e.oauthStates[state]
	delete(e.oauthStates, state)
	e.mu.Unlock()
	if !ok || e.now().After(st.expiresAt) {
		return "", false
	}
	return st.verifier, true
}

// ======================== 子令牌签发、六种额度核销、周期回血与管理员调额 ========================

// MintSubKey 为门户用户签发新的 sk-qwq-... 子令牌并即时注入内存热缓存。
func (e *LedgerEngine) MintSubKey(ctx context.Context, userID, name string, quotaLimitMicros int64, allowedModels, allowedIPs []string, rpmLimit int, expiresAtMs int64) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plainKey := "sk-qwq-" + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)

	sum := sha256.Sum256([]byte(plainKey))
	keyHash := hex.EncodeToString(sum[:])
	masked := plainKey[:11] + "..." + plainKey[len(plainKey)-4:]
	tokID := randomHexID("tok_", 8)
	if strings.TrimSpace(name) == "" {
		name = "default-key"
	}
	if rpmLimit <= 0 {
		rpmLimit = 60
	}
	if allowedModels == nil {
		allowedModels = make([]string, 0)
	}
	if allowedIPs == nil {
		allowedIPs = make([]string, 0)
	}
	modelsJSON, _ := json.Marshal(allowedModels)
	ipsJSON, _ := json.Marshal(allowedIPs)
	cipherKey, err := EncryptSecret(e.masterKey, []byte(plainKey))
	if err != nil {
		return "", err
	}
	nowMs := e.now().UTC().UnixMilli()

	if _, err := e.db.ExecContext(ctx, `
		INSERT INTO api_tokens (id, user_id, name, key_sha256, key_masked, key_ciphertext, quota_limit_micros,
		                        allowed_models_json, allowed_ips_json, rpm_limit, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		tokID, userID, name, keyHash, masked, cipherKey, quotaLimitMicros,
		string(modelsJSON), string(ipsJSON), rpmLimit, expiresAtMs, nowMs); err != nil {
		return "", err
	}

	e.mu.Lock()
	if u, ok := e.users[userID]; ok {
		e.tokens[keyHash] = buildLiveToken(tokID, name, u, "", quotaLimitMicros, 0, allowedModels, allowedIPs, rpmLimit, expiresAtMs)
	}
	e.mu.Unlock()
	return plainKey, nil
}

// GenerateCodes 批量签发注册邀请码、单用 CDK 或群共享口令码。
func (e *LedgerEngine) GenerateCodes(ctx context.Context, kind, title string, amountMicros int64, count, maxUses int, grantGroup, customCode string, expiresInHours int) ([]string, int64, error) {
	if count < 1 || count > 200 {
		return nil, 0, errors.New("VALIDATION_FAILED: count 必须在 1..200 之间")
	}
	now := e.now().UTC()
	nowMs := now.UnixMilli()
	var expMs int64
	if expiresInHours > 0 {
		expMs = now.Add(time.Duration(expiresInHours) * time.Hour).UnixMilli()
	}

	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	codes := make([]string, 0, count)
	switch kind {
	case "cdk_shared":
		if amountMicros <= 0 {
			return nil, 0, errors.New("VALIDATION_FAILED: 兑换码面额必须大于 0")
		}
		code := strings.TrimSpace(customCode)
		if code == "" {
			code = "GRP-" + strings.ToUpper(randomHexID("", 6))
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO redemption_codes (code, title, amount_micros, max_claims, claimed_count, expires_at, created_at)
			VALUES (?, ?, ?, ?, 0, ?, ?);`,
			code, title, amountMicros, count, expMs, nowMs); err != nil {
			return nil, 0, fmt.Errorf("CONFLICT: 群口令码 %s 已存在: %w", code, err)
		}
		codes = append(codes, code)

	case "cdk_single":
		if amountMicros <= 0 {
			return nil, 0, errors.New("VALIDATION_FAILED: 兑换码面额必须大于 0")
		}
		for idx := 0; idx < count; idx++ {
			code := "CDK-" + strings.ToUpper(randomHexID("", 8))
			if count == 1 && strings.TrimSpace(customCode) != "" {
				code = strings.TrimSpace(customCode)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO redemption_codes (code, title, amount_micros, max_claims, claimed_count, expires_at, created_at)
				VALUES (?, ?, ?, 1, 0, ?, ?);`,
				code, title, amountMicros, expMs, nowMs); err != nil {
				return nil, 0, err
			}
			codes = append(codes, code)
		}

	case "invite":
		if strings.TrimSpace(grantGroup) == "" {
			grantGroup = "default"
		}
		if maxUses < 1 {
			maxUses = 1
		}
		for idx := 0; idx < count; idx++ {
			code := "INV-" + strings.ToUpper(randomHexID("", 6))
			if count == 1 && strings.TrimSpace(customCode) != "" {
				code = strings.TrimSpace(customCode)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO invite_codes (code, grant_group, bonus_micros, max_uses, used_count, expires_at, created_at)
				VALUES (?, ?, ?, ?, 0, ?, ?);`,
				code, grantGroup, amountMicros, maxUses, expMs, nowMs); err != nil {
				return nil, 0, err
			}
			codes = append(codes, code)
		}
	default:
		return nil, 0, fmt.Errorf("VALIDATION_FAILED: unsupported code kind %q", kind)
	}

	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return codes, expMs, nil
}

// RedeemCode 原子核销单用 CDK 或群口令共享码，防并发双花与同用户重复领取。
func (e *LedgerEngine) RedeemCode(ctx context.Context, userID, code string) (grantedMicros int64, newBalance int64, err error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return 0, 0, errors.New("VALIDATION_FAILED: empty redemption code")
	}
	nowMs := e.now().UTC().UnixMilli()

	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var amount int64
	var maxClaims, claimed int
	var expMs int64
	err = tx.QueryRowContext(ctx, `
		SELECT amount_micros, max_claims, claimed_count, expires_at FROM redemption_codes WHERE code = ?;`, code,
	).Scan(&amount, &maxClaims, &claimed, &expMs)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, errors.New("NOT_FOUND: 兑换码不存在")
	}
	if err != nil {
		return 0, 0, err
	}
	if expMs > 0 && nowMs > expMs {
		return 0, 0, errors.New("EXPIRED: 该兑换码已过期")
	}
	if claimed >= maxClaims {
		return 0, 0, errors.New("EXHAUSTED: 该兑换码已被领完")
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO redemption_claims (code, user_id, claimed_at) VALUES (?, ?, ?);`,
		code, userID, nowMs); err != nil {
		return 0, 0, errors.New("ALREADY_CLAIMED: 您已领取过该兑换码")
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE redemption_codes SET claimed_count = claimed_count + 1 WHERE code = ? AND claimed_count < max_claims;`, code)
	if err != nil {
		return 0, 0, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, 0, errors.New("EXHAUSTED: 该兑换码刚刚被领完")
	}

	if err := e.creditUserTx(ctx, tx, userID, "cdk_redeem", amount, "CDK:"+code, nowMs, &newBalance); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	e.addMemoryBalance(userID, amount)
	return amount, newBalance, nil
}

// DailyCheckIn 执行每日签到与防屯号低余额公益水龙头补水（checkin_drip_below_micros）。
func (e *LedgerEngine) DailyCheckIn(ctx context.Context, userID string) (grantedMicros int64, newBalance int64, err error) {
	now := e.now().UTC()
	dayStr := now.Format("2006-01-02")
	nowMs := now.UnixMilli()

	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var enabled int
	var minM, maxM, dripBelow int64
	if err := tx.QueryRowContext(ctx, `
		SELECT checkin_enabled, checkin_min_micros, checkin_max_micros, checkin_drip_below_micros
		FROM portal_settings WHERE id = 1;`,
	).Scan(&enabled, &minM, &maxM, &dripBelow); err != nil {
		return 0, 0, err
	}
	if enabled == 0 {
		return 0, 0, errors.New("DISABLED: 当前未开放每日签到")
	}

	var curBal int64
	if err := tx.QueryRowContext(ctx, `SELECT balance_micros FROM relay_users WHERE id = ?;`, userID).Scan(&curBal); err != nil {
		return 0, 0, err
	}
	if dripBelow > 0 && curBal >= dripBelow {
		return 0, curBal, fmt.Errorf("BALANCE_SUFFICIENT: 当前剩余统计额度充足（仅低于 $%.2f 时开放公益补水）", float64(dripBelow)/float64(MicrosPerDollar))
	}

	grant := minM
	if maxM > minM {
		nBig, _ := rand.Int(rand.Reader, big.NewInt(maxM-minM+1))
		grant = minM + nBig.Int64()
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO checkin_records (user_id, day_utc, granted_micros, created_at) VALUES (?, ?, ?, ?);`,
		userID, dayStr, grant, nowMs); err != nil {
		return 0, curBal, errors.New("ALREADY_CHECKED_IN: 今日已签到，请明日再来")
	}

	if err := e.creditUserTx(ctx, tx, userID, "daily_checkin", grant, "CheckIn:"+dayStr, nowMs, &newBalance); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	e.addMemoryBalance(userID, grant)
	return grant, newBalance, nil
}

// RunPeriodicAutoRefill 执行周期定额回血（日度/月度自动补齐至上限，不叠加膨胀）。
func (e *LedgerEngine) RunPeriodicAutoRefill(ctx context.Context) error {
	now := e.now().UTC()
	dayPeriod := now.Format("2006-01-02")
	monthPeriod := now.Format("2006-01")
	nowMs := now.UnixMilli()

	rows, err := e.db.QueryContext(ctx, `
		SELECT id, balance_micros, auto_refill_cap_micros, auto_refill_cycle, last_refilled_period
		FROM relay_users WHERE status = 'active' AND auto_refill_cap_micros > 0 AND auto_refill_cycle IN ('daily', 'monthly');`)
	if err != nil {
		return err
	}
	type candidate struct {
		id     string
		cur    int64
		capAmt int64
		period string
	}
	var todo []candidate
	for rows.Next() {
		var id, cycle, lastP string
		var cur, capAmt int64
		if err := rows.Scan(&id, &cur, &capAmt, &cycle, &lastP); err != nil {
			continue
		}
		targetP := dayPeriod
		if cycle == "monthly" {
			targetP = monthPeriod
		}
		if lastP != targetP && cur < capAmt {
			todo = append(todo, candidate{id: id, cur: cur, capAmt: capAmt, period: targetP})
		}
	}
	_ = rows.Close()

	for _, c := range todo {
		delta := c.capAmt - c.cur
		tx, err := e.db.BeginTx(ctx, nil)
		if err != nil {
			continue
		}
		var newBal int64
		if err := e.creditUserTx(ctx, tx, c.id, "periodic_refill", delta, "AutoRefill:"+c.period, nowMs, &newBal); err == nil {
			_, _ = tx.ExecContext(ctx, `UPDATE relay_users SET last_refilled_period = ? WHERE id = ?;`, c.period, c.id)
			if tx.Commit() == nil {
				e.addMemoryBalance(c.id, delta)
			}
		} else {
			_ = tx.Rollback()
		}
	}
	return nil
}

// AdjustUserQuota 管理员调整用户统计微点、分组、账号状态及周期回血策略。
func (e *LedgerEngine) AdjustUserQuota(ctx context.Context, userID string, deltaMicros int64, groupName, status string, refillCap *int64, refillCycle, note string) (UserView, error) {
	nowMs := e.now().UTC().UnixMilli()
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return UserView{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var cur UserView
	var emailNull sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT id, username, email, group_name, status, signup_source, balance_micros, used_micros,
		       request_count, auto_refill_cap_micros, auto_refill_cycle, personal_invite_code, created_at, updated_at
		FROM relay_users WHERE id = ?;`, userID,
	).Scan(&cur.ID, &cur.Username, &emailNull, &cur.GroupName, &cur.Status, &cur.SignupSource,
		&cur.BalanceMicros, &cur.UsedMicros, &cur.RequestCount, &cur.AutoRefillCapMicros,
		&cur.AutoRefillCycle, &cur.PersonalInviteCode, &cur.CreatedAt, &cur.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return UserView{}, errors.New("NOT_FOUND: 分发用户不存在")
	}
	if err != nil {
		return UserView{}, err
	}
	cur.Email = emailNull.String

	if strings.TrimSpace(groupName) != "" {
		cur.GroupName = strings.TrimSpace(groupName)
	}
	if status != "" {
		if status != "active" && status != "disabled" {
			return UserView{}, errors.New("VALIDATION_FAILED: invalid status")
		}
		cur.Status = status
	}
	if refillCap != nil {
		if *refillCap < 0 {
			return UserView{}, errors.New("VALIDATION_FAILED: auto_refill_cap_micros cannot be negative")
		}
		cur.AutoRefillCapMicros = *refillCap
	}
	if refillCycle != "" {
		if refillCycle != "none" && refillCycle != "daily" && refillCycle != "monthly" {
			return UserView{}, errors.New("VALIDATION_FAILED: invalid auto_refill_cycle")
		}
		cur.AutoRefillCycle = refillCycle
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE relay_users
		SET group_name = ?, status = ?, auto_refill_cap_micros = ?, auto_refill_cycle = ?, updated_at = ?
		WHERE id = ?;`,
		cur.GroupName, cur.Status, cur.AutoRefillCapMicros, cur.AutoRefillCycle, nowMs, userID); err != nil {
		return UserView{}, err
	}

	if deltaMicros != 0 {
		var after int64
		if err := e.creditUserTx(ctx, tx, userID, "admin_adjust", deltaMicros, note, nowMs, &after); err != nil {
			return UserView{}, err
		}
		cur.BalanceMicros = after
	}
	cur.UpdatedAt = nowMs

	if err := tx.Commit(); err != nil {
		return UserView{}, err
	}

	e.mu.Lock()
	if lu, ok := e.users[userID]; ok {
		lu.GroupName = cur.GroupName
		lu.StatusActive.Store(cur.Status == "active")
		if deltaMicros != 0 {
			ApplyAtomicBalanceDelta(&lu.BalanceMicros, deltaMicros)
		}
	}
	e.mu.Unlock()
	return cur, nil
}

// ======================== 设置、渠道、模型倍率与查询读操作 ========================

func (e *LedgerEngine) GetSettings(ctx context.Context) (PortalSettingsView, error) {
	var out PortalSettingsView
	var allowInv, allowEmail, allowLD, chkEn int
	var emailListJSON, tierJSON string
	var ldSecretEnc, smtpEnc []byte
	if err := e.db.QueryRowContext(ctx, `
		SELECT site_title, site_announcement, allow_invite_signup, allow_email_signup, email_domain_allowlist_json,
		       allow_linuxdo_signup, linuxdo_client_id, linuxdo_client_secret_enc, linuxdo_min_trust_level,
		       linuxdo_tier_rules_json, default_signup_micros, inviter_reward_micros, invitee_reward_micros,
		       max_invite_rewards_per_user, checkin_enabled, checkin_min_micros, checkin_max_micros,
		       checkin_drip_below_micros, smtp_config_enc, updated_at
		FROM portal_settings WHERE id = 1;`,
	).Scan(
		&out.SiteTitle, &out.SiteAnnouncement, &allowInv, &allowEmail, &emailListJSON,
		&allowLD, &out.LinuxDoClientID, &ldSecretEnc, &out.LinuxDoMinTrustLevel,
		&tierJSON, &out.DefaultSignupMicros, &out.InviterRewardMicros, &out.InviteeRewardMicros,
		&out.MaxInviteRewardsPerUser, &chkEn, &out.CheckinMinMicros, &out.CheckinMaxMicros,
		&out.CheckinDripBelowMicros, &smtpEnc, &out.UpdatedAt,
	); err != nil {
		return PortalSettingsView{}, err
	}
	out.AllowInviteSignup = allowInv == 1
	out.AllowEmailSignup = allowEmail == 1
	out.AllowLinuxDoSignup = allowLD == 1
	out.CheckinEnabled = chkEn == 1
	out.LinuxDoClientSecretConfigured = len(ldSecretEnc) > 0
	out.SMTPConfigured = len(smtpEnc) > 0
	out.EmailDomainAllowlist = make([]string, 0)
	_ = json.Unmarshal([]byte(emailListJSON), &out.EmailDomainAllowlist)
	out.LinuxDoTierRules = make(map[string]LinuxDoTierRule)
	_ = json.Unmarshal([]byte(tierJSON), &out.LinuxDoTierRules)
	return out, nil
}

// GetLinuxDoCredentials 返回解密后的 LinuxDo OAuth2 ClientID 与 ClientSecret（仅内部 OAuth 交换使用）。
func (e *LedgerEngine) GetLinuxDoCredentials(ctx context.Context) (clientID, clientSecret string, err error) {
	var enc []byte
	if err := e.db.QueryRowContext(ctx, `SELECT linuxdo_client_id, linuxdo_client_secret_enc FROM portal_settings WHERE id = 1;`).Scan(&clientID, &enc); err != nil {
		return "", "", err
	}
	if len(enc) > 0 {
		plain, err := DecryptSecret(e.masterKey, enc)
		if err != nil {
			return "", "", err
		}
		clientSecret = string(plain)
		clear(plain)
	}
	return clientID, clientSecret, nil
}

func (e *LedgerEngine) UpdateSettings(ctx context.Context, patch SettingsPatch) (PortalSettingsView, error) {
	cur, err := e.GetSettings(ctx)
	if err != nil {
		return PortalSettingsView{}, err
	}
	if patch.SiteTitle != nil {
		cur.SiteTitle = strings.TrimSpace(*patch.SiteTitle)
	}
	if patch.SiteAnnouncement != nil {
		cur.SiteAnnouncement = *patch.SiteAnnouncement
	}
	if patch.AllowInviteSignup != nil {
		cur.AllowInviteSignup = *patch.AllowInviteSignup
	}
	if patch.AllowEmailSignup != nil {
		cur.AllowEmailSignup = *patch.AllowEmailSignup
	}
	if patch.HasEmailDomainAllowlist {
		norm := make([]string, 0, len(patch.EmailDomainAllowlist))
		for _, d := range patch.EmailDomainAllowlist {
			if s := strings.ToLower(strings.TrimSpace(d)); s != "" {
				norm = append(norm, s)
			}
		}
		cur.EmailDomainAllowlist = norm
	}
	if patch.AllowLinuxDoSignup != nil {
		cur.AllowLinuxDoSignup = *patch.AllowLinuxDoSignup
	}
	if patch.LinuxDoClientID != nil {
		cur.LinuxDoClientID = strings.TrimSpace(*patch.LinuxDoClientID)
	}
	if patch.LinuxDoMinTrustLevel != nil {
		cur.LinuxDoMinTrustLevel = *patch.LinuxDoMinTrustLevel
	}
	if len(patch.LinuxDoTierRules) > 0 {
		cur.LinuxDoTierRules = patch.LinuxDoTierRules
	}
	if patch.DefaultSignupMicros != nil {
		cur.DefaultSignupMicros = *patch.DefaultSignupMicros
	}
	if patch.InviterRewardMicros != nil {
		cur.InviterRewardMicros = *patch.InviterRewardMicros
	}
	if patch.InviteeRewardMicros != nil {
		cur.InviteeRewardMicros = *patch.InviteeRewardMicros
	}
	if patch.MaxInviteRewardsPerUser != nil {
		cur.MaxInviteRewardsPerUser = *patch.MaxInviteRewardsPerUser
	}
	if patch.CheckinEnabled != nil {
		cur.CheckinEnabled = *patch.CheckinEnabled
	}
	if patch.CheckinMinMicros != nil {
		cur.CheckinMinMicros = *patch.CheckinMinMicros
	}
	if patch.CheckinMaxMicros != nil {
		cur.CheckinMaxMicros = *patch.CheckinMaxMicros
	}
	if patch.CheckinDripBelowMicros != nil {
		cur.CheckinDripBelowMicros = *patch.CheckinDripBelowMicros
	}

	emailListJSON, _ := json.Marshal(cur.EmailDomainAllowlist)
	tierJSON, _ := json.Marshal(cur.LinuxDoTierRules)
	nowMs := e.now().UTC().UnixMilli()

	if _, err := e.db.ExecContext(ctx, `
		UPDATE portal_settings
		SET site_title = ?, site_announcement = ?, allow_invite_signup = ?, allow_email_signup = ?,
		    email_domain_allowlist_json = ?, allow_linuxdo_signup = ?, linuxdo_client_id = ?,
		    linuxdo_min_trust_level = ?, linuxdo_tier_rules_json = ?, default_signup_micros = ?,
		    inviter_reward_micros = ?, invitee_reward_micros = ?, max_invite_rewards_per_user = ?,
		    checkin_enabled = ?, checkin_min_micros = ?, checkin_max_micros = ?,
		    checkin_drip_below_micros = ?, updated_at = ?
		WHERE id = 1;`,
		cur.SiteTitle, cur.SiteAnnouncement, boolToInt(cur.AllowInviteSignup), boolToInt(cur.AllowEmailSignup),
		string(emailListJSON), boolToInt(cur.AllowLinuxDoSignup), cur.LinuxDoClientID,
		cur.LinuxDoMinTrustLevel, string(tierJSON), cur.DefaultSignupMicros,
		cur.InviterRewardMicros, cur.InviteeRewardMicros, cur.MaxInviteRewardsPerUser,
		boolToInt(cur.CheckinEnabled), cur.CheckinMinMicros, cur.CheckinMaxMicros,
		cur.CheckinDripBelowMicros, nowMs); err != nil {
		return PortalSettingsView{}, err
	}

	if strings.TrimSpace(patch.LinuxDoClientSecret) != "" {
		enc, err := EncryptSecret(e.masterKey, []byte(strings.TrimSpace(patch.LinuxDoClientSecret)))
		if err != nil {
			return PortalSettingsView{}, err
		}
		if _, err := e.db.ExecContext(ctx, `UPDATE portal_settings SET linuxdo_client_secret_enc = ?, updated_at = ? WHERE id = 1;`, enc, nowMs); err != nil {
			return PortalSettingsView{}, err
		}
	}
	if patch.SMTP != nil {
		rawSMTP, _ := json.Marshal(patch.SMTP)
		enc, err := EncryptSecret(e.masterKey, rawSMTP)
		clear(rawSMTP)
		if err != nil {
			return PortalSettingsView{}, err
		}
		if _, err := e.db.ExecContext(ctx, `UPDATE portal_settings SET smtp_config_enc = ?, updated_at = ? WHERE id = 1;`, enc, nowMs); err != nil {
			return PortalSettingsView{}, err
		}
	}
	return e.GetSettings(ctx)
}

func (e *LedgerEngine) UpsertChannel(ctx context.Context, rec ChannelRecord) (ChannelRecord, error) {
	nowMs := e.now().UTC().UnixMilli()
	if len(rec.Groups) == 0 {
		rec.Groups = []string{"default"}
	}
	if rec.Models == nil {
		rec.Models = make([]string, 0)
	}
	if rec.ModelMapping == nil {
		rec.ModelMapping = make(map[string]string)
	}
	if rec.Weight < 1 {
		rec.Weight = 10
	}
	if rec.MaxConcurrent < 1 {
		rec.MaxConcurrent = 16
	}
	groupsJSON, _ := json.Marshal(rec.Groups)
	modelsJSON, _ := json.Marshal(rec.Models)
	mapJSON, _ := json.Marshal(rec.ModelMapping)

	if strings.TrimSpace(rec.ID) == "" {
		if strings.TrimSpace(rec.Credential) == "" {
			return ChannelRecord{}, errors.New("VALIDATION_FAILED: 新建上游渠道必须提供 credential")
		}
		rec.ID = randomHexID("ch_", 8)
		enc, err := EncryptSecret(e.masterKey, []byte(rec.Credential))
		if err != nil {
			return ChannelRecord{}, err
		}
		if _, err := e.db.ExecContext(ctx, `
			INSERT INTO upstream_channels (id, name, kind, base_url, credential_enc, groups_json, models_json,
			                               model_mapping_json, priority, weight, max_concurrent, enabled,
			                               health_state, cooldown_until, last_ttft_ms, last_error, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'healthy', 0, 0, '', ?, ?);`,
			rec.ID, rec.Name, rec.Kind, rec.BaseURL, enc, string(groupsJSON), string(modelsJSON),
			string(mapJSON), rec.Priority, rec.Weight, rec.MaxConcurrent, boolToInt(rec.Enabled), nowMs, nowMs); err != nil {
			return ChannelRecord{}, err
		}
		rec.HealthState = "healthy"
		rec.UpdatedAt = nowMs
		return rec, nil
	}

	if strings.TrimSpace(rec.Credential) != "" {
		enc, err := EncryptSecret(e.masterKey, []byte(rec.Credential))
		if err != nil {
			return ChannelRecord{}, err
		}
		res, err := e.db.ExecContext(ctx, `
			UPDATE upstream_channels
			SET name = ?, kind = ?, base_url = ?, credential_enc = ?, groups_json = ?, models_json = ?,
			    model_mapping_json = ?, priority = ?, weight = ?, max_concurrent = ?, enabled = ?, updated_at = ?
			WHERE id = ?;`,
			rec.Name, rec.Kind, rec.BaseURL, enc, string(groupsJSON), string(modelsJSON),
			string(mapJSON), rec.Priority, rec.Weight, rec.MaxConcurrent, boolToInt(rec.Enabled), nowMs, rec.ID)
		if err != nil {
			return ChannelRecord{}, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ChannelRecord{}, errors.New("NOT_FOUND: 上游渠道不存在")
		}
	} else {
		res, err := e.db.ExecContext(ctx, `
			UPDATE upstream_channels
			SET name = ?, kind = ?, base_url = ?, groups_json = ?, models_json = ?,
			    model_mapping_json = ?, priority = ?, weight = ?, max_concurrent = ?, enabled = ?, updated_at = ?
			WHERE id = ?;`,
			rec.Name, rec.Kind, rec.BaseURL, string(groupsJSON), string(modelsJSON),
			string(mapJSON), rec.Priority, rec.Weight, rec.MaxConcurrent, boolToInt(rec.Enabled), nowMs, rec.ID)
		if err != nil {
			return ChannelRecord{}, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ChannelRecord{}, errors.New("NOT_FOUND: 上游渠道不存在")
		}
	}
	rec.HealthState = "healthy"
	rec.UpdatedAt = nowMs
	return rec, nil
}

func (e *LedgerEngine) ListChannels(ctx context.Context, kindFilter string, limit int, includeSecrets bool) ([]ChannelRecord, error) {
	if limit <= 0 || limit > 256 {
		limit = 100
	}
	var args []any
	q := `SELECT id, name, kind, base_url, credential_enc, groups_json, models_json, model_mapping_json,
	             priority, weight, max_concurrent, enabled, health_state, cooldown_until, last_ttft_ms, last_error, updated_at
	      FROM upstream_channels`
	if strings.TrimSpace(kindFilter) != "" {
		q += " WHERE kind = ?"
		args = append(args, strings.TrimSpace(kindFilter))
	}
	q += " ORDER BY priority DESC, id ASC LIMIT ?"
	args = append(args, limit)

	rows, err := e.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ChannelRecord, 0)
	for rows.Next() {
		var r ChannelRecord
		var credEnc []byte
		var groupsJSON, modelsJSON, mapJSON string
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &r.BaseURL, &credEnc, &groupsJSON, &modelsJSON, &mapJSON,
			&r.Priority, &r.Weight, &r.MaxConcurrent, &en, &r.HealthState, &r.CooldownUntil, &r.LastTTFTMs, &r.LastError, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		r.Groups = make([]string, 0)
		r.Models = make([]string, 0)
		r.ModelMapping = make(map[string]string)
		_ = json.Unmarshal([]byte(groupsJSON), &r.Groups)
		_ = json.Unmarshal([]byte(modelsJSON), &r.Models)
		_ = json.Unmarshal([]byte(mapJSON), &r.ModelMapping)
		if includeSecrets && len(credEnc) > 0 {
			if plain, err := DecryptSecret(e.masterKey, credEnc); err == nil {
				r.Credential = string(plain)
				clear(plain)
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (e *LedgerEngine) UpdateChannelHealth(ctx context.Context, id, healthState string, cooldownUntil, ttftMs int64, lastErr string) error {
	nowMs := e.now().UTC().UnixMilli()
	_, err := e.db.ExecContext(ctx, `
		UPDATE upstream_channels
		SET health_state = ?, cooldown_until = ?, last_ttft_ms = ?, last_error = ?, updated_at = ?
		WHERE id = ?;`, healthState, cooldownUntil, ttftMs, lastErr, nowMs, id)
	return err
}

func (e *LedgerEngine) RemoveChannel(ctx context.Context, id string) (bool, error) {
	res, err := e.db.ExecContext(ctx, `DELETE FROM upstream_channels WHERE id = ?;`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (e *LedgerEngine) UpsertPricing(ctx context.Context, rec PricingRecord) (PricingRecord, error) {
	if rec.BillingMode == "" {
		rec.BillingMode = "token"
	}
	rec.UpdatedAt = e.now().UTC().UnixMilli()
	if _, err := e.db.ExecContext(ctx, `
		INSERT INTO model_pricings (model_name, billing_mode, input_micros_per_1k, output_micros_per_1k,
		                            cache_read_ratio, cache_write_ratio, per_call_micros, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(model_name) DO UPDATE SET
			billing_mode         = excluded.billing_mode,
			input_micros_per_1k  = excluded.input_micros_per_1k,
			output_micros_per_1k = excluded.output_micros_per_1k,
			cache_read_ratio     = excluded.cache_read_ratio,
			cache_write_ratio    = excluded.cache_write_ratio,
			per_call_micros      = excluded.per_call_micros,
			updated_at           = excluded.updated_at;`,
		rec.ModelName, rec.BillingMode, rec.InputMicrosPer1K, rec.OutputMicrosPer1K,
		rec.CacheReadRatio, rec.CacheWriteRatio, rec.PerCallMicros, rec.UpdatedAt); err != nil {
		return PricingRecord{}, err
	}
	return rec, nil
}

func (e *LedgerEngine) ListPricings(ctx context.Context) ([]PricingRecord, error) {
	rows, err := e.db.QueryContext(ctx, `
		SELECT model_name, billing_mode, input_micros_per_1k, output_micros_per_1k,
		       cache_read_ratio, cache_write_ratio, per_call_micros, updated_at
		FROM model_pricings ORDER BY model_name ASC;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PricingRecord, 0)
	for rows.Next() {
		var p PricingRecord
		if err := rows.Scan(&p.ModelName, &p.BillingMode, &p.InputMicrosPer1K, &p.OutputMicrosPer1K,
			&p.CacheReadRatio, &p.CacheWriteRatio, &p.PerCallMicros, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (e *LedgerEngine) ListUsers(ctx context.Context, groupFilter, statusFilter, sourceFilter string, limit int) ([]UserView, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var conds []string
	var args []any
	if groupFilter != "" {
		conds = append(conds, "group_name = ?")
		args = append(args, groupFilter)
	}
	if statusFilter != "" {
		conds = append(conds, "status = ?")
		args = append(args, statusFilter)
	}
	if sourceFilter != "" {
		conds = append(conds, "signup_source = ?")
		args = append(args, sourceFilter)
	}
	q := `SELECT id, username, email, group_name, status, signup_source, balance_micros, used_micros,
	             request_count, auto_refill_cap_micros, auto_refill_cycle, personal_invite_code, created_at, updated_at
	      FROM relay_users`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := e.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]UserView, 0)
	for rows.Next() {
		var u UserView
		var emailNull sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &emailNull, &u.GroupName, &u.Status, &u.SignupSource,
			&u.BalanceMicros, &u.UsedMicros, &u.RequestCount, &u.AutoRefillCapMicros,
			&u.AutoRefillCycle, &u.PersonalInviteCode, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.Email = emailNull.String
		if memBal, memUsed, ok := e.MemoryBalance(u.ID); ok {
			u.BalanceMicros = memBal
			u.UsedMicros = memUsed
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (e *LedgerEngine) GetUserByID(ctx context.Context, userID string) (UserView, error) {
	var u UserView
	var emailNull sql.NullString
	err := e.db.QueryRowContext(ctx, `
		SELECT id, username, email, group_name, status, signup_source, balance_micros, used_micros,
		       request_count, auto_refill_cap_micros, auto_refill_cycle, personal_invite_code, created_at, updated_at
		FROM relay_users WHERE id = ?;`, userID,
	).Scan(&u.ID, &u.Username, &emailNull, &u.GroupName, &u.Status, &u.SignupSource,
		&u.BalanceMicros, &u.UsedMicros, &u.RequestCount, &u.AutoRefillCapMicros,
		&u.AutoRefillCycle, &u.PersonalInviteCode, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return UserView{}, errors.New("NOT_FOUND: user not found")
	}
	if err != nil {
		return UserView{}, err
	}
	u.Email = emailNull.String
	if memBal, memUsed, ok := e.MemoryBalance(u.ID); ok {
		u.BalanceMicros = memBal
		u.UsedMicros = memUsed
	}
	return u, nil
}

func (e *LedgerEngine) ListUserTokens(ctx context.Context, userID string) ([]APITokenView, error) {
	rows, err := e.db.QueryContext(ctx, `
		SELECT id, name, key_masked, key_ciphertext, group_override, status, quota_limit_micros,
		       used_micros, allowed_models_json, allowed_ips_json, rpm_limit, expires_at, last_used_at, created_at
		FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC;`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]APITokenView, 0)
	for rows.Next() {
		var t APITokenView
		var cipherKey []byte
		var modelsJSON, ipsJSON string
		if err := rows.Scan(&t.ID, &t.Name, &t.KeyMasked, &cipherKey, &t.GroupOverride, &t.Status,
			&t.QuotaLimitMicros, &t.UsedMicros, &modelsJSON, &ipsJSON, &t.RPMLimit,
			&t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.AllowedModels = make([]string, 0)
		t.AllowedIPs = make([]string, 0)
		_ = json.Unmarshal([]byte(modelsJSON), &t.AllowedModels)
		_ = json.Unmarshal([]byte(ipsJSON), &t.AllowedIPs)
		if len(cipherKey) > 0 {
			if plain, err := DecryptSecret(e.masterKey, cipherKey); err == nil {
				t.PlainKey = string(plain)
				clear(plain)
			}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (e *LedgerEngine) ListUserRecentLogs(ctx context.Context, userID string, limit int) ([]UsageLogRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := e.db.QueryContext(ctx, `
		SELECT user_id, token_id, token_name, model_name, protocol_in, input_tokens, cached_read_tokens,
		       cache_write_tokens, output_tokens, cost_micros, ttft_ms, duration_ms, created_at
		FROM usage_logs WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?;`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]UsageLogRecord, 0)
	for rows.Next() {
		var l UsageLogRecord
		if err := rows.Scan(&l.UserID, &l.TokenID, &l.TokenName, &l.ModelName, &l.ProtocolIn,
			&l.InputTokens, &l.CachedReadTokens, &l.CacheWriteTokens, &l.OutputTokens,
			&l.CostMicros, &l.TTFTMs, &l.DurationMs, &l.CreatedAtMs); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (e *LedgerEngine) Overview(ctx context.Context, windowHours int) (OverviewStats, error) {
	if windowHours <= 0 {
		windowHours = 24
	}
	var st OverviewStats
	_ = e.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM upstream_channels;`).Scan(&st.TotalChannels)
	_ = e.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM upstream_channels WHERE enabled = 1 AND health_state = 'healthy';`).Scan(&st.HealthyChannels)
	_ = e.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM relay_users;`).Scan(&st.TotalUsers)
	_ = e.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM relay_users WHERE status = 'active';`).Scan(&st.ActiveUsers)
	cutoff := e.now().UTC().Add(-time.Duration(windowHours) * time.Hour).UnixMilli()
	_ = e.db.QueryRowContext(ctx, `
		SELECT COUNT(1), COALESCE(SUM(cost_micros), 0) FROM usage_logs WHERE created_at >= ?;`, cutoff,
	).Scan(&st.WindowRequests, &st.WindowCostMicros)
	return st, nil
}

// PruneOldLogs 清理超过保留天数的调用明细记录。
func (e *LedgerEngine) PruneOldLogs(ctx context.Context, retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cutoff := e.now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour).UnixMilli()
	_, err := e.db.ExecContext(ctx, `DELETE FROM usage_logs WHERE created_at < ?;`, cutoff)
	return err
}

// ======================== 校验与内部辅助函数 ========================

// ValidateEmailAllowed 校验邮箱语法及管理员配置的域名白名单。
func ValidateEmailAllowed(email string, allowlist []string) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 || parts[0] == "" || !strings.Contains(parts[1], ".") {
		return false
	}
	if len(allowlist) == 0 {
		return true
	}
	return slices.Contains(allowlist, parts[1])
}

func (e *LedgerEngine) creditUserTx(ctx context.Context, tx *sql.Tx, userID, source string, delta int64, note string, nowMs int64, afterOut *int64) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE relay_users SET balance_micros = MAX(0, balance_micros + ?), updated_at = ? WHERE id = ?;`,
		delta, nowMs, userID); err != nil {
		return err
	}
	var after int64
	if err := tx.QueryRowContext(ctx, `SELECT balance_micros FROM relay_users WHERE id = ?;`, userID).Scan(&after); err != nil {
		return err
	}
	if afterOut != nil {
		*afterOut = after
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO quota_ledger (user_id, source, delta_micros, balance_after, note, created_at)
		VALUES (?, ?, ?, ?, ?, ?);`, userID, source, delta, after, note, nowMs)
	return err
}

func (e *LedgerEngine) registerMemoryUser(userID, group string, initBalance int64) {
	u := &LiveUserQuota{UserID: userID, GroupName: group}
	u.StatusActive.Store(true)
	u.BalanceMicros.Store(initBalance)
	e.mu.Lock()
	e.users[userID] = u
	e.mu.Unlock()
}

func (e *LedgerEngine) addMemoryBalance(userID string, delta int64) {
	e.mu.RLock()
	u, ok := e.users[userID]
	e.mu.RUnlock()
	if ok {
		ApplyAtomicBalanceDelta(&u.BalanceMicros, delta)
	}
}

func buildLiveToken(id, name string, user *LiveUserQuota, grpOv string, limitM, usedM int64, models, ips []string, rpm int, expMs int64) *LiveAPIToken {
	modSet := make(map[string]struct{}, len(models))
	for _, m := range models {
		if s := strings.TrimSpace(m); s != "" {
			modSet[s] = struct{}{}
		}
	}
	pfxs := make([]netip.Prefix, 0, len(ips))
	for _, ipStr := range ips {
		if p, err := netip.ParsePrefix(strings.TrimSpace(ipStr)); err == nil {
			pfxs = append(pfxs, p.Masked())
		} else if a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(ipStr), "[]")); err == nil {
			a = a.Unmap()
			pfxs = append(pfxs, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	lt := &LiveAPIToken{
		TokenID:          id,
		TokenName:        name,
		User:             user,
		GroupOverride:    grpOv,
		QuotaLimitMicros: limitM,
		AllowedModels:    modSet,
		AllowedPrefixes:  pfxs,
		RPMLimit:         rpm,
		ExpiresAtUnixMs:  expMs,
	}
	lt.UsedMicros.Store(usedM)
	return lt
}

func randomHexID(prefix string, nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func randomBase64Token(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
