// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ======================== 测试夹具 ========================

func loadTestSchema(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if err != nil {
		t.Fatalf("读取 schema.sql 失败: %v", err)
	}
	return string(raw)
}

func newTestLedger(t *testing.T, clock *atomic.Pointer[time.Time]) (*LedgerEngine, func()) {
	t.Helper()
	db, masterKey, err := OpenDB(t.TempDir(), loadTestSchema(t))
	if err != nil {
		t.Fatalf("OpenDB 失败: %v", err)
	}
	nowFn := func() time.Time {
		if clock != nil {
			if p := clock.Load(); p != nil {
				return *p
			}
		}
		return time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	}
	eng := NewLedgerEngine(db, masterKey, &http.Client{Timeout: 5 * time.Second}, nowFn)
	if err := eng.LoadFromDB(context.Background()); err != nil {
		_ = eng.Close()
		t.Fatalf("LoadFromDB 失败: %v", err)
	}
	return eng, func() { _ = eng.Close() }
}

func ptr[T any](v T) *T { return &v }

// ======================== 加密与口令哈希测试 ========================

func TestCryptoAndPasswordRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	secret := []byte("sk-upstream-super-secret-value")
	enc, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("EncryptSecret 失败: %v", err)
	}
	dec, err := DecryptSecret(key, enc)
	if err != nil {
		t.Fatalf("DecryptSecret 失败: %v", err)
	}
	if string(dec) != string(secret) {
		t.Fatalf("解密明文不匹配: got %q want %q", dec, secret)
	}
	wrongKey := make([]byte, 32)
	if _, err := DecryptSecret(wrongKey, enc); err == nil {
		t.Fatal("错误密钥应当解密失败")
	}

	if _, err := HashPassword("short"); err == nil {
		t.Fatal("短口令应当被拒绝")
	}
	hash, err := HashPassword("MyStr0ngPass!")
	if err != nil {
		t.Fatalf("HashPassword 失败: %v", err)
	}
	if !VerifyPassword("MyStr0ngPass!", hash) {
		t.Fatal("正确口令校验失败")
	}
	if VerifyPassword("WrongPass123!", hash) {
		t.Fatal("错误口令不应通过校验")
	}
}

// ======================== 100 并发原子扣费守恒与微批零丢账测试 ========================

func TestAtomicQuotaConservation100Goroutines(t *testing.T) {
	ctx := context.Background()
	eng, cleanup := newTestLedger(t, nil)
	defer cleanup()

	stopBatcher := eng.StartBatcher(ctx)

	const initialBalance int64 = 100_000 // $0.10
	user, err := eng.CreateUserByAdmin(ctx, "racer", "RacePass123!", "", "default", initialBalance, 0, "none")
	if err != nil {
		t.Fatalf("创建测试用户失败: %v", err)
	}
	apiKey, err := eng.MintSubKey(ctx, user.ID, "race-key", 0, nil, nil, 1000, 0)
	if err != nil {
		t.Fatalf("签发子令牌失败: %v", err)
	}

	const workers = 100
	var (
		wg           sync.WaitGroup
		startGate    = make(chan struct{})
		totalCharged atomic.Int64
		settledCalls atomic.Int64
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startGate
			tok, resv, err := eng.AuthorizeAndReserve(apiKey, "gpt-4o-mini", "203.0.113.10", 15_000)
			if err != nil {
				return
			}
			// 交替模拟低于预扣（退款路径）与高于预扣（CAS 追加扣费路径）的真实结算。
			actual := int64(7_000)
			if idx%3 == 0 {
				actual = 22_000
			}
			charged := resv.Settle(actual, UsageLogRecord{
				UserID:       tok.User.UserID,
				TokenID:      tok.TokenID,
				TokenName:    tok.TokenName,
				ModelName:    "gpt-4o-mini",
				ProtocolIn:   "openai_chat",
				InputTokens:  120,
				OutputTokens: 45,
			})
			// 二次调用 Settle 必须幂等返回 0。
			if again := resv.Settle(actual, UsageLogRecord{}); again != 0 {
				t.Errorf("重复 Settle 应返回 0，实际 %d", again)
			}
			totalCharged.Add(charged)
			settledCalls.Add(1)
		}(i)
	}

	close(startGate)
	wg.Wait()
	stopBatcher()

	memBal, memUsed, ok := eng.MemoryBalance(user.ID)
	if !ok {
		t.Fatal("内存热账本缺少测试用户")
	}
	charged := totalCharged.Load()
	if memBal < 0 {
		t.Fatalf("内存余额击穿为负数: %d", memBal)
	}
	if charged <= 0 || charged > initialBalance {
		t.Fatalf("累计扣费越界: charged=%d initial=%d", charged, initialBalance)
	}
	if memBal+charged != initialBalance {
		t.Fatalf("额度守恒破坏: memBal(%d) + charged(%d) != initial(%d)", memBal, charged, initialBalance)
	}
	if memUsed != charged {
		t.Fatalf("内存已用统计不一致: memUsed=%d charged=%d", memUsed, charged)
	}

	// 校验微批写库器排空后 SQLite 持久化完全一致（零丢账）。
	var dbBal, dbUsed, dbReqs int64
	if err := eng.db.QueryRowContext(ctx, `SELECT balance_micros, used_micros, request_count FROM relay_users WHERE id = ?;`, user.ID).
		Scan(&dbBal, &dbUsed, &dbReqs); err != nil {
		t.Fatalf("查询 SQLite 用户余额失败: %v", err)
	}
	if dbBal != memBal || dbUsed != charged || dbReqs != settledCalls.Load() {
		t.Fatalf("SQLite 账本与内存不一致: db=(bal=%d, used=%d, reqs=%d) mem=(bal=%d, used=%d, reqs=%d)",
			dbBal, dbUsed, dbReqs, memBal, charged, settledCalls.Load())
	}

	var logCnt, logSum int64
	if err := eng.db.QueryRowContext(ctx, `SELECT COUNT(1), COALESCE(SUM(cost_micros), 0) FROM usage_logs WHERE user_id = ?;`, user.ID).
		Scan(&logCnt, &logSum); err != nil {
		t.Fatalf("查询 usage_logs 失败: %v", err)
	}
	if logCnt != settledCalls.Load() || logSum != charged {
		t.Fatalf("usage_logs 丢账或金额不等: cnt=%d want=%d, sum=%d want=%d", logCnt, settledCalls.Load(), logSum, charged)
	}
}

// ======================== 子令牌配额上限、模型白名单、IP CIDR 与 RPM 限制测试 ========================

func TestSubKeyHardLimitsModelsIPsAndRPM(t *testing.T) {
	ctx := context.Background()
	var clock atomic.Pointer[time.Time]
	baseTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	clock.Store(&baseTime)

	eng, cleanup := newTestLedger(t, &clock)
	defer cleanup()

	user, err := eng.CreateUserByAdmin(ctx, "scoped", "ScopePass123!", "", "default", 5_000_000, 0, "none")
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	exp := baseTime.Add(10 * time.Minute).UnixMilli()
	apiKey, err := eng.MintSubKey(ctx, user.ID, "ci-key", 20_000, []string{"claude-sonnet-4-5"}, []string{"198.51.100.0/24"}, 2, exp)
	if err != nil {
		t.Fatalf("签发受限子令牌失败: %v", err)
	}

	// 模型白名单校验。
	if _, _, err := eng.AuthorizeAndReserve(apiKey, "gpt-4o", "198.51.100.5", 5_000); err == nil || !strings.HasPrefix(err.Error(), "MODEL_NOT_ALLOWED") {
		t.Fatalf("未授权模型应返回 MODEL_NOT_ALLOWED，实际: %v", err)
	}
	// IP 白名单校验。
	if _, _, err := eng.AuthorizeAndReserve(apiKey, "claude-sonnet-4-5", "203.0.113.9", 5_000); err == nil || !strings.HasPrefix(err.Error(), "IP_DENIED") {
		t.Fatalf("未授权 IP 应返回 IP_DENIED，实际: %v", err)
	}

	// 合法调用 2 次消耗全部子令牌额度 20_000 且触发 RPM=2 限制。
	_, r1, err := eng.AuthorizeAndReserve(apiKey, "claude-sonnet-4-5", "198.51.100.8", 10_000)
	if err != nil {
		t.Fatalf("第 1 次合法调用失败: %v", err)
	}
	r1.Settle(10_000, UsageLogRecord{UserID: user.ID, TokenID: r1.token.TokenID, ModelName: "claude-sonnet-4-5", ProtocolIn: "anthropic_messages"})

	_, r2, err := eng.AuthorizeAndReserve(apiKey, "claude-sonnet-4-5", "198.51.100.8", 10_000)
	if err != nil {
		t.Fatalf("第 2 次合法调用失败: %v", err)
	}
	r2.Settle(10_000, UsageLogRecord{UserID: user.ID, TokenID: r2.token.TokenID, ModelName: "claude-sonnet-4-5", ProtocolIn: "anthropic_messages"})

	// 同分钟内第 3 次触发 RPM 限流。
	if _, _, err := eng.AuthorizeAndReserve(apiKey, "claude-sonnet-4-5", "198.51.100.8", 1_000); err == nil || !strings.HasPrefix(err.Error(), "RATE_LIMITED") {
		t.Fatalf("超 RPM 应返回 RATE_LIMITED，实际: %v", err)
	}

	// 推进 1 分钟后 RPM 窗口重置，应命中子令牌额度上限 QUOTA_EXHAUSTED（即使主账号仍有 $4.98）。
	nextMin := baseTime.Add(65 * time.Second)
	clock.Store(&nextMin)
	if _, _, err := eng.AuthorizeAndReserve(apiKey, "claude-sonnet-4-5", "198.51.100.8", 1_000); err == nil || !strings.HasPrefix(err.Error(), "QUOTA_EXHAUSTED") {
		t.Fatalf("子令牌用尽应返回 QUOTA_EXHAUSTED，实际: %v", err)
	}

	// 推进至过期后应返回 TOKEN_EXPIRED。
	expired := baseTime.Add(15 * time.Minute)
	clock.Store(&expired)
	if _, _, err := eng.AuthorizeAndReserve(apiKey, "claude-sonnet-4-5", "198.51.100.8", 1_000); err == nil || !strings.HasPrefix(err.Error(), "TOKEN_EXPIRED") {
		t.Fatalf("过期子令牌应返回 TOKEN_EXPIRED，实际: %v", err)
	}
}

// ======================== 四大注册通道测试 ========================

func TestFourRegistrationModes(t *testing.T) {
	ctx := context.Background()
	eng, cleanup := newTestLedger(t, nil)
	defer cleanup()

	// 1) 管理员直接创建 + 密码认证。
	adminUser, err := eng.CreateUserByAdmin(ctx, "alice", "AlicePass123!", "alice@corp.test", "default", 2_000_000, 0, "none")
	if err != nil {
		t.Fatalf("CreateUserByAdmin 失败: %v", err)
	}
	gotID, err := eng.AuthenticatePassword(ctx, "alice", "AlicePass123!")
	if err != nil || gotID != adminUser.ID {
		t.Fatalf("AuthenticatePassword 失败: id=%q err=%v", gotID, err)
	}
	if _, err := eng.AuthenticatePassword(ctx, "alice", "BadPass999!"); err == nil {
		t.Fatal("错误密码不应登录成功")
	}

	// 开放邀请、邮箱白名单、LinuxDo 三种自助注册通道。
	_, err = eng.UpdateSettings(ctx, SettingsPatch{
		AllowInviteSignup:       ptr(true),
		AllowEmailSignup:        ptr(true),
		EmailDomainAllowlist:    []string{"school.edu.cn", "corp.test"},
		HasEmailDomainAllowlist: true,
		AllowLinuxDoSignup:      ptr(true),
		LinuxDoClientID:         ptr("ld-client-id"),
		LinuxDoClientSecret:     "ld-client-secret",
		LinuxDoMinTrustLevel:    ptr(2),
		DefaultSignupMicros:     ptr(int64(1_000_000)),
		InviterRewardMicros:     ptr(int64(500_000)),
		InviteeRewardMicros:     ptr(int64(250_000)),
		MaxInviteRewardsPerUser: ptr(1),
	})
	if err != nil {
		t.Fatalf("UpdateSettings 失败: %v", err)
	}

	// 2a) 管理员批次邀请码注册（单次有效，分配 pro 分组与附加赠额）。
	invCodes, _, err := eng.GenerateCodes(ctx, "invite", "VIP Batch", 750_000, 1, 1, "pro", "INV-PRO-001", 24)
	if err != nil || len(invCodes) != 1 {
		t.Fatalf("生成邀请码失败: %v", err)
	}
	bobID, err := eng.SignupWithInviteCode(ctx, "bob_inv", "BobPass1234!", invCodes[0])
	if err != nil {
		t.Fatalf("管理员邀请码注册失败: %v", err)
	}
	bob, err := eng.GetUserByID(ctx, bobID)
	if err != nil || bob.GroupName != "pro" || bob.BalanceMicros != 1_750_000 {
		t.Fatalf("邀请码用户状态异常: %+v err=%v", bob, err)
	}
	if _, err := eng.SignupWithInviteCode(ctx, "bob_dup", "BobPass1234!", invCodes[0]); err == nil || !strings.HasPrefix(err.Error(), "INVITE_INVALID") {
		t.Fatalf("用尽的邀请码应拒绝再次注册，实际: %v", err)
	}

	// 2b) 老用户个人邀请码裂变（含奖励上限 MaxInviteRewardsPerUser=1 验证）。
	charlieID, err := eng.SignupWithInviteCode(ctx, "charlie", "CharPass123!", adminUser.PersonalInviteCode)
	if err != nil {
		t.Fatalf("个人邀请码第 1 次注册失败: %v", err)
	}
	charlie, _ := eng.GetUserByID(ctx, charlieID)
	if charlie.BalanceMicros != 1_250_000 {
		t.Fatalf("被邀请人应获得 default+invitee=1_250_000，实际 %d", charlie.BalanceMicros)
	}
	aliceAfter1, _ := eng.GetUserByID(ctx, adminUser.ID)
	if aliceAfter1.BalanceMicros != 2_500_000 {
		t.Fatalf("邀请人首次奖励后余额应为 2_500_000，实际 %d", aliceAfter1.BalanceMicros)
	}
	// 第 2 次邀请达到上限，仍允许注册但邀请人不再额外获利。
	if _, err := eng.SignupWithInviteCode(ctx, "dave", "DavePass123!", adminUser.PersonalInviteCode); err != nil {
		t.Fatalf("达奖励上限后仍应允许注册: %v", err)
	}
	aliceAfter2, _ := eng.GetUserByID(ctx, adminUser.ID)
	if aliceAfter2.BalanceMicros != 2_500_000 {
		t.Fatalf("超上限不应继续向邀请人发奖: got %d want 2_500_000", aliceAfter2.BalanceMicros)
	}

	// 3) 邮箱域名白名单 + 6 位 OTP 注册。
	if _, err := eng.SendEmailOTP(ctx, "intruder@blocked.xyz"); err == nil || !strings.HasPrefix(err.Error(), "EMAIL_DOMAIN_DENIED") {
		t.Fatalf("非白名单域名应被拒绝，实际: %v", err)
	}
	otp, err := eng.SendEmailOTP(ctx, "student@school.edu.cn")
	if err != nil || len(otp) != 6 {
		t.Fatalf("SendEmailOTP 失败: otp=%q err=%v", otp, err)
	}
	if _, err := eng.SignupWithEmailOTP(ctx, "eve", "EvePass1234!", "student@school.edu.cn", "000000"); err == nil || !strings.HasPrefix(err.Error(), "OTP_INVALID") {
		t.Fatalf("错误 OTP 应返回 OTP_INVALID，实际: %v", err)
	}
	eveID, err := eng.SignupWithEmailOTP(ctx, "eve", "EvePass1234!", "student@school.edu.cn", otp)
	if err != nil {
		t.Fatalf("正确 OTP 注册失败: %v", err)
	}
	eve, _ := eng.GetUserByID(ctx, eveID)
	if eve.SignupSource != "email" || eve.BalanceMicros != 1_000_000 {
		t.Fatalf("邮箱注册用户状态异常: %+v", eve)
	}

	// 4) LinuxDo OAuth2 + PKCE 信任分级映射与风控测试。
	var profileMu sync.Mutex
	curProfile := LinuxDoUserProfile{}
	ldServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			if err := r.ParseForm(); err != nil || r.FormValue("code_verifier") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "ld-access-tok"})
		case "/api/user":
			profileMu.Lock()
			p := curProfile
			profileMu.Unlock()
			_ = json.NewEncoder(w).Encode(p)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ldServer.Close()
	eng.SetLinuxDoBaseURL(ldServer.URL)

	// 禁言账号必须拒绝。
	profileMu.Lock()
	curProfile = LinuxDoUserProfile{ID: "9001", Username: "muted", TrustLevel: 3, Active: true, Silenced: true}
	profileMu.Unlock()
	if _, _, _, err := eng.LoginOrSignupWithLinuxDo(ctx, "ld-client-id", "ld-client-secret", "http://cb", "c1", "verifier1"); err == nil || !strings.HasPrefix(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("禁言 LinuxDo 账号应返回 PERMISSION_DENIED，实际: %v", err)
	}

	// TL1 < minTL(2) 必须拒绝。
	profileMu.Lock()
	curProfile = LinuxDoUserProfile{ID: "9002", Username: "newbie", TrustLevel: 1, Active: true, Silenced: false}
	profileMu.Unlock()
	if _, _, _, err := eng.LoginOrSignupWithLinuxDo(ctx, "ld-client-id", "ld-client-secret", "http://cb", "c2", "verifier2"); err == nil || !strings.HasPrefix(err.Error(), "TRUST_LEVEL_TOO_LOW") {
		t.Fatalf("低信任等级应返回 TRUST_LEVEL_TOO_LOW，实际: %v", err)
	}

	// TL3 映射至 pro 分组 + 50_000_000 初始微点 + 25_000_000 日度自动回血（对齐 schema.sql 默认规则）。
	profileMu.Lock()
	curProfile = LinuxDoUserProfile{ID: "9003", Username: "veteran", TrustLevel: 3, Active: true, Silenced: false}
	profileMu.Unlock()
	ldUID, ldUname, isNew, err := eng.LoginOrSignupWithLinuxDo(ctx, "ld-client-id", "ld-client-secret", "http://cb", "c3", "verifier3")
	if err != nil || !isNew || ldUname != "ld_veteran" {
		t.Fatalf("TL3 首次登录失败: uid=%q uname=%q isNew=%v err=%v", ldUID, ldUname, isNew, err)
	}
	ldUser, _ := eng.GetUserByID(ctx, ldUID)
	if ldUser.GroupName != "pro" || ldUser.BalanceMicros != 50_000_000 || ldUser.AutoRefillCapMicros != 25_000_000 || ldUser.AutoRefillCycle != "daily" {
		t.Fatalf("TL3 信任等级映射不符合默认规则: %+v", ldUser)
	}

	// 同一外部 ID 再次登录不新建账号。
	ldUID2, _, isNew2, err := eng.LoginOrSignupWithLinuxDo(ctx, "ld-client-id", "ld-client-secret", "http://cb", "c4", "verifier4")
	if err != nil || isNew2 || ldUID2 != ldUID {
		t.Fatalf("重复登录应复用已有账号: uid2=%q isNew2=%v err=%v", ldUID2, isNew2, err)
	}
}

// ======================== 六种虚拟统计额度与防屯号签到测试 ========================

func TestSixQuotaSourcesAndAntiHoarding(t *testing.T) {
	ctx := context.Background()
	var clock atomic.Pointer[time.Time]
	day1 := time.Date(2026, 6, 15, 8, 0, 0, 0, time.UTC)
	clock.Store(&day1)

	eng, cleanup := newTestLedger(t, &clock)
	defer cleanup()

	_, err := eng.UpdateSettings(ctx, SettingsPatch{
		CheckinEnabled:         ptr(true),
		CheckinMinMicros:       ptr(int64(300_000)),
		CheckinMaxMicros:       ptr(int64(300_000)),
		CheckinDripBelowMicros: ptr(int64(1_000_000)), // 余额 >= $1.00 时防屯号拦截
	})
	if err != nil {
		t.Fatalf("更新签到策略失败: %v", err)
	}

	uA, err := eng.CreateUserByAdmin(ctx, "user_a", "UserAPass123!", "", "default", 1_500_000, 3_000_000, "daily")
	if err != nil {
		t.Fatalf("创建 uA 失败: %v", err)
	}
	uB, err := eng.CreateUserByAdmin(ctx, "user_b", "UserBPass123!", "", "default", 500_000, 0, "none")
	if err != nil {
		t.Fatalf("创建 uB 失败: %v", err)
	}
	uC, err := eng.CreateUserByAdmin(ctx, "user_c", "UserCPass123!", "", "default", 500_000, 0, "none")
	if err != nil {
		t.Fatalf("创建 uC 失败: %v", err)
	}

	// 1) 防屯号每日签到水龙头：uA ($1.50 >= $1.00) 应被拦截，uB ($0.50 < $1.00) 应成功且当日不可重复签到。
	if _, _, err := eng.DailyCheckIn(ctx, uA.ID); err == nil || !strings.HasPrefix(err.Error(), "BALANCE_SUFFICIENT") {
		t.Fatalf("高余额用户应命中防屯号拦截 BALANCE_SUFFICIENT，实际: %v", err)
	}
	granted, balB, err := eng.DailyCheckIn(ctx, uB.ID)
	if err != nil || granted != 300_000 || balB != 800_000 {
		t.Fatalf("uB 签到结果异常: granted=%d bal=%d err=%v", granted, balB, err)
	}
	if _, _, err := eng.DailyCheckIn(ctx, uB.ID); err == nil || !strings.HasPrefix(err.Error(), "ALREADY_CHECKED_IN") {
		t.Fatalf("当日重复签到应返回 ALREADY_CHECKED_IN，实际: %v", err)
	}

	// 2) 单用 CDK 与群共享口令码核销防双花。
	singleCodes, _, err := eng.GenerateCodes(ctx, "cdk_single", "Single Gift", 400_000, 1, 1, "", "CDK-ONE-1", 24)
	if err != nil {
		t.Fatalf("生成单用 CDK 失败: %v", err)
	}
	if _, _, err := eng.RedeemCode(ctx, uB.ID, singleCodes[0]); err != nil {
		t.Fatalf("uB 核销单用 CDK 失败: %v", err)
	}
	if _, _, err := eng.RedeemCode(ctx, uC.ID, singleCodes[0]); err == nil || !strings.HasPrefix(err.Error(), "EXHAUSTED") {
		t.Fatalf("单用 CDK 第二次核销应返回 EXHAUSTED，实际: %v", err)
	}

	sharedCodes, _, err := eng.GenerateCodes(ctx, "cdk_shared", "Group Drop", 250_000, 2, 0, "", "GRP-LINUXDO", 24)
	if err != nil {
		t.Fatalf("生成群口令码失败: %v", err)
	}
	if _, _, err := eng.RedeemCode(ctx, uA.ID, sharedCodes[0]); err != nil {
		t.Fatalf("uA 领取群口令码失败: %v", err)
	}
	if _, _, err := eng.RedeemCode(ctx, uA.ID, sharedCodes[0]); err == nil || !strings.HasPrefix(err.Error(), "ALREADY_CLAIMED") {
		t.Fatalf("同用户重复领群口令码应返回 ALREADY_CLAIMED，实际: %v", err)
	}
	if _, _, err := eng.RedeemCode(ctx, uB.ID, sharedCodes[0]); err != nil {
		t.Fatalf("uB 领取群口令码失败: %v", err)
	}
	if _, _, err := eng.RedeemCode(ctx, uC.ID, sharedCodes[0]); err == nil || !strings.HasPrefix(err.Error(), "EXHAUSTED") {
		t.Fatalf("名额用尽的群口令码应返回 EXHAUSTED，实际: %v", err)
	}

	// 3) 周期自动回血（补齐至上限 3_000_000，且同周期再次执行不叠加）。
	if err := eng.RunPeriodicAutoRefill(ctx); err != nil {
		t.Fatalf("RunPeriodicAutoRefill 失败: %v", err)
	}
	aAfterRefill, _ := eng.GetUserByID(ctx, uA.ID)
	if aAfterRefill.BalanceMicros != 3_000_000 {
		t.Fatalf("日度回血应精确补齐至上限 3_000_000，实际 %d", aAfterRefill.BalanceMicros)
	}
	if err := eng.RunPeriodicAutoRefill(ctx); err != nil {
		t.Fatalf("同日二次 RunPeriodicAutoRefill 失败: %v", err)
	}
	aAfterRefill2, _ := eng.GetUserByID(ctx, uA.ID)
	if aAfterRefill2.BalanceMicros != 3_000_000 {
		t.Fatalf("同日二次回血不应叠加膨胀，实际 %d", aAfterRefill2.BalanceMicros)
	}

	// 4) 管理员调额与停用即时生效。
	keyA, err := eng.MintSubKey(ctx, uA.ID, "a-key", 0, nil, nil, 60, 0)
	if err != nil {
		t.Fatalf("签发 uA 密钥失败: %v", err)
	}
	adj, err := eng.AdjustUserQuota(ctx, uA.ID, 500_000, "vip", "disabled", nil, "", "manual adjust")
	if err != nil || adj.BalanceMicros != 3_500_000 || adj.GroupName != "vip" || adj.Status != "disabled" {
		t.Fatalf("AdjustUserQuota 结果异常: %+v err=%v", adj, err)
	}
	if _, _, err := eng.AuthorizeAndReserve(keyA, "gpt-4o", "1.1.1.1", 1_000); err == nil || !strings.HasPrefix(err.Error(), "USER_DISABLED") {
		t.Fatalf("已停用用户密钥应被热路径立即拒绝，实际: %v", err)
	}

	// 5) 推进至次日，验证低余额用户 uC 可以正常签到。
	day2 := day1.Add(24 * time.Hour)
	clock.Store(&day2)
	if g2, _, err := eng.DailyCheckIn(ctx, uC.ID); err != nil || g2 != 300_000 {
		t.Fatalf("次日低余额用户签到失败: g2=%d err=%v", g2, err)
	}
}

func TestDisabledUserRejectedAndSMTPMetadataBlocked(t *testing.T) {
	ctx := context.Background()
	eng, cleanup := newTestLedger(t, nil)
	defer cleanup()

	_, err := eng.UpdateSettings(ctx, SettingsPatch{
		AllowLinuxDoSignup:     ptr(true),
		LinuxDoMinTrustLevel:   ptr(0),
		CheckinEnabled:         ptr(true),
		CheckinMinMicros:       ptr(int64(100_000)),
		CheckinMaxMicros:       ptr(int64(100_000)),
		CheckinDripBelowMicros: ptr(int64(0)),
	})
	if err != nil {
		t.Fatalf("UpdateSettings 失败: %v", err)
	}

	ldSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-disabled-check"})
		case "/api/user":
			_ = json.NewEncoder(w).Encode(LinuxDoUserProfile{ID: json.Number("900123"), Username: "banned_ld", TrustLevel: 2, Active: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ldSrv.Close()
	eng.SetLinuxDoBaseURL(ldSrv.URL)

	uid, _, _, err := eng.LoginOrSignupWithLinuxDo(ctx, "cid", "csec", "http://cb", "code1", "ver1")
	if err != nil {
		t.Fatalf("首次 LinuxDo 注册失败: %v", err)
	}
	codes, _, err := eng.GenerateCodes(ctx, "cdk_single", "Gift", 100_000, 1, 1, "", "CDK-BAN-CHECK", 24)
	if err != nil || len(codes) != 1 {
		t.Fatalf("生成兑换码失败: %v", err)
	}

	// 封禁该账号后，DailyCheckIn / RedeemCode / LinuxDo 二次登录必须全部返回 USER_DISABLED。
	if _, err := eng.AdjustUserQuota(ctx, uid, 0, "", "disabled", nil, "", "ban user"); err != nil {
		t.Fatalf("封禁用户失败: %v", err)
	}
	if _, _, err := eng.DailyCheckIn(ctx, uid); err == nil || !strings.HasPrefix(err.Error(), "USER_DISABLED") {
		t.Fatalf("封禁用户 DailyCheckIn 应返回 USER_DISABLED，实际: %v", err)
	}
	if _, _, err := eng.RedeemCode(ctx, uid, codes[0]); err == nil || !strings.HasPrefix(err.Error(), "USER_DISABLED") {
		t.Fatalf("封禁用户 RedeemCode 应返回 USER_DISABLED，实际: %v", err)
	}
	if _, _, _, err := eng.LoginOrSignupWithLinuxDo(ctx, "cid", "csec", "http://cb", "code2", "ver2"); err == nil || !strings.HasPrefix(err.Error(), "USER_DISABLED") {
		t.Fatalf("封禁用户 LinuxDo 登录应返回 USER_DISABLED，实际: %v", err)
	}

	// SMTP 元数据及隧道地址硬拦截验证（AWS/GCP 169.254.169.254、阿里云 100.100.100.200、metadata.google.internal、0.0.0.0、NAT64、6to4、Teredo）。
	for _, badHost := range []string{
		"169.254.169.254",
		"100.100.100.200",
		"0.0.0.0",
		"fd00:ec2::254",
		"64:ff9b::169.254.169.254",
		"2002:a9fe:a9fe::1",
		"2001:0:4136:e378::1",
		"metadata.google.internal",
	} {
		err := SendVerificationEmailBounded(ctx, RelaySMTPConfig{
			Host: badHost,
			Port: 587,
			From: "noreply@example.com",
		}, "user@example.com", "Test", "123456")
		if err == nil || !strings.Contains(err.Error(), "SSRF_BLOCKED") {
			t.Fatalf("SMTP 主机 %s 应命中 SSRF_BLOCKED，实际: %v", badHost, err)
		}
	}
}

func TestAuthorizeAndReserveRejectsInsufficientBalanceAndSubKey(t *testing.T) {
	ctx := context.Background()
	eng, cleanup := newTestLedger(t, nil)
	defer cleanup()

	// 1. 仅剩 1 micro 的账号不能以 50_000 micros 预扣放行
	poorUser, err := eng.CreateUserByAdmin(ctx, "poor_user", "PoorPass123!", "", "default", 1, 0, "none")
	if err != nil {
		t.Fatalf("CreateUserByAdmin 失败: %v", err)
	}
	poorKey, err := eng.MintSubKey(ctx, poorUser.ID, "poor-key", 0, nil, nil, 60, 0)
	if err != nil {
		t.Fatalf("MintSubKey 失败: %v", err)
	}
	if _, _, err := eng.AuthorizeAndReserve(poorKey, "gpt-4o", "198.51.100.1", 50_000); err == nil || !errors.Is(err, ErrQuotaExhausted) || !strings.HasPrefix(err.Error(), "QUOTA_EXHAUSTED") {
		t.Fatalf("余额 1 micro 申请预扣 50000 应返回 ErrQuotaExhausted，实际: %v", err)
	}
	if bal, _, ok := eng.MemoryBalance(poorUser.ID); !ok || bal != 1 {
		t.Fatalf("拒绝预扣后余额应保持 1 micro，实际 bal=%d ok=%v", bal, ok)
	}

	// 2. 主账号充裕但子令牌限额 10_000 小于本次预扣 50_000，同样必须拒绝
	richUser, err := eng.CreateUserByAdmin(ctx, "rich_user", "RichPass123!", "", "default", 5_000_000, 0, "none")
	if err != nil {
		t.Fatalf("CreateUserByAdmin 失败: %v", err)
	}
	cappedKey, err := eng.MintSubKey(ctx, richUser.ID, "capped-key", 10_000, nil, nil, 60, 0)
	if err != nil {
		t.Fatalf("MintSubKey 失败: %v", err)
	}
	if _, _, err := eng.AuthorizeAndReserve(cappedKey, "gpt-4o", "198.51.100.1", 50_000); err == nil || !errors.Is(err, ErrQuotaExhausted) || !strings.HasPrefix(err.Error(), "QUOTA_EXHAUSTED") {
		t.Fatalf("子令牌剩余 10000 申请预扣 50000 应返回 ErrQuotaExhausted，实际: %v", err)
	}
}

func TestDisabledUserSessionInvalidatedAndEvicted(t *testing.T) {
	ctx := context.Background()
	eng, cleanup := newTestLedger(t, nil)
	defer cleanup()

	u, err := eng.CreateUserByAdmin(ctx, "sess_user", "SessPass123!", "", "default", 1_000_000, 0, "none")
	if err != nil {
		t.Fatalf("CreateUserByAdmin 失败: %v", err)
	}
	sess := eng.CreateSession(u.ID)
	if gotUID, ok := eng.ValidateSession(sess); !ok || gotUID != u.ID {
		t.Fatalf("活跃用户会话校验失败: uid=%q ok=%v", gotUID, ok)
	}

	// 管理员停用用户后，既有门户会话应被立即驱逐且校验失败
	if _, err := eng.AdjustUserQuota(ctx, u.ID, 0, "", "disabled", nil, "", "disable account"); err != nil {
		t.Fatalf("AdjustUserQuota 停用失败: %v", err)
	}
	if gotUID, ok := eng.ValidateSession(sess); ok || gotUID != "" {
		t.Fatalf("停用用户的既有会话必须失效，实际 uid=%q ok=%v", gotUID, ok)
	}

	// 即使存在未驱逐会话，ValidateSession 检查 StatusActive 也必须拒绝
	staleSess := eng.CreateSession(u.ID)
	if gotUID, ok := eng.ValidateSession(staleSess); ok || gotUID != "" {
		t.Fatalf("停用用户的会话不应通过 ValidateSession，实际 uid=%q ok=%v", gotUID, ok)
	}
}

func TestConcurrentAdjustUserQuotaAndEffectiveGroupRaceFree(t *testing.T) {
	ctx := context.Background()
	eng, cleanup := newTestLedger(t, nil)
	defer cleanup()

	u, err := eng.CreateUserByAdmin(ctx, "race_grp", "RaceGrp123!", "", "default", 10_000_000, 0, "none")
	if err != nil {
		t.Fatalf("CreateUserByAdmin 失败: %v", err)
	}
	key, err := eng.MintSubKey(ctx, u.ID, "race-grp-key", 0, nil, nil, 0, 0)
	if err != nil {
		t.Fatalf("MintSubKey 失败: %v", err)
	}

	var wg sync.WaitGroup
	groups := []string{"default", "pro", "vip"}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for idx := 0; idx < 30; idx++ {
			_, _ = eng.AdjustUserQuota(ctx, u.ID, 0, groups[idx%len(groups)], "", nil, "", "rotate")
		}
	}()
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := 0; idx < 100; idx++ {
				tok, resv, err := eng.AuthorizeAndReserve(key, "gpt-4o", "198.51.100.1", 1_000)
				if err != nil {
					continue
				}
				grp := tok.EffectiveGroup()
				if grp != "default" && grp != "pro" && grp != "vip" {
					t.Errorf("unexpected group %q", grp)
				}
				resv.Settle(0, UsageLogRecord{})
			}
		}()
	}
	wg.Wait()
}

func TestSubKeyExtraSettlementCannotOverdraftParentBalance(t *testing.T) {
	ctx := context.Background()
	eng, cleanup := newTestLedger(t, nil)
	defer cleanup()

	// Parent has $100, sub-key hard limit is $0.10 (100_000 micros).
	u, err := eng.CreateUserByAdmin(ctx, "subcap_owner", "SubCapPass123!", "", "default", 100_000_000, 0, "none")
	if err != nil {
		t.Fatalf("CreateUserByAdmin: %v", err)
	}
	subKey, err := eng.MintSubKey(ctx, u.ID, "capped-key", 100_000, nil, nil, 1000, 0)
	if err != nil {
		t.Fatalf("MintSubKey: %v", err)
	}

	// 10 concurrent reservations of 10_000 each (total reserved = 100_000),
	// acquired first so all 10 are simultaneously in-flight, then settled concurrently at 500_000 actual!
	resvs := make([]*QuotaReservation, 0, 10)
	for i := 0; i < 10; i++ {
		_, resv, err := eng.AuthorizeAndReserve(subKey, "gpt-4o", "198.51.100.1", 10_000)
		if err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
		resvs = append(resvs, resv)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var totalCharged atomic.Int64
	for _, resv := range resvs {
		wg.Add(1)
		go func(r *QuotaReservation) {
			defer wg.Done()
			<-start
			c := r.Settle(500_000, UsageLogRecord{UserID: u.ID, TokenID: r.token.TokenID, ModelName: "gpt-4o", ProtocolIn: "openai_chat"})
			totalCharged.Add(c)
		}(resv)
	}
	close(start)
	wg.Wait()

	if got := totalCharged.Load(); got > 100_000 {
		t.Fatalf("sub-key overdrew parent balance past hard limit: charged=%d limit=100000", got)
	}
	memBal, _, _ := eng.MemoryBalance(u.ID)
	if memBal < 100_000_000-100_000 {
		t.Fatalf("parent balance dropped past sub-key hard limit: balance=%d", memBal)
	}
}
