-- SPDX-License-Identifier: AGPL-3.0-only
-- AI API 聚合中转与多源分发门户插件本地 SQLite 12 表严格模式架构（WAL + 外键约束）
-- 纯个人与团体共享虚拟统计额度模型（micros 整数微点：$1.000000 = 1,000,000 micros），零收银台/商城/支付表。

-- 1. 门户全局注册、LinuxDo 信任分级与公益水龙头策略单行配置表
CREATE TABLE IF NOT EXISTS portal_settings (
    id                          INTEGER PRIMARY KEY CHECK (id = 1),
    site_title                  TEXT NOT NULL DEFAULT 'QWQ AI Relay Hub',
    site_announcement           TEXT NOT NULL DEFAULT '仅供内部团队与受邀成员学习研发使用，额度仅作成本统计与防刷配额，不含任何商业收费。',
    allow_invite_signup         INTEGER NOT NULL DEFAULT 1 CHECK (allow_invite_signup IN (0, 1)),
    allow_email_signup          INTEGER NOT NULL DEFAULT 0 CHECK (allow_email_signup IN (0, 1)),
    email_domain_allowlist_json TEXT NOT NULL DEFAULT '[]',
    allow_linuxdo_signup        INTEGER NOT NULL DEFAULT 0 CHECK (allow_linuxdo_signup IN (0, 1)),
    linuxdo_client_id           TEXT NOT NULL DEFAULT '',
    linuxdo_client_secret_enc   BLOB,
    linuxdo_min_trust_level     INTEGER NOT NULL DEFAULT 1 CHECK (linuxdo_min_trust_level BETWEEN 0 AND 4),
    linuxdo_tier_rules_json     TEXT NOT NULL DEFAULT '{"0":{"group":"default","init_micros":1000000,"daily_refill_micros":0},"1":{"group":"default","init_micros":5000000,"daily_refill_micros":2000000},"2":{"group":"standard","init_micros":20000000,"daily_refill_micros":10000000},"3":{"group":"pro","init_micros":50000000,"daily_refill_micros":25000000},"4":{"group":"pro","init_micros":100000000,"daily_refill_micros":50000000}}',
    default_signup_micros       INTEGER NOT NULL DEFAULT 5000000,
    inviter_reward_micros       INTEGER NOT NULL DEFAULT 3000000,
    invitee_reward_micros       INTEGER NOT NULL DEFAULT 2000000,
    max_invite_rewards_per_user INTEGER NOT NULL DEFAULT 20,
    checkin_enabled             INTEGER NOT NULL DEFAULT 1 CHECK (checkin_enabled IN (0, 1)),
    checkin_min_micros          INTEGER NOT NULL DEFAULT 1000000,
    checkin_max_micros          INTEGER NOT NULL DEFAULT 3000000,
    checkin_drip_below_micros   INTEGER NOT NULL DEFAULT 10000000,
    smtp_config_enc             BLOB,
    updated_at                  INTEGER NOT NULL
) STRICT;

-- 2. 分发门户独立用户表（与 VPS 宿主管理员表物理隔离）
CREATE TABLE IF NOT EXISTS relay_users (
    id                      TEXT PRIMARY KEY,
    username                TEXT NOT NULL UNIQUE,
    password_hash           TEXT NOT NULL DEFAULT '',
    email                   TEXT UNIQUE,
    group_name              TEXT NOT NULL DEFAULT 'default',
    status                  TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    signup_source           TEXT NOT NULL CHECK (signup_source IN ('admin', 'invite', 'email', 'linuxdo')),
    invited_by              TEXT REFERENCES relay_users(id),
    invite_reward_count     INTEGER NOT NULL DEFAULT 0,
    balance_micros          INTEGER NOT NULL DEFAULT 0 CHECK (balance_micros >= 0),
    used_micros             INTEGER NOT NULL DEFAULT 0 CHECK (used_micros >= 0),
    request_count           INTEGER NOT NULL DEFAULT 0,
    auto_refill_cap_micros  INTEGER NOT NULL DEFAULT 0 CHECK (auto_refill_cap_micros >= 0),
    auto_refill_cycle       TEXT NOT NULL DEFAULT 'none' CHECK (auto_refill_cycle IN ('none', 'daily', 'monthly')),
    last_refilled_period    TEXT NOT NULL DEFAULT '',
    personal_invite_code    TEXT NOT NULL UNIQUE,
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL
) STRICT;

-- 3. LinuxDo 社区 OAuth 身份绑定表
CREATE TABLE IF NOT EXISTS user_oauth_links (
    provider        TEXT NOT NULL CHECK (provider IN ('linuxdo')),
    external_id     TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES relay_users(id) ON DELETE CASCADE,
    external_login  TEXT NOT NULL,
    trust_level     INTEGER NOT NULL DEFAULT 0,
    last_login_at   INTEGER NOT NULL,
    PRIMARY KEY (provider, external_id)
) STRICT;

-- 4. 邮箱注册验证码短期挑战表
CREATE TABLE IF NOT EXISTS email_verifications (
    email           TEXT PRIMARY KEY,
    code_sha256     TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    expires_at      INTEGER NOT NULL,
    sent_at         INTEGER NOT NULL
) STRICT;

-- 5. 管理员签发的批次注册邀请码表
CREATE TABLE IF NOT EXISTS invite_codes (
    code            TEXT PRIMARY KEY,
    grant_group     TEXT NOT NULL DEFAULT 'default',
    bonus_micros    INTEGER NOT NULL DEFAULT 0,
    max_uses        INTEGER NOT NULL DEFAULT 1,
    used_count      INTEGER NOT NULL DEFAULT 0,
    expires_at      INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
) STRICT;

-- 6. 福利兑换码 / 群口令红包码表
CREATE TABLE IF NOT EXISTS redemption_codes (
    code            TEXT PRIMARY KEY,
    title           TEXT NOT NULL DEFAULT '',
    amount_micros   INTEGER NOT NULL CHECK (amount_micros > 0),
    max_claims      INTEGER NOT NULL DEFAULT 1 CHECK (max_claims >= 1),
    claimed_count   INTEGER NOT NULL DEFAULT 0,
    expires_at      INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS redemption_claims (
    code            TEXT NOT NULL REFERENCES redemption_codes(code) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES relay_users(id) ON DELETE CASCADE,
    claimed_at      INTEGER NOT NULL,
    PRIMARY KEY (code, user_id)
) STRICT;

-- 7. 每日签到记录表（联合主键防并发双签）
CREATE TABLE IF NOT EXISTS checkin_records (
    user_id         TEXT NOT NULL REFERENCES relay_users(id) ON DELETE CASCADE,
    day_utc         TEXT NOT NULL,
    granted_micros  INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (user_id, day_utc)
) STRICT;

-- 8. 不可篡改的虚拟额度来源审计流水表
CREATE TABLE IF NOT EXISTS quota_ledger (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL REFERENCES relay_users(id) ON DELETE CASCADE,
    source          TEXT NOT NULL CHECK (source IN ('signup_gift', 'invite_bonus', 'cdk_redeem', 'daily_checkin', 'periodic_refill', 'admin_adjust')),
    delta_micros    INTEGER NOT NULL,
    balance_after   INTEGER NOT NULL,
    note            TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL
) STRICT;

-- 9. 用户自服务子令牌表（sk-qwq-...）
CREATE TABLE IF NOT EXISTS api_tokens (
    id                      TEXT PRIMARY KEY,
    user_id                 TEXT NOT NULL REFERENCES relay_users(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL,
    key_sha256              TEXT NOT NULL UNIQUE,
    key_masked              TEXT NOT NULL,
    key_ciphertext          BLOB,
    group_override          TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    quota_limit_micros      INTEGER NOT NULL DEFAULT 0,
    used_micros             INTEGER NOT NULL DEFAULT 0,
    allowed_models_json     TEXT NOT NULL DEFAULT '[]',
    allowed_ips_json        TEXT NOT NULL DEFAULT '[]',
    rpm_limit               INTEGER NOT NULL DEFAULT 60,
    expires_at              INTEGER NOT NULL DEFAULT 0,
    last_used_at            INTEGER NOT NULL DEFAULT 0,
    created_at              INTEGER NOT NULL
) STRICT;

-- 10. 上游聚合渠道与 Sub2API OAuth 订阅池表
CREATE TABLE IF NOT EXISTS upstream_channels (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    kind                    TEXT NOT NULL CHECK (kind IN (
                                'openai_compatible',
                                'anthropic_native',
                                'gemini_native',
                                'sub2api_claude_oauth',
                                'sub2api_codex_oauth',
                                'sub2api_gemini_oauth'
                            )),
    base_url                TEXT NOT NULL,
    credential_enc          BLOB NOT NULL,
    groups_json             TEXT NOT NULL DEFAULT '["default"]',
    models_json             TEXT NOT NULL DEFAULT '[]',
    model_mapping_json      TEXT NOT NULL DEFAULT '{}',
    priority                INTEGER NOT NULL DEFAULT 0,
    weight                  INTEGER NOT NULL DEFAULT 10 CHECK (weight >= 1),
    max_concurrent          INTEGER NOT NULL DEFAULT 16,
    enabled                 INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    health_state            TEXT NOT NULL DEFAULT 'healthy' CHECK (health_state IN ('healthy', 'cooling', 'tripped')),
    cooldown_until          INTEGER NOT NULL DEFAULT 0,
    last_ttft_ms            INTEGER NOT NULL DEFAULT 0,
    last_error              TEXT NOT NULL DEFAULT '',
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL
) STRICT;

-- 11. 模型统计倍率表（支持 Prompt Cache 读写差分折扣与按次计费）
CREATE TABLE IF NOT EXISTS model_pricings (
    model_name              TEXT PRIMARY KEY,
    billing_mode            TEXT NOT NULL DEFAULT 'token' CHECK (billing_mode IN ('token', 'per_call')),
    input_micros_per_1k     INTEGER NOT NULL DEFAULT 2000,
    output_micros_per_1k    INTEGER NOT NULL DEFAULT 8000,
    cache_read_ratio        REAL NOT NULL DEFAULT 0.1,
    cache_write_ratio       REAL NOT NULL DEFAULT 1.25,
    per_call_micros         INTEGER NOT NULL DEFAULT 0,
    updated_at              INTEGER NOT NULL
) STRICT;

-- 12. 脱敏调用消费明细表（1 秒微批落盘）
CREATE TABLE IF NOT EXISTS usage_logs (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                 TEXT NOT NULL,
    token_id                TEXT NOT NULL,
    token_name              TEXT NOT NULL,
    model_name              TEXT NOT NULL,
    protocol_in             TEXT NOT NULL,
    input_tokens            INTEGER NOT NULL DEFAULT 0,
    cached_read_tokens      INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens      INTEGER NOT NULL DEFAULT 0,
    output_tokens           INTEGER NOT NULL DEFAULT 0,
    cost_micros             INTEGER NOT NULL DEFAULT 0,
    ttft_ms                 INTEGER NOT NULL DEFAULT 0,
    duration_ms             INTEGER NOT NULL DEFAULT 0,
    created_at              INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_usage_logs_user_time ON usage_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_quota_ledger_user ON quota_ledger (user_id, created_at DESC);
