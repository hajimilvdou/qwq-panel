-- SPDX-License-Identifier: AGPL-3.0-only
-- server.probe 私有 SQLite WAL 数据库结构 (/var/lib/qwq-plugin-data/server.probe/default/probe.db)
-- 开启 WAL + STRICT 表约束，兼顾 1C1G 低写放大与强类型数据完整性。

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

-- 1. 探针纳管服务器节点表（含本机 local 免 Agent 节点与外部单向上报小鸡）
CREATE TABLE IF NOT EXISTS probe_nodes (
    id                      TEXT PRIMARY KEY,               -- 'local' 或 'node_<slug>'
    name                    TEXT NOT NULL,                  -- 展示名称，如 '香港 CN2 GIA · 01'
    region_code             TEXT NOT NULL DEFAULT 'UN',     -- ISO 国旗/地区码，如 'HK', 'JP', 'US', 'SG', 'DE', 'CN'
    group_name              TEXT NOT NULL DEFAULT '默认分组',-- 分组标签，如 '亚太主力', '欧洲落地', '内网存储'
    tags_json               TEXT NOT NULL DEFAULT '[]',     -- 自定义徽章数组，如 '["CN2 GIA","流媒体解锁","1Gbps"]'
    is_local                INTEGER NOT NULL DEFAULT 0 CHECK (is_local IN (0, 1)),
    sort_order              INTEGER NOT NULL DEFAULT 100,
    public_hidden           INTEGER NOT NULL DEFAULT 0 CHECK (public_hidden IN (0, 1)),

    -- 单向安全上报鉴权（仅存 SHA-256 哈希与展示前缀，绝不存明文令牌！）
    agent_token_sha256      TEXT NOT NULL DEFAULT '',
    agent_token_prefix      TEXT NOT NULL DEFAULT '',
    last_report_seq         INTEGER NOT NULL DEFAULT 0,
    report_interval_sec     INTEGER NOT NULL DEFAULT 2 CHECK (report_interval_sec BETWEEN 1 AND 60),

    -- 硬件与静态系统信息（由 Agent 或本机采样自动更新，IP 仅后台可见，访客 DTO 物理剥离）
    os_name                 TEXT NOT NULL DEFAULT '',
    kernel_version          TEXT NOT NULL DEFAULT '',
    arch                    TEXT NOT NULL DEFAULT '',
    virt_type               TEXT NOT NULL DEFAULT 'kvm',
    cpu_model               TEXT NOT NULL DEFAULT '',
    cpu_cores               INTEGER NOT NULL DEFAULT 1,
    mem_total_bytes         INTEGER NOT NULL DEFAULT 0,
    swap_total_bytes        INTEGER NOT NULL DEFAULT 0,
    disk_total_bytes        INTEGER NOT NULL DEFAULT 0,
    ipv4_masked_source      TEXT NOT NULL DEFAULT '',       -- 后台私有记录，对外恒剥离或掩码
    has_ipv4                INTEGER NOT NULL DEFAULT 0 CHECK (has_ipv4 IN (0, 1)),
    has_ipv6                INTEGER NOT NULL DEFAULT 0 CHECK (has_ipv6 IN (0, 1)),

    -- 月度流量配额与 reset_epoch 防丢账累加器（吸收极简探针 & CF 探针核心痛点）
    quota_bytes             INTEGER NOT NULL DEFAULT 0,     -- 0 表示不限流量
    quota_mode              TEXT NOT NULL DEFAULT 'both' CHECK (quota_mode IN ('both', 'max', 'out_only')),
    reset_day               INTEGER NOT NULL DEFAULT 1 CHECK (reset_day BETWEEN 1 AND 31),
    current_period_key      TEXT NOT NULL DEFAULT '',       -- 如 '2026-11'
    period_rx_bytes         INTEGER NOT NULL DEFAULT 0,
    period_tx_bytes         INTEGER NOT NULL DEFAULT 0,
    calibration_bytes       INTEGER NOT NULL DEFAULT 0,     -- 手动校准偏移字节
    last_boot_epoch         INTEGER NOT NULL DEFAULT 0,     -- 检测小鸡重启换代，避免网卡计数器归零产生负数
    last_raw_rx_bytes       INTEGER NOT NULL DEFAULT 0,
    last_raw_tx_bytes       INTEGER NOT NULL DEFAULT 0,

    -- 商家账单与到期提醒（支持对外隐私隐藏开关）
    provider_name           TEXT NOT NULL DEFAULT '',
    billing_price_cents     INTEGER NOT NULL DEFAULT 0,     -- 以分为单位避免浮点误差
    billing_currency        TEXT NOT NULL DEFAULT 'USD',
    billing_cycle           TEXT NOT NULL DEFAULT 'yearly' CHECK (billing_cycle IN ('monthly', 'quarterly', 'semiannually', 'yearly', 'triennial', 'once')),
    expires_at              INTEGER NOT NULL DEFAULT 0,     -- Unix 秒，0 表示长期有效
    admin_note              TEXT NOT NULL DEFAULT '',       -- 仅后台可见私有备注

    last_seen_at            INTEGER NOT NULL DEFAULT 0,
    online_state            TEXT NOT NULL DEFAULT 'pending' CHECK (online_state IN ('pending', 'online', 'offline')),
    revision                TEXT NOT NULL,
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL
) STRICT;

-- 2. 分钟级历史趋势归档表（每 60 秒批量写入 1 次事务，保留 30 天自动环形裁剪）
CREATE TABLE IF NOT EXISTS probe_metric_rollups (
    node_id                 TEXT NOT NULL REFERENCES probe_nodes(id) ON DELETE CASCADE,
    bucket_minute_unix      INTEGER NOT NULL,
    cpu_pct_x100            INTEGER NOT NULL,               -- 0..10000 代表 0.00%..100.00%
    mem_pct_x100            INTEGER NOT NULL,
    disk_pct_x100           INTEGER NOT NULL,
    load1_x100              INTEGER NOT NULL,
    net_rx_bps              INTEGER NOT NULL,
    net_tx_bps              INTEGER NOT NULL,
    tcp_conns               INTEGER NOT NULL DEFAULT 0,
    ping_ct_ms              INTEGER NOT NULL DEFAULT -1,    -- 电信参考延迟 ms（-1 为未测）
    ping_cu_ms              INTEGER NOT NULL DEFAULT -1,    -- 联通参考延迟 ms
    ping_cm_ms              INTEGER NOT NULL DEFAULT -1,    -- 移动参考延迟 ms
    PRIMARY KEY (node_id, bucket_minute_unix)
) STRICT;

-- 3. UptimeFlare 风格 90 天日度在线率状态格归档表（每节点/目标每天仅 1 行）
CREATE TABLE IF NOT EXISTS probe_daily_sla (
    target_kind             TEXT NOT NULL CHECK (target_kind IN ('node', 'service')),
    target_id               TEXT NOT NULL,
    day_utc                 TEXT NOT NULL,                  -- 'YYYY-MM-DD'
    total_checks            INTEGER NOT NULL DEFAULT 0,
    up_checks               INTEGER NOT NULL DEFAULT 0,
    downtime_seconds        INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms          INTEGER NOT NULL DEFAULT 0,
    incident_summary        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (target_kind, target_id, day_utc)
) STRICT;

-- 4. 多目标 TCP / HTTP / HTTPS 服务与三网拨测配置表
CREATE TABLE IF NOT EXISTS probe_service_monitors (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,                  -- 如 '广州电信 163 骨干' 或 '主站 API 健康度'
    kind                    TEXT NOT NULL CHECK (kind IN ('tcp', 'http', 'https', 'icmp_carrier')),
    carrier_tag             TEXT NOT NULL DEFAULT 'global' CHECK (carrier_tag IN ('ct', 'cu', 'cm', 'global', 'custom')),
    target_addr             TEXT NOT NULL,                  -- host:port 或 https://...（经防 SSRF 校验）
    interval_sec            INTEGER NOT NULL DEFAULT 30 CHECK (interval_sec BETWEEN 10 AND 600),
    expected_status_min     INTEGER NOT NULL DEFAULT 200,
    expected_status_max     INTEGER NOT NULL DEFAULT 299,
    public_visible          INTEGER NOT NULL DEFAULT 1 CHECK (public_visible IN (0, 1)),
    enabled                 INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_status             TEXT NOT NULL DEFAULT 'unknown' CHECK (last_status IN ('unknown', 'up', 'degraded', 'down')),
    last_latency_ms         INTEGER NOT NULL DEFAULT 0,
    last_checked_at         INTEGER NOT NULL DEFAULT 0,
    created_at              INTEGER NOT NULL
) STRICT;

-- 5. 防抖告警规则与多渠道通知配置表（Telegram / Bark / Webhook / SMTP）
CREATE TABLE IF NOT EXISTS probe_alert_channels (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    channel_type            TEXT NOT NULL CHECK (channel_type IN ('telegram', 'bark', 'webhook', 'smtp')),
    encrypted_config_b64    TEXT NOT NULL,                  -- AES-256-GCM 密封的 BotToken / Webhook Secret
    offline_grace_sec       INTEGER NOT NULL DEFAULT 45 CHECK (offline_grace_sec BETWEEN 15 AND 1800),
    cpu_threshold_pct       INTEGER NOT NULL DEFAULT 92,
    mem_threshold_pct       INTEGER NOT NULL DEFAULT 92,
    quota_warn_pct          INTEGER NOT NULL DEFAULT 85,
    expiry_warn_days        INTEGER NOT NULL DEFAULT 7,
    enabled                 INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_triggered_at       INTEGER NOT NULL DEFAULT 0,
    created_at              INTEGER NOT NULL
) STRICT;

-- 6. 公开设置、双轨域名绑定与独立探针管理员认证配置表（单行主配置 id = 'default'）
CREATE TABLE IF NOT EXISTS probe_portal_settings (
    id                          TEXT PRIMARY KEY CHECK (id = 'default'),
    site_title                  TEXT NOT NULL DEFAULT 'qwq Probe · 全球节点实时探针',
    site_subtitle               TEXT NOT NULL DEFAULT '单向零入站安全遥测 · 90 天 SLA 与三网延迟实时大盘',
    default_view                TEXT NOT NULL DEFAULT 'orb-cards' CHECK (default_view IN ('orb-cards', 'compact-list', 'tty-terminal')),
    default_palette             TEXT NOT NULL DEFAULT 'oat-berry',
    allow_visitor_theme_switch  INTEGER NOT NULL DEFAULT 1 CHECK (allow_visitor_theme_switch IN (0, 1)),
    mask_node_ip                INTEGER NOT NULL DEFAULT 1 CHECK (mask_node_ip IN (0, 1)),
    expose_billing_cost         INTEGER NOT NULL DEFAULT 1 CHECK (expose_billing_cost IN (0, 1)),
    expose_isp_carrier          INTEGER NOT NULL DEFAULT 1 CHECK (expose_isp_carrier IN (0, 1)),
    visitor_password_hash       TEXT NOT NULL DEFAULT '',   -- 为空则完全公开，非空则启用私有探针访客口令
    status_banner_level         TEXT NOT NULL DEFAULT 'ok' CHECK (status_banner_level IN ('ok', 'maintenance', 'degraded')),
    status_banner_text          TEXT NOT NULL DEFAULT '所有监控节点与拨测链路运行正常',

    -- 独立探针页后台认证（与 qwq 面板宿主会话 100% 物理隔离）
    standalone_admin_user       TEXT NOT NULL DEFAULT 'admin',
    standalone_admin_argon2     TEXT NOT NULL DEFAULT '',
    standalone_totp_secret_b64  TEXT NOT NULL DEFAULT '',

    -- 双轨域名与 TLS 绑定配置（Track A 联动面板 DNC / Track B 探针内置独立闭环）
    domain_enabled              INTEGER NOT NULL DEFAULT 0 CHECK (domain_enabled IN (0, 1)),
    custom_domain               TEXT NOT NULL DEFAULT '',   -- 如 'status.example.com'
    binding_track               TEXT NOT NULL DEFAULT 'auto' CHECK (binding_track IN ('auto', 'panel_dnc', 'builtin_acme', 'builtin_pem', 'reverse_proxy')),
    panel_dns_provider_id       TEXT NOT NULL DEFAULT '',   -- Track A: 借用 domain.dns provider
    panel_dns_zone_id           TEXT NOT NULL DEFAULT '',   -- Track A: 借用 domain.dns zone
    panel_cert_binding_ref      TEXT NOT NULL DEFAULT '',   -- Track A: 借用 tls.certificates certbind_*
    builtin_listen_addr         TEXT NOT NULL DEFAULT '127.0.0.1:8443',
    builtin_acme_email          TEXT NOT NULL DEFAULT '',
    builtin_cert_fingerprint    TEXT NOT NULL DEFAULT '',
    builtin_cert_expires_at     INTEGER NOT NULL DEFAULT 0,
    builtin_encrypted_pem_b64   TEXT NOT NULL DEFAULT '',
    trust_cloudflare_ips        INTEGER NOT NULL DEFAULT 0 CHECK (trust_cloudflare_ips IN (0, 1)),
    trusted_proxies_json        TEXT NOT NULL DEFAULT '["127.0.0.1/32","::1/128"]',

    -- 可插拔前台主题与动态水玻璃外观配置（后台 /admin 永久隔离不受影响）
    active_theme_id             TEXT NOT NULL DEFAULT 'builtin:classic',
    appearance_json             TEXT NOT NULL DEFAULT '{}',
    theme_settings_json         TEXT NOT NULL DEFAULT '{}',

    revision                    TEXT NOT NULL,
    updated_at                  INTEGER NOT NULL
) STRICT;

-- 7. 故障与恢复事件时间线表（展示在公开探针页底部与后台审计）
CREATE TABLE IF NOT EXISTS probe_incidents (
    id                      TEXT PRIMARY KEY,
    node_id                 TEXT NOT NULL DEFAULT '',
    severity                TEXT NOT NULL CHECK (severity IN ('info', 'warn', 'critical', 'resolved')),
    title                   TEXT NOT NULL,
    detail                  TEXT NOT NULL DEFAULT '',
    public_visible          INTEGER NOT NULL DEFAULT 1 CHECK (public_visible IN (0, 1)),
    occurred_at             INTEGER NOT NULL,
    resolved_at             INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX IF NOT EXISTS idx_rollups_time ON probe_metric_rollups(bucket_minute_unix);
CREATE INDEX IF NOT EXISTS idx_incidents_occurred ON probe_incidents(occurred_at DESC);
