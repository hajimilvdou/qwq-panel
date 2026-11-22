-- SPDX-License-Identifier: AGPL-3.0-only
-- 高级代理插件本地 SQLite 严格模式架构（WAL + 外键约束：套餐/用户连接与IP限额/链式代理/TCP Brutal/tcpfit 调优快照）

CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL DEFAULT 0 CHECK (quota_bytes >= 0),
    down_limit_kbps INTEGER NOT NULL DEFAULT 0 CHECK (down_limit_kbps >= 0),
    up_limit_kbps INTEGER NOT NULL DEFAULT 0 CHECK (up_limit_kbps >= 0),
    max_connections INTEGER NOT NULL DEFAULT 0 CHECK (max_connections >= 0 AND max_connections <= 65535),
    max_ips INTEGER NOT NULL DEFAULT 0 CHECK (max_ips >= 0 AND max_ips <= 1024),
    billing_reset_day INTEGER NOT NULL DEFAULT 1 CHECK (billing_reset_day >= 0 AND billing_reset_day <= 28),
    validity_days INTEGER NOT NULL DEFAULT 0 CHECK (validity_days >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE TABLE IF NOT EXISTS proxy_users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
    vless_uuid TEXT NOT NULL,
    hy2_password TEXT NOT NULL,
    ss2022_user_key TEXT NOT NULL,
    traffic_mark INTEGER NOT NULL DEFAULT 0 CHECK (traffic_mark = 0 OR (traffic_mark >= 20736 AND traffic_mark <= 20991)),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended_quota', 'expired', 'disabled')),
    expires_at INTEGER NOT NULL DEFAULT 0 CHECK (expires_at >= 0),
    max_connections_override INTEGER NOT NULL DEFAULT -1 CHECK (max_connections_override >= -1 AND max_connections_override <= 65535),
    max_ips_override INTEGER NOT NULL DEFAULT -1 CHECK (max_ips_override >= -1 AND max_ips_override <= 1024),
    chain_id TEXT NOT NULL DEFAULT '',
    sub_token_sha256 TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_users_mark
    ON proxy_users(traffic_mark)
    WHERE traffic_mark > 0;

CREATE INDEX IF NOT EXISTS idx_proxy_users_status
    ON proxy_users(status);

CREATE TABLE IF NOT EXISTS usage_counters (
    user_id TEXT PRIMARY KEY REFERENCES proxy_users(id) ON DELETE CASCADE,
    period_up_bytes INTEGER NOT NULL DEFAULT 0 CHECK (period_up_bytes >= 0),
    period_down_bytes INTEGER NOT NULL DEFAULT 0 CHECK (period_down_bytes >= 0),
    total_up_bytes INTEGER NOT NULL DEFAULT 0 CHECK (total_up_bytes >= 0),
    total_down_bytes INTEGER NOT NULL DEFAULT 0 CHECK (total_down_bytes >= 0),
    last_xray_epoch TEXT NOT NULL DEFAULT '',
    last_raw_up INTEGER NOT NULL DEFAULT 0 CHECK (last_raw_up >= 0),
    last_raw_down INTEGER NOT NULL DEFAULT 0 CHECK (last_raw_down >= 0),
    period_started_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS usage_hourly_rollups (
    user_id TEXT NOT NULL REFERENCES proxy_users(id) ON DELETE CASCADE,
    bucket_hour_ms INTEGER NOT NULL CHECK (bucket_hour_ms >= 0),
    up_bytes INTEGER NOT NULL DEFAULT 0 CHECK (up_bytes >= 0),
    down_bytes INTEGER NOT NULL DEFAULT 0 CHECK (down_bytes >= 0),
    PRIMARY KEY (user_id, bucket_hour_ms)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_usage_rollups_bucket
    ON usage_hourly_rollups(bucket_hour_ms);

CREATE TABLE IF NOT EXISTS subscription_access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES proxy_users(id) ON DELETE CASCADE,
    accessed_at INTEGER NOT NULL,
    format TEXT NOT NULL,
    ua_summary TEXT NOT NULL,
    status_code INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_sub_logs_user_time
    ON subscription_access_logs(user_id, accessed_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS proxy_chains (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    mode TEXT NOT NULL DEFAULT 'both' CHECK (mode IN ('server_forward', 'client_dialer', 'both')),
    protocol TEXT NOT NULL CHECK (protocol IN ('socks5', 'http', 'vless', 'trojan', 'shadowsocks')),
    server TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    config_enc BLOB NOT NULL,
    config_masked_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_masked_json)),
    next_hop_id TEXT NOT NULL DEFAULT '',
    apply_default INTEGER NOT NULL DEFAULT 0 CHECK (apply_default IN (0, 1)),
    notes TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS brutal_bindings (
    id TEXT PRIMARY KEY,
    inbound_tag TEXT NOT NULL UNIQUE,
    protocol TEXT NOT NULL DEFAULT 'vless' CHECK (protocol IN ('vless', 'shadowsocks', 'trojan', 'tcp')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    listen_port INTEGER NOT NULL CHECK (listen_port >= 0 AND listen_port <= 65535),
    target_port INTEGER NOT NULL CHECK (target_port >= 1 AND target_port <= 65535),
    bandwidth_mbps INTEGER NOT NULL DEFAULT 100 CHECK (bandwidth_mbps >= 1 AND bandwidth_mbps <= 10000),
    oversend_pct INTEGER NOT NULL DEFAULT 125 CHECK (oversend_pct >= 100 AND oversend_pct <= 250),
    cwnd_gain INTEGER NOT NULL DEFAULT 20 CHECK (cwnd_gain >= 10 AND cwnd_gain <= 50),
    enable_in_sub INTEGER NOT NULL DEFAULT 1 CHECK (enable_in_sub IN (0, 1)),
    notes TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS tuning_snapshots (
    id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    reason TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'proxy',
    bandwidth_mbps INTEGER NOT NULL DEFAULT 0,
    rtt_ms INTEGER NOT NULL DEFAULT 0,
    sysctl_json TEXT NOT NULL CHECK (json_valid(sysctl_json)),
    applied INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0, 1)),
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_tuning_snapshots_rev
    ON tuning_snapshots(revision DESC);
