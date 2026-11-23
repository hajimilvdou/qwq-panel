-- SPDX-License-Identifier: AGPL-3.0-only
-- notify.hub: 统一告警与通知中枢（SQLite STRICT WAL，1C1G 低内存有界留存）

CREATE TABLE IF NOT EXISTS notify_channels (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL UNIQUE,
    kind               TEXT NOT NULL CHECK (kind IN ('telegram', 'feishu', 'dingtalk', 'wecom', 'discord', 'smtp', 'webhook')),
    enabled            INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    config_enc         BLOB NOT NULL,
    config_masked_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_masked_json)),
    last_status        TEXT NOT NULL DEFAULT 'unknown',
    last_error         TEXT NOT NULL DEFAULT '',
    last_sent_at       INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS notify_rules (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL UNIQUE,
    enabled               INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    source_pattern        TEXT NOT NULL DEFAULT '*',
    min_severity          TEXT NOT NULL DEFAULT 'warn' CHECK (min_severity IN ('info', 'warn', 'critical')),
    channel_ids_json      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(channel_ids_json)),
    cooldown_sec          INTEGER NOT NULL DEFAULT 300 CHECK (cooldown_sec >= 0 AND cooldown_sec <= 86400),
    quiet_start           TEXT NOT NULL DEFAULT '',
    quiet_end             TEXT NOT NULL DEFAULT '',
    quiet_tz              TEXT NOT NULL DEFAULT 'UTC',
    allow_critical_bypass INTEGER NOT NULL DEFAULT 1 CHECK (allow_critical_bypass IN (0, 1)),
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS notify_deliveries (
    id           TEXT PRIMARY KEY,
    event_id     TEXT NOT NULL,
    source       TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('info', 'warn', 'critical')),
    title        TEXT NOT NULL,
    channel_id   TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('sent', 'failed', 'suppressed_quiet', 'suppressed_cooldown')),
    attempts     INTEGER NOT NULL DEFAULT 1,
    http_status  INTEGER NOT NULL DEFAULT 0,
    error_msg    TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_notify_deliveries_created ON notify_deliveries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notify_deliveries_channel ON notify_deliveries(channel_id, created_at DESC);

CREATE TABLE IF NOT EXISTS notify_cooldowns (
    cool_key TEXT PRIMARY KEY,
    fired_at INTEGER NOT NULL
) STRICT;

