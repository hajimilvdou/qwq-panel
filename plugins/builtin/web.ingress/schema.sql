-- SPDX-License-Identifier: AGPL-3.0-only
-- web.ingress: 轻量反向代理与站点托管（SQLite STRICT WAL，1C1G 低内存有界快照）

CREATE TABLE IF NOT EXISTS ingress_sites (
    id                 TEXT PRIMARY KEY,
    domain             TEXT NOT NULL,
    enabled            INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    upstream_url       TEXT NOT NULL,
    path_prefix        TEXT NOT NULL DEFAULT '/',
    websocket          INTEGER NOT NULL DEFAULT 1 CHECK (websocket IN (0, 1)),
    tls_mode           TEXT NOT NULL DEFAULT 'managed' CHECK (tls_mode IN ('off', 'managed', 'custom')),
    cert_id            TEXT NOT NULL DEFAULT '',
    force_https        INTEGER NOT NULL DEFAULT 1 CHECK (force_https IN (0, 1)),
    rate_limit_rps     INTEGER NOT NULL DEFAULT 0 CHECK (rate_limit_rps >= 0 AND rate_limit_rps <= 10000),
    rate_limit_burst   INTEGER NOT NULL DEFAULT 0 CHECK (rate_limit_burst >= 0 AND rate_limit_burst <= 20000),
    basic_auth_user    TEXT NOT NULL DEFAULT '',
    basic_auth_hash    TEXT NOT NULL DEFAULT '',
    extra_headers_json    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(extra_headers_json)),
    upstream_tls_insecure INTEGER NOT NULL DEFAULT 0 CHECK (upstream_tls_insecure IN (0, 1)),
    max_body_mb           INTEGER NOT NULL DEFAULT 0 CHECK (max_body_mb >= 0 AND max_body_mb <= 102400),
    notes                 TEXT NOT NULL DEFAULT '',
    revision           INTEGER NOT NULL DEFAULT 1,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    UNIQUE (domain, path_prefix)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_ingress_sites_domain ON ingress_sites(domain);

CREATE TABLE IF NOT EXISTS ingress_snapshots (
    id         TEXT PRIMARY KEY,
    revision   INTEGER NOT NULL,
    reason     TEXT NOT NULL,
    sites_json TEXT NOT NULL CHECK (json_valid(sites_json)),
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_ingress_snapshots_rev ON ingress_snapshots(revision DESC);
