-- SPDX-License-Identifier: AGPL-3.0-only
-- containers.docker: 轻量容器与 Compose 编排栈状态库（SQLite STRICT WAL，1C1G 低内存）

CREATE TABLE IF NOT EXISTS compose_stacks (
    name         TEXT PRIMARY KEY,
    compose_yaml TEXT NOT NULL,
    work_dir     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'saved' CHECK (status IN ('saved', 'running', 'stopped', 'error')),
    warnings_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(warnings_json)),
    last_error   TEXT NOT NULL DEFAULT '',
    revision     INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS container_ingress_links (
    id                TEXT PRIMARY KEY,
    container_name    TEXT NOT NULL,
    stack_name        TEXT NOT NULL DEFAULT '',
    service_name      TEXT NOT NULL DEFAULT '',
    container_port    INTEGER NOT NULL CHECK (container_port >= 1 AND container_port <= 65535),
    host_bind_ip      TEXT NOT NULL DEFAULT '127.0.0.1',
    host_port         INTEGER NOT NULL CHECK (host_port >= 1 AND host_port <= 65535),
    upstream_scheme   TEXT NOT NULL DEFAULT 'http' CHECK (upstream_scheme IN ('http', 'https')),
    upstream_insecure INTEGER NOT NULL DEFAULT 0 CHECK (upstream_insecure IN (0, 1)),
    ingress_site_id   TEXT NOT NULL,
    domain            TEXT NOT NULL,
    path_prefix       TEXT NOT NULL DEFAULT '/',
    tls_mode          TEXT NOT NULL DEFAULT 'managed',
    cert_id           TEXT NOT NULL DEFAULT '',
    max_body_mb       INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    UNIQUE (domain, path_prefix)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_cil_container_name ON container_ingress_links(container_name);
