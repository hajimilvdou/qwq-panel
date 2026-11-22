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
