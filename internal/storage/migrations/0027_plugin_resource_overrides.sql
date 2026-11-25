-- SPDX-License-Identifier: AGPL-3.0-only
-- Per-plugin administrator resource limit overrides (memory, CPU, PIDs, FDs, disk).

CREATE TABLE IF NOT EXISTS plugin_resource_overrides (
    plugin_id         TEXT PRIMARY KEY,
    memory_max_mb     INTEGER NOT NULL DEFAULT 0,
    cpu_quota_percent INTEGER NOT NULL DEFAULT 0,
    pids_max          INTEGER NOT NULL DEFAULT 0,
    fds_max           INTEGER NOT NULL DEFAULT 0,
    disk_max_mb       INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT NOT NULL
);
