-- SPDX-License-Identifier: AGPL-3.0-only
-- Persistent live panel access & stealth disguise settings (port, secret entry
-- path, disguise mode/HTML, reverse-proxy panel domain). Seeded on first boot
-- from /etc/qwq/qwq.json and mutated live via PUT /api/v1/system/access.

CREATE TABLE IF NOT EXISTS panel_access_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    listen_port INTEGER NOT NULL DEFAULT 0,
    entry_path TEXT NOT NULL DEFAULT '',
    disguise TEXT NOT NULL DEFAULT 'drop',
    disguise_html TEXT NOT NULL DEFAULT '',
    panel_domain TEXT NOT NULL DEFAULT '',
    auto_disable_on_domain INTEGER NOT NULL DEFAULT 1,
    gate_secret TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);
