-- SPDX-License-Identifier: AGPL-3.0-only
-- Plugin enablement (GAPS gap 7). The flag is per plugin, not per version:
-- disabling a plugin must survive a host restart, an update and a rollback.
-- A plugin without a row is enabled, so an installation that predates this
-- migration keeps running exactly as before.
--
-- revision is the resource.changed sequence of the last write, like every other
-- resource table (ADR-0008 §4).

CREATE TABLE plugin_states (
    plugin_id  TEXT    NOT NULL PRIMARY KEY,
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    updated_at TEXT    NOT NULL,
    revision   INTEGER NOT NULL DEFAULT 0
) STRICT;