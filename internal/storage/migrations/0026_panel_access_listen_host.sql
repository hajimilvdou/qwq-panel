-- SPDX-License-Identifier: AGPL-3.0-only
-- Persist live hot-switched listen_host (e.g. 127.0.0.1 <-> 0.0.0.0 / ::) across restarts.

ALTER TABLE panel_access_settings ADD COLUMN listen_host TEXT NOT NULL DEFAULT '';
