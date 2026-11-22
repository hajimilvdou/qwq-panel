-- SPDX-License-Identifier: AGPL-3.0-only
-- The plugin token digest the host channel verifies (PRIV-05, ADR-0013).
--
-- The controller generates a fresh token on every unit install and hands it to
-- the root helper, which stores it as
-- /var/lib/qwq-privileged/creds/<plugin_id>.token for LoadCredential=. Only
-- the hex SHA-256 is kept here: the token itself never reaches the database.
-- One row per plugin, because the unit and the token file are per plugin; a
-- reinstall replaces the row. hostsvc compares every call's token against it.
--
-- No PRAGMA statements: connection settings live in the DSN (see
-- internal/storage).

CREATE TABLE plugin_credentials (
    plugin_id    TEXT NOT NULL PRIMARY KEY,
    token_sha256 TEXT NOT NULL CHECK (length(token_sha256) = 64),
    issued_at    TEXT NOT NULL
) STRICT;
