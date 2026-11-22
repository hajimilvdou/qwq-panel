-- SPDX-License-Identifier: AGPL-3.0-only
-- Authorization (P1-T4, ADR-0004 D4): delegations for AI operators and service
-- accounts for automation. Both store only the SHA-256 of their bearer token
-- plus a short recognisable prefix for leak scanning. The effective permission of
-- a delegation is recomputed on every request from the owner's current role, so
-- disabling or demoting the owner takes effect immediately.
CREATE TABLE delegations (
  delegation_id TEXT    PRIMARY KEY,
  -- The human whose authority is delegated. Deleting the owner revokes the token.
  owner_id      TEXT    NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  label         TEXT    NOT NULL,
  token_hash    BLOB    NOT NULL UNIQUE,
  -- First characters of the token (e.g. "qwq_dlg_ab12"), for recognition.
  token_prefix  TEXT    NOT NULL,
  -- DelegationPolicy of the public API, as JSON: actions, node_ids,
  -- auto_approve_max_risk, on_approval_required, requests_per_minute.
  policy        TEXT    NOT NULL CHECK (json_valid(policy)),
  status        TEXT    NOT NULL CHECK (status IN ('active', 'suspended', 'expired')),
  created_by    TEXT    NOT NULL DEFAULT '',
  created_at    TEXT    NOT NULL,
  updated_at    TEXT    NOT NULL,
  expires_at    TEXT    NOT NULL,
  last_used_at  TEXT    NOT NULL DEFAULT '',
  revision      INTEGER NOT NULL DEFAULT 0,
  CHECK (length(label) BETWEEN 1 AND 64),
  CHECK (length(token_prefix) <= 16)
) STRICT;

CREATE INDEX delegations_owner ON delegations (owner_id, status);
CREATE INDEX delegations_expiry ON delegations (expires_at);

CREATE TABLE service_accounts (
  service_id   TEXT    PRIMARY KEY,
  name         TEXT    NOT NULL UNIQUE,
  -- Service accounts are limited to a built-in role and are always denied the
  -- human-only actions (ADR-0004 D6).
  role         TEXT    NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
  token_hash   BLOB    NOT NULL UNIQUE,
  token_prefix TEXT    NOT NULL,
  disabled     INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
  created_by   TEXT    NOT NULL DEFAULT '',
  created_at   TEXT    NOT NULL,
  updated_at   TEXT    NOT NULL,
  last_used_at TEXT    NOT NULL DEFAULT '',
  revision     INTEGER NOT NULL DEFAULT 0,
  CHECK (length(name) BETWEEN 1 AND 64),
  CHECK (length(token_prefix) <= 16)
) STRICT;

CREATE INDEX service_accounts_live ON service_accounts (disabled);
