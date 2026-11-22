-- SPDX-License-Identifier: AGPL-3.0-only
-- Identity (P1-T3, ADR-0005 Q7, ADR-0008 §1): users, credentials, sessions, MFA
-- challenges and one-time tokens. Every table with a `revision` column stores the
-- sequence number of the resource.changed event that last touched the resource
-- (ADR-0008 §4); credentials and sessions are covered by their user's resource, so
-- they carry the revision of that change (0 means "not published").
CREATE TABLE users (
  user_id      TEXT    PRIMARY KEY,
  -- Canonical login name: lower case, ASCII. The unique index makes lookups
  -- case-insensitive without a collation (the host stores only the canonical form).
  username     TEXT    NOT NULL UNIQUE,
  display_name TEXT    NOT NULL DEFAULT '',
  -- Built-in roles; the Role enum of the public API is the source of truth.
  role         TEXT    NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
  disabled     INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
  created_at   TEXT    NOT NULL,
  updated_at   TEXT    NOT NULL,
  revision     INTEGER NOT NULL DEFAULT 0,
  CHECK (username = lower(username)),
  CHECK (length(username) BETWEEN 1 AND 64),
  CHECK (length(display_name) <= 128)
) STRICT;

-- Credentials are (type, secret, data) rows so that WebAuthn and OIDC can be
-- added without a schema change (ADR-0005 Q7):
--   password      secret = argon2id PHC string
--   totp          secret = sealed secret reference (SecretSealer), counter = last
--                 accepted time step (replay protection)
--   totp_pending  as totp, but not yet confirmed by a valid code
--   recovery      secret = hex SHA-256 of the normalised recovery code
--   webauthn      secret = sealed credential public key, data = {credential_id, ...}
--   oidc          secret = '', data = {issuer, subject, email}
CREATE TABLE credentials (
  credential_id TEXT    PRIMARY KEY,
  user_id       TEXT    NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  type          TEXT    NOT NULL CHECK (type IN
                   ('password', 'totp', 'totp_pending', 'recovery', 'webauthn', 'oidc')),
  secret        TEXT    NOT NULL DEFAULT '',
  data          TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(data)),
  counter       INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT    NOT NULL,
  updated_at    TEXT    NOT NULL,
  revision      INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX credentials_user_type ON credentials (user_id, type);
-- At most one password, one confirmed TOTP secret and one pending TOTP secret
-- per user; recovery codes and future WebAuthn/OIDC rows are many.
CREATE UNIQUE INDEX credentials_unique_password ON credentials (user_id) WHERE type = 'password';
CREATE UNIQUE INDEX credentials_unique_totp ON credentials (user_id) WHERE type = 'totp';
CREATE UNIQUE INDEX credentials_unique_totp_pending ON credentials (user_id) WHERE type = 'totp_pending';

CREATE TABLE sessions (
  session_id      TEXT    PRIMARY KEY,
  user_id         TEXT    NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  -- SHA-256 of the 32-byte session token; the token itself is never stored.
  token_hash      BLOB    NOT NULL UNIQUE,
  -- Synchroniser token returned in Session.csrf_token. It only mitigates
  -- cross-site requests, so it is kept readable for GET /sessions/current.
  csrf_token      TEXT    NOT NULL,
  mfa_verified_at TEXT    NOT NULL DEFAULT '',
  created_at      TEXT    NOT NULL,
  last_seen_at    TEXT    NOT NULL,
  idle_expires_at TEXT    NOT NULL,
  expires_at      TEXT    NOT NULL,
  revoked_at      TEXT    NOT NULL DEFAULT '',
  client_ip       TEXT    NOT NULL DEFAULT '',
  user_agent      TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expiry ON sessions (expires_at);
CREATE INDEX sessions_live ON sessions (user_id) WHERE revoked_at = '';

-- Half-authenticated login: the password was correct, the second factor is not
-- answered yet. The challenge ID is a random token; only its hash is stored.
CREATE TABLE mfa_challenges (
  id_hash    BLOB    PRIMARY KEY,
  user_id    TEXT    NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  created_at TEXT    NOT NULL,
  expires_at TEXT    NOT NULL,
  used_at    TEXT    NOT NULL DEFAULT '',
  attempts   INTEGER NOT NULL DEFAULT 0,
  client_ip  TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX mfa_challenges_user ON mfa_challenges (user_id);

-- One-time tokens: `setup` initialises a fresh installation, `enroll` lets an
-- administrator hand a new user a link to choose their own password. Only the
-- SHA-256 of the token is stored (ARCH §4.1.1).
CREATE TABLE one_time_tokens (
  token_id   TEXT    PRIMARY KEY,
  purpose    TEXT    NOT NULL CHECK (purpose IN ('setup', 'enroll')),
  user_id    TEXT    REFERENCES users (user_id) ON DELETE CASCADE,
  token_hash BLOB    NOT NULL UNIQUE,
  created_at TEXT    NOT NULL,
  expires_at TEXT    NOT NULL,
  used_at    TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX one_time_tokens_purpose ON one_time_tokens (purpose, used_at);
