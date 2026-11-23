-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 0024: expand agent_sessions core CHECK to allow 'dsh' and 'acp'
-- and status CHECK to allow 'attention', without PRAGMA statements and while
-- preserving all agent_messages and agent_tool_calls rows under foreign_keys=ON.
-- Also adds missing expiry/cleanup indexes and drops redundant plugin_configs_revision_idx.

CREATE TABLE _mig0024_messages_bak AS SELECT * FROM agent_messages;
CREATE TABLE _mig0024_tool_calls_bak AS SELECT * FROM agent_tool_calls;

DROP TABLE agent_messages;
DROP TABLE agent_tool_calls;

CREATE TABLE agent_sessions_next (
    session_id      TEXT    PRIMARY KEY,
    plugin_id       TEXT    NOT NULL DEFAULT 'agent.native',
    owner_kind      TEXT    NOT NULL,
    owner_id        TEXT    NOT NULL,
    title           TEXT    NOT NULL,
    core            TEXT    NOT NULL,
    permission_mode TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    config_json     TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(config_json)),
    last_seq        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    revision        INTEGER NOT NULL,
    api_key_ref     TEXT    NOT NULL DEFAULT '',
    CHECK (owner_kind IN ('human', 'service')),
    CHECK (core IN ('native', 'claude-code', 'codex', 'opencode', 'dsh', 'acp')),
    CHECK (permission_mode IN ('read_only', 'safe', 'full', 'custom')),
    CHECK (status IN ('idle', 'running', 'waiting_approval', 'attention', 'cancelled', 'failed'))
) STRICT;

INSERT INTO agent_sessions_next (
    session_id, plugin_id, owner_kind, owner_id, title, core, permission_mode,
    status, config_json, last_seq, created_at, updated_at, revision, api_key_ref
)
SELECT
    session_id, plugin_id, owner_kind, owner_id, title, core, permission_mode,
    status, config_json, last_seq, created_at, updated_at, revision, api_key_ref
FROM agent_sessions;

DROP TABLE agent_sessions;
ALTER TABLE agent_sessions_next RENAME TO agent_sessions;

CREATE INDEX agent_sessions_owner ON agent_sessions (owner_kind, owner_id, session_id);
CREATE INDEX agent_sessions_status ON agent_sessions (status, session_id);

CREATE TABLE agent_messages (
    session_id        TEXT    NOT NULL REFERENCES agent_sessions (session_id) ON DELETE CASCADE,
    seq               INTEGER NOT NULL,
    message_id        TEXT    NOT NULL,
    role              TEXT    NOT NULL,
    content           TEXT    NOT NULL,
    content_json      TEXT    CHECK (content_json IS NULL OR json_valid(content_json)),
    operation_id      TEXT    NOT NULL DEFAULT '',
    approval_id       TEXT    NOT NULL DEFAULT '',
    client_message_id TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL,
    PRIMARY KEY (session_id, seq),
    CHECK (role IN ('user', 'assistant', 'system', 'tool'))
) STRICT;

INSERT INTO agent_messages (
    session_id, seq, message_id, role, content, content_json,
    operation_id, approval_id, client_message_id, created_at
)
SELECT
    session_id, seq, message_id, role, content, content_json,
    operation_id, approval_id, client_message_id, created_at
FROM _mig0024_messages_bak;

DROP TABLE _mig0024_messages_bak;

CREATE UNIQUE INDEX agent_messages_message_id ON agent_messages (message_id);
CREATE UNIQUE INDEX agent_messages_client_id ON agent_messages (session_id, client_message_id)
    WHERE client_message_id <> '';
CREATE INDEX agent_messages_retention ON agent_messages (session_id, seq);

CREATE TABLE agent_tool_calls (
    call_id      TEXT PRIMARY KEY,
    session_id   TEXT    NOT NULL REFERENCES agent_sessions (session_id) ON DELETE CASCADE,
    seq          INTEGER NOT NULL,
    action_id    TEXT    NOT NULL,
    args_json    TEXT    NOT NULL CHECK (json_valid(args_json)),
    operation_id TEXT    NOT NULL DEFAULT '',
    approval_id  TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL,
    result_json  TEXT    CHECK (result_json IS NULL OR json_valid(result_json)),
    error_json   TEXT    CHECK (error_json IS NULL OR json_valid(error_json)),
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    revision     INTEGER NOT NULL,
    UNIQUE (session_id, seq),
    CHECK (status IN ('proposed', 'running', 'awaiting_approval', 'succeeded', 'failed', 'rejected', 'cancelled'))
) STRICT;

INSERT INTO agent_tool_calls (
    call_id, session_id, seq, action_id, args_json, operation_id, approval_id,
    status, result_json, error_json, created_at, updated_at, revision
)
SELECT
    call_id, session_id, seq, action_id, args_json, operation_id, approval_id,
    status, result_json, error_json, created_at, updated_at, revision
FROM _mig0024_tool_calls_bak;

DROP TABLE _mig0024_tool_calls_bak;

CREATE INDEX agent_tool_calls_session ON agent_tool_calls (session_id, seq);
CREATE INDEX agent_tool_calls_status ON agent_tool_calls (session_id, status);
CREATE INDEX agent_tool_calls_approval ON agent_tool_calls (approval_id) WHERE approval_id <> '';

-- Index governance: add missing expiry/user cleanup indexes and remove redundant index.
CREATE INDEX IF NOT EXISTS idx_one_time_tokens_user_id ON one_time_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_one_time_tokens_expires_at ON one_time_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at ON mfa_challenges (expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_idle_expires_at ON sessions (idle_expires_at);
DROP INDEX IF EXISTS plugin_configs_revision_idx;
