-- SPDX-License-Identifier: AGPL-3.0-only
-- Native agent sessions (ADR-0010 §5, docs/design/agent-sessions.md).
--
-- A session is private chat state of one owner (a human user or a service
-- account); the owner columns are what the API uses to answer 404 for another
-- principal's session. The rows are not host resources of the operation
-- surface: a tool call an agent proposes goes through operations.Run, but the
-- transcript itself is bounded, user-owned data. `revision` is still the
-- resource.changed sequence of the last write to the session row, so a client
-- can use expected_revision and since_revision like on every other resource.
--
-- seq is a per-session counter shared by messages and tool calls; it is the SSE
-- event id, so a client that reconnects with Last-Event-ID sees one monotonic
-- stream. agent_sessions.last_seq is the high-water mark of that counter.
--
-- Messages are pruned to the newest N per session (N is a host setting, 200 by
-- default). Tool calls and their approval association are kept longer: they
-- are the local audit trail of what the agent tried to do, and the operations
-- audit row has the authoritative record.
--
-- No PRAGMA statements: connection settings live in the DSN (see
-- internal/storage).

CREATE TABLE agent_sessions (
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
    CHECK (owner_kind IN ('human', 'service')),
    CHECK (core IN ('native', 'claude-code', 'codex', 'opencode')),
    CHECK (permission_mode IN ('read_only', 'safe', 'full', 'custom')),
    CHECK (status IN ('idle', 'running', 'waiting_approval', 'cancelled', 'failed'))
) STRICT;

-- List order is session_id DESC (IDs are time ordered); the owner pair is the
-- access-control predicate of every read.
CREATE INDEX agent_sessions_owner ON agent_sessions (owner_kind, owner_id, session_id);
-- The floating window asks for attention = waiting_approval | failed.
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

CREATE UNIQUE INDEX agent_messages_message_id ON agent_messages (message_id);
-- A retried send (same client_message_id) must not append the message twice.
CREATE UNIQUE INDEX agent_messages_client_id ON agent_messages (session_id, client_message_id)
    WHERE client_message_id <> '';

-- Retention deletes the oldest rows by seq within one session.
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

CREATE INDEX agent_tool_calls_session ON agent_tool_calls (session_id, seq);
CREATE INDEX agent_tool_calls_status ON agent_tool_calls (session_id, status);
CREATE INDEX agent_tool_calls_approval ON agent_tool_calls (approval_id) WHERE approval_id <> '';
