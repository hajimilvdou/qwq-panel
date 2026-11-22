<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# SQL Migration Draft (Reserved Post-`0020` Slot): Expand `agent_sessions.core` CHECK for `dsh` / `acp`

> **Status**: Draft only — intentionally NOT placed inside `internal/storage/migrations/` yet so we do NOT collide with Codex's reserved `0019` (Track 05 `netfacts`) and `0020` (retention indexes) or violate `internal/storage/migrate.go`'s contiguous `1..n` sequence rule.

## Current Persistence Boundary (on `0007`..`0018`)

- **Persisted directly in SQLite (`agent_sessions.core`) & validated by `CoreName.Valid()`**:
  - `native` (backed by `EnhancedNativeCore`; enhanced fields `stream`, `enable_plan_tool`, `plan_mode`, `reasoning_effort`, `active_skills` live inside `agent_sessions.config_json` and pass `normalizeConfig`'s 32 KiB limit and plaintext/reference secret guards).
  - `claude-code` (backed by `ClaudeCodeCore`).
  - `codex` (backed by `CodexCore`).
  - `opencode` (backed by `OpenCodeCore`).
- **Registered in Go runtime (`Service.cores` & `CoreDescriptors`) and awaiting post-`0020` migration slot**:
  - `dsh` (`DSHCore`)
  - `acp` (`GenericACPCore`)
  - Until Codex publishes the next available migration number (`0021+`) and coordinates `api/public/v1/openapi.yaml` `AgentCore` enum generation, `Service.Create` continues to accept only `native | claude-code | codex | opencode` so DB `CHECK` and Go validation remain strictly consistent.

## Proposed SQLite Migration (when slot `00XX` is assigned by Codex)

SQLite requires table rebuild to widen a `CHECK` constraint on `agent_sessions.core` while preserving every existing row, foreign key, and index from `0007_agent_sessions.sql`:

```sql
-- 00XX_agent_session_cores_dsh_acp.sql
PRAGMA foreign_keys = OFF;

CREATE TABLE agent_sessions_new (
  session_id        TEXT PRIMARY KEY,
  owner_kind        TEXT NOT NULL CHECK (owner_kind IN ('human', 'service')),
  owner_id          TEXT NOT NULL,
  title             TEXT NOT NULL DEFAULT '',
  core              TEXT NOT NULL CHECK (core IN ('native', 'claude-code', 'codex', 'opencode', 'dsh', 'acp')),
  permission_mode   TEXT NOT NULL CHECK (permission_mode IN ('read_only', 'safe', 'full', 'custom')),
  status            TEXT NOT NULL CHECK (status IN ('idle', 'running', 'waiting_approval', 'attention', 'cancelled', 'failed')),
  config_json       TEXT NOT NULL DEFAULT '{}',
  api_key_ref       TEXT NOT NULL DEFAULT '',
  revision          INTEGER NOT NULL DEFAULT 1,
  last_seq          INTEGER NOT NULL DEFAULT 0,
  last_message_at   TEXT,
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

INSERT INTO agent_sessions_new SELECT * FROM agent_sessions;
DROP TABLE agent_sessions;
ALTER TABLE agent_sessions_new RENAME TO agent_sessions;

CREATE INDEX idx_agent_sessions_owner ON agent_sessions (owner_kind, owner_id, updated_at DESC);

PRAGMA foreign_keys = ON;
```

*(Verify exact column list against `0007_agent_sessions.sql` and any intervening migrations before committing into `internal/storage/migrations/`.)*
