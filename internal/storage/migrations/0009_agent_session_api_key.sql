-- SPDX-License-Identifier: AGPL-3.0-only
-- The API key of a native agent session (AGT-02).
--
-- api_key_ref is the secret reference (sec_…) of the key the session owner
-- stored with PUT /api/v1/agent-sessions/{session_id}/api-key, or '' when the
-- session has none. The secret row is owned by agent_sessions/<session_id> with
-- the purpose agent.native.api_key, and the native core decrypts it only through
-- secrets.RevealOwned with exactly that owner and purpose, so a reference to any
-- other secret is useless here. Deleting the session deletes the secret in the
-- same transaction. The reference never leaves the host: the API only shows
-- has_api_key.
--
-- No PRAGMA statements: connection settings live in the DSN (see
-- internal/storage).

ALTER TABLE agent_sessions ADD COLUMN api_key_ref TEXT NOT NULL DEFAULT '';
