-- SPDX-License-Identifier: AGPL-3.0-only
-- Extend global AI providers with:
--   - anthropic_compatible protocol support alongside openai_compatible
--   - cached fetched model list (models_json)
--   - default reasoning_effort ('' | none | low | medium | high | xhigh)
--   - default max_context_tokens (0 = core default)
--
-- Rebuilds ai_providers in place because SQLite CHECK constraints cannot be
-- altered in place. No PRAGMA statements (managed by internal/storage).

CREATE TABLE ai_providers_next (
    provider_id        TEXT    PRIMARY KEY,
    name               TEXT    NOT NULL,
    kind               TEXT    NOT NULL,
    base_url           TEXT    NOT NULL,
    model              TEXT    NOT NULL,
    models_json        TEXT    NOT NULL DEFAULT '[]',
    reasoning_effort   TEXT    NOT NULL DEFAULT '',
    max_context_tokens INTEGER NOT NULL DEFAULT 0,
    api_key_ref        TEXT    NOT NULL DEFAULT '',
    is_default         INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT    NOT NULL,
    updated_at         TEXT    NOT NULL,
    revision           INTEGER NOT NULL,
    CHECK (kind IN ('openai_compatible', 'anthropic_compatible')),
    CHECK (reasoning_effort IN ('', 'none', 'low', 'medium', 'high', 'xhigh')),
    CHECK (max_context_tokens >= 0),
    CHECK (is_default IN (0, 1))
) STRICT;

INSERT INTO ai_providers_next
    (provider_id, name, kind, base_url, model, models_json, reasoning_effort, max_context_tokens,
     api_key_ref, is_default, created_at, updated_at, revision)
SELECT
    provider_id, name, kind, base_url, model, '[]', '', 0,
    api_key_ref, is_default, created_at, updated_at, revision
FROM ai_providers;

DROP TABLE ai_providers;
ALTER TABLE ai_providers_next RENAME TO ai_providers;

CREATE UNIQUE INDEX ai_providers_name ON ai_providers (name);
CREATE UNIQUE INDEX ai_providers_default ON ai_providers (is_default) WHERE is_default = 1;
