-- SPDX-License-Identifier: AGPL-3.0-only
-- Global AI providers (ADR-0017).
--
-- A provider is a model endpoint an administrator configured for the whole
-- installation: every owner of an agent session may pick one, and a session
-- without its own endpoint uses the default one. base_url and model are plain
-- configuration; the API key is not here. api_key_ref is the secret reference
-- (sec_…) of the key stored with PUT /api/v1/ai/providers/{provider_id}/api-key,
-- or '' when the provider has none. The secret row is owned by
-- ai_providers/<provider_id> with the purpose agent.native.api_key, and the
-- native core decrypts it only through secrets.RevealOwned with exactly that
-- owner and purpose. Deleting the provider deletes the secret in the same
-- transaction. The reference never leaves the host: the API only shows
-- has_api_key.
--
-- At most one provider is the default (partial unique index); names are unique
-- because people choose a provider by its name.
--
-- No PRAGMA statements: connection settings live in the DSN (see
-- internal/storage).

CREATE TABLE ai_providers (
    provider_id TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    base_url    TEXT    NOT NULL,
    model       TEXT    NOT NULL,
    api_key_ref TEXT    NOT NULL DEFAULT '',
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    revision    INTEGER NOT NULL,
    CHECK (kind IN ('openai_compatible')),
    CHECK (is_default IN (0, 1))
) STRICT;

CREATE UNIQUE INDEX ai_providers_name ON ai_providers (name);
CREATE UNIQUE INDEX ai_providers_default ON ai_providers (is_default) WHERE is_default = 1;
