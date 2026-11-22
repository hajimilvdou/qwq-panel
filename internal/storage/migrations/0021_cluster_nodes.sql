-- SPDX-License-Identifier: AGPL-3.0-only
-- Track 08 P4: Multi-node Controller <-> Node Agent enrollment and cluster state tables.

CREATE TABLE nodes (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    mode                TEXT NOT NULL CHECK (mode IN ('full', 'probe_512m')),
    enrollment_state    TEXT NOT NULL CHECK (enrollment_state IN ('pending', 'active', 'cordoned', 'revoked')),
    cert_serial         TEXT NOT NULL DEFAULT '',
    cert_fingerprint    TEXT NOT NULL DEFAULT '',
    cert_expires_at     INTEGER NOT NULL DEFAULT 0,
    agent_version       TEXT NOT NULL DEFAULT '',
    arch                TEXT NOT NULL DEFAULT '',
    public_addrs_json   TEXT NOT NULL DEFAULT '[]',
    last_heartbeat_at   INTEGER NOT NULL DEFAULT 0,
    last_ack_seq        INTEGER NOT NULL DEFAULT 0,
    revision            TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
) STRICT;

CREATE INDEX nodes_state_idx ON nodes (enrollment_state, last_heartbeat_at);

CREATE TABLE node_enrollment_tokens (
    id                  TEXT PRIMARY KEY,
    token_sha256        TEXT NOT NULL UNIQUE,
    preset_name         TEXT NOT NULL,
    mode                TEXT NOT NULL CHECK (mode IN ('full', 'probe_512m')),
    expires_at          INTEGER NOT NULL,
    redeemed_node_id    TEXT NOT NULL DEFAULT '',
    created_by          TEXT NOT NULL,
    created_at          INTEGER NOT NULL
) STRICT;

CREATE INDEX node_enrollment_tokens_expiry_idx ON node_enrollment_tokens (expires_at);
