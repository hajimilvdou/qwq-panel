-- SPDX-License-Identifier: AGPL-3.0-only
-- Secrets (P1-T6, ADR-0008 §7).
--
-- A row is one AES-256-GCM ciphertext plus everything needed to find the key
-- and bind the value to its owner: the nonce, the id of the master key that
-- encrypted it, and the purpose it may be used for. The additional
-- authenticated data is id + owner + purpose, so a ciphertext copied into
-- another row, or relabelled, does not decrypt (internal/secrets).
--
-- Only references (sec_…) appear in other tables, config snapshots, events,
-- audit rows and logs. revision is reserved: secrets deliberately publish no
-- resource.changed event, so there is no sequence number to record yet.

CREATE TABLE secrets (
    id         TEXT    NOT NULL PRIMARY KEY,
    owner      TEXT    NOT NULL,
    purpose    TEXT    NOT NULL,
    key_id     TEXT    NOT NULL,
    nonce      BLOB    NOT NULL,
    ciphertext BLOB    NOT NULL,
    created_at TEXT    NOT NULL,
    revision   INTEGER NOT NULL DEFAULT 0
) STRICT;

-- DeleteOwner (plugin uninstall) scans by owner; rotation scans by key.
CREATE INDEX secrets_owner_idx ON secrets (owner);
CREATE INDEX secrets_key_idx ON secrets (key_id);
