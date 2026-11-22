-- SPDX-License-Identifier: AGPL-3.0-only
-- Event journal (ARCH §4.2, ADR-0008 §4). seq is the SSE id and Last-Event-ID; AUTOINCREMENT
-- guarantees a seq is never reused after pruning. A resource's revision is the seq of the
-- resource.changed event that last modified it. Only reliable events are journaled; lossy realtime
-- samples go through memory only.
CREATE TABLE event_journal (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id       TEXT    NOT NULL UNIQUE,
  type           TEXT    NOT NULL,
  schema_version TEXT    NOT NULL,
  subject        TEXT    NOT NULL,
  occurred_at    TEXT    NOT NULL,
  actor_kind     TEXT    NOT NULL DEFAULT '',
  actor_id       TEXT    NOT NULL DEFAULT '',
  on_behalf_of   TEXT    NOT NULL DEFAULT '',
  node_id        TEXT    NOT NULL DEFAULT '',
  trace_id       TEXT    NOT NULL DEFAULT '',
  operation_id   TEXT    NOT NULL DEFAULT '',
  payload        TEXT    NOT NULL CHECK (json_valid(payload))
) STRICT;

CREATE INDEX event_journal_occurred_at ON event_journal (occurred_at);
CREATE INDEX event_journal_operation ON event_journal (operation_id) WHERE operation_id <> '';
