-- SPDX-License-Identifier: AGPL-3.0-only
-- Operations, plans, approvals, idempotency keys and the audit log
-- (ARCH §7, §8.1; ADR-0004 D1/D6/D7; ADR-0008 §2, §4).
--
-- Every row that carries `revision` stores the sequence number of the
-- resource.changed event that last modified it (ADR-0008 §4); the owning code
-- obtains it from storage.Tx.Changed. No PRAGMA statements: connection
-- settings live in the DSN (see internal/storage).
--
-- Mutable JSON members are stored as TEXT with json_valid() checks so a broken
-- row cannot be read back as a valid document. Operations are never deleted;
-- plans and idempotency keys are pruned by the operations package.

-- One record per state change (ARCH §7). `action_meta` is the catalog metadata
-- frozen at creation, so an approved operation still knows its effect, risk and
-- permission if the plugin was uninstalled in between.
CREATE TABLE operations (
  operation_id        TEXT    PRIMARY KEY,
  action              TEXT    NOT NULL,
  action_meta         TEXT    NOT NULL CHECK (json_valid(action_meta)),
  status              TEXT    NOT NULL,
  target              TEXT    NOT NULL CHECK (json_valid(target)),
  node_id             TEXT    NOT NULL DEFAULT '',
  plugin_id           TEXT    NOT NULL DEFAULT '',
  instance_id         TEXT    NOT NULL DEFAULT '',
  subject             TEXT    NOT NULL DEFAULT '',
  actor_kind          TEXT    NOT NULL,
  actor_id            TEXT    NOT NULL,
  actor_on_behalf_of  TEXT    NOT NULL DEFAULT '',
  effective_risk      TEXT    NOT NULL,
  declared_risk       TEXT    NOT NULL,
  effect              TEXT    NOT NULL,
  mode                TEXT    NOT NULL,
  idempotent          INTEGER NOT NULL DEFAULT 0,
  permission          TEXT    NOT NULL DEFAULT '',
  ui_route            TEXT    NOT NULL DEFAULT '',
  args                TEXT    NOT NULL CHECK (json_valid(args)),
  args_digest         TEXT    NOT NULL,
  expected_revision   TEXT    NOT NULL DEFAULT '',
  preconditions       TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(preconditions)),
  plan_id             TEXT    NOT NULL DEFAULT '',
  approval_id         TEXT    NOT NULL DEFAULT '',
  parent_operation_id TEXT    NOT NULL DEFAULT '',
  attempt             INTEGER NOT NULL DEFAULT 1,
  cancel_requested    INTEGER NOT NULL DEFAULT 0,
  progress            TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(progress)),
  result              TEXT    CHECK (result IS NULL OR json_valid(result)),
  error               TEXT    CHECK (error IS NULL OR json_valid(error)),
  timeout_ms          INTEGER NOT NULL,
  request_id          TEXT    NOT NULL DEFAULT '',
  trace_id            TEXT    NOT NULL DEFAULT '',
  created_at          TEXT    NOT NULL,
  updated_at          TEXT    NOT NULL,
  started_at          TEXT    NOT NULL DEFAULT '',
  finished_at         TEXT    NOT NULL DEFAULT '',
  revision            INTEGER NOT NULL
) STRICT;

CREATE INDEX operations_status ON operations (status, operation_id);
CREATE INDEX operations_actor ON operations (actor_kind, actor_id, operation_id);
CREATE INDEX operations_node_plugin ON operations (node_id, plugin_id, operation_id);
CREATE INDEX operations_revision ON operations (revision);
CREATE INDEX operations_parent ON operations (parent_operation_id) WHERE parent_operation_id <> '';
CREATE INDEX operations_plan ON operations (plan_id) WHERE plan_id <> '';

-- One row per execution attempt; (operation_id, attempt) identifies an
-- execution (ARCH §7, ADR-0007 #14/#15). A retried attempt gets a new row.
CREATE TABLE operation_attempts (
  operation_id TEXT    NOT NULL REFERENCES operations (operation_id),
  attempt      INTEGER NOT NULL,
  status       TEXT    NOT NULL,
  started_at   TEXT    NOT NULL,
  finished_at  TEXT    NOT NULL DEFAULT '',
  error        TEXT    CHECK (error IS NULL OR json_valid(error)),
  PRIMARY KEY (operation_id, attempt)
) STRICT;

-- Side-effect free preview bound to a later execution (ADR-0004 D7).
-- `preconditions` holds host-side entries with full subjects; the plugin-side
-- ones keep the relative subjects the ABI gives them (ADR-0007 #2).
CREATE TABLE plans (
  plan_id              TEXT    PRIMARY KEY,
  action               TEXT    NOT NULL,
  action_meta          TEXT    NOT NULL CHECK (json_valid(action_meta)),
  target               TEXT    NOT NULL CHECK (json_valid(target)),
  args                 TEXT    NOT NULL CHECK (json_valid(args)),
  args_digest          TEXT    NOT NULL,
  plannable            INTEGER NOT NULL,
  changes              TEXT    NOT NULL CHECK (json_valid(changes)),
  changes_truncated    INTEGER NOT NULL DEFAULT 0,
  violations           TEXT    NOT NULL CHECK (json_valid(violations)),
  warnings             TEXT    NOT NULL CHECK (json_valid(warnings)),
  preconditions        TEXT    NOT NULL CHECK (json_valid(preconditions)),
  plugin_preconditions TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(plugin_preconditions)),
  effective_risk       TEXT    NOT NULL,
  requires_approval    INTEGER NOT NULL,
  requires_mfa         INTEGER NOT NULL,
  executable           INTEGER NOT NULL,
  operation_id         TEXT    NOT NULL DEFAULT '',
  actor_kind           TEXT    NOT NULL,
  actor_id             TEXT    NOT NULL,
  actor_on_behalf_of   TEXT    NOT NULL DEFAULT '',
  trace_id             TEXT    NOT NULL DEFAULT '',
  request_id           TEXT    NOT NULL DEFAULT '',
  created_at           TEXT    NOT NULL,
  expires_at           TEXT    NOT NULL,
  revision             INTEGER NOT NULL
) STRICT;

CREATE INDEX plans_expires_at ON plans (expires_at);
CREATE INDEX plans_principal ON plans (actor_kind, actor_id, actor_on_behalf_of, created_at);

-- A request for a human decision (ADR-0004 D6). `facts` is everything the host
-- knows on its own; `plugin_preview` is the untrusted part of a plan.
CREATE TABLE approvals (
  approval_id             TEXT    PRIMARY KEY,
  operation_id            TEXT    NOT NULL,
  plan_id                 TEXT    NOT NULL DEFAULT '',
  status                  TEXT    NOT NULL,
  facts                   TEXT    NOT NULL CHECK (json_valid(facts)),
  plugin_preview          TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(plugin_preview)),
  requires_mfa            INTEGER NOT NULL DEFAULT 0,
  decided_by_kind         TEXT    NOT NULL DEFAULT '',
  decided_by_id           TEXT    NOT NULL DEFAULT '',
  decided_by_on_behalf_of TEXT    NOT NULL DEFAULT '',
  decided_at              TEXT    NOT NULL DEFAULT '',
  comment                 TEXT    NOT NULL DEFAULT '',
  created_at              TEXT    NOT NULL,
  expires_at              TEXT    NOT NULL,
  revision                INTEGER NOT NULL
) STRICT;

CREATE INDEX approvals_status ON approvals (status, created_at);
CREATE INDEX approvals_operation ON approvals (operation_id);

-- Idempotency keys, scoped to principal + method + route (ARCH §4.1).
-- `state` is `in_progress` while the first request runs and `completed` once a
-- replayable response exists. `response_body` is the exact JSON that was sent.
CREATE TABLE idempotency_keys (
  key_id          TEXT    PRIMARY KEY,
  principal       TEXT    NOT NULL,
  method          TEXT    NOT NULL,
  route           TEXT    NOT NULL,
  key             TEXT    NOT NULL,
  fingerprint     TEXT    NOT NULL,
  state           TEXT    NOT NULL,
  operation_id    TEXT    NOT NULL DEFAULT '',
  response_status INTEGER NOT NULL DEFAULT 0,
  response_body   TEXT    CHECK (response_body IS NULL OR json_valid(response_body)),
  created_at      TEXT    NOT NULL,
  updated_at      TEXT    NOT NULL,
  expires_at      TEXT    NOT NULL,
  UNIQUE (principal, method, route, key)
) STRICT;

CREATE INDEX idempotency_expires_at ON idempotency_keys (expires_at);
CREATE INDEX idempotency_principal ON idempotency_keys (principal, expires_at);

-- Audit log (ARCH §8.1, ADR-0008 §2). Authentication flows write here without
-- creating an operation; plugin-reported records will be added with
-- source=plugin and their own quota (review S10).
CREATE TABLE audit_log (
  audit_id           TEXT PRIMARY KEY,
  occurred_at        TEXT NOT NULL,
  actor_kind         TEXT NOT NULL DEFAULT '',
  actor_id           TEXT NOT NULL DEFAULT '',
  actor_on_behalf_of TEXT NOT NULL DEFAULT '',
  source             TEXT NOT NULL DEFAULT 'host',
  action             TEXT NOT NULL,
  subject            TEXT NOT NULL DEFAULT '',
  outcome            TEXT NOT NULL,
  operation_id       TEXT NOT NULL DEFAULT '',
  node_id            TEXT NOT NULL DEFAULT '',
  trace_id           TEXT NOT NULL DEFAULT '',
  request_id         TEXT NOT NULL DEFAULT '',
  details            TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details))
) STRICT;

CREATE INDEX audit_log_occurred_at ON audit_log (occurred_at);
CREATE INDEX audit_log_actor ON audit_log (actor_kind, actor_id, occurred_at);
CREATE INDEX audit_log_subject ON audit_log (subject, occurred_at);
CREATE INDEX audit_log_operation ON audit_log (operation_id) WHERE operation_id <> '';
