-- SPDX-License-Identifier: AGPL-3.0-only
-- Audit query indexes (GAPS gap 7). GET /audit filters by action, outcome and
-- actor id and orders by occurred_at; 0004 already indexes occurred_at, subject,
-- operation_id and (actor_kind, actor_id), but an actor-id-only filter cannot
-- use an index whose leading column is actor_kind.

CREATE INDEX IF NOT EXISTS audit_log_action ON audit_log (action, occurred_at);
CREATE INDEX IF NOT EXISTS audit_log_outcome ON audit_log (outcome, occurred_at);
CREATE INDEX IF NOT EXISTS audit_log_actor_id ON audit_log (actor_id, occurred_at);