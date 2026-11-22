-- SPDX-License-Identifier: AGPL-3.0-only
-- Retention indexes (OPS-05). The sweeper deletes finished operations and old
-- audit rows in bounded batches, oldest first, so both need an index on the
-- timestamp it orders by.
--
-- audit_log_occurred_at already exists (0004_operations.sql); it is not created
-- again here.

CREATE INDEX IF NOT EXISTS operations_finished_at ON operations (finished_at) WHERE finished_at <> '';
CREATE INDEX IF NOT EXISTS idempotency_in_progress ON idempotency_keys (created_at) WHERE state = 'in_progress';