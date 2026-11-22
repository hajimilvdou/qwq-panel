-- SPDX-License-Identifier: AGPL-3.0-only
-- Wave 0 P2-CORE: non-redundant hot-path indexes for event topic replay,
-- action history queries, and pending approval expiration sweeps.

CREATE INDEX IF NOT EXISTS event_journal_type_seq ON event_journal (type, seq);
CREATE INDEX IF NOT EXISTS operations_action_created ON operations (action, created_at);
CREATE INDEX IF NOT EXISTS approvals_pending_expires ON approvals (expires_at) WHERE status = 'pending';
