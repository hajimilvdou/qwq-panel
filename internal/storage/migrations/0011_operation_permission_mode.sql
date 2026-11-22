-- SPDX-License-Identifier: AGPL-3.0-only
-- The permission mode of the caller that created an operation (ADR-0011 §5).
--
-- A plugin-to-plugin child operation inherits the mode of its parent; the
-- mode lived only on the request context before, so a plugin's host call
-- could not see it. An empty value (every row written before this column)
-- reads as safe, so the default never widens anything.
ALTER TABLE operations ADD COLUMN permission_mode TEXT NOT NULL DEFAULT '';
