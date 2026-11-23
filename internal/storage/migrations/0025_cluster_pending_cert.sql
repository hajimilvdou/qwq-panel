-- SPDX-License-Identifier: AGPL-3.0-only
-- Persist pending node certificate metadata across controller restarts during two-phase rotation.

ALTER TABLE nodes ADD COLUMN pending_cert_serial TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN pending_cert_fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN pending_cert_expires_at TEXT NOT NULL DEFAULT '';
