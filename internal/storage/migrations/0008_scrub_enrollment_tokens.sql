-- SPDX-License-Identifier: AGPL-3.0-only
-- Scrub enrollment tokens stored in clear (AUTH-06).
--
-- Earlier releases returned a new user's enrollment token in the result of
-- host.users.create. The result is kept for good in operations.result and for
-- 24 h in idempotency_keys.response_body, and every person who may read the
-- operation saw it. Both copies are removed here. Copies may also live outside
-- these tables (agent session transcripts, client caches), so every enrollment
-- token that was not redeemed yet is retired as well: an administrator issues
-- a new link with POST /api/v1/users/{user_id}/enrollment-token.
--
-- used_at is '' for an unused token; the value written here has the storage
-- time layout (2006-01-02T15:04:05.000Z).
UPDATE operations
   SET result = json_remove(result, '$.enrollment_token')
 WHERE action = 'host.users.create' AND result IS NOT NULL
   AND json_type(result, '$.enrollment_token') IS NOT NULL;

UPDATE idempotency_keys
   SET response_body = json_remove(response_body, '$.result.enrollment_token')
 WHERE response_body IS NOT NULL
   AND json_type(response_body, '$.result.enrollment_token') IS NOT NULL;

UPDATE one_time_tokens
   SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
 WHERE purpose = 'enroll' AND used_at = '';
