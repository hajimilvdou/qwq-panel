// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/qwq-panel/qwq/internal/storage"
)

// pruneBatch bounds one Prune step, like the operations sweeper's batches: a
// host with a long backlog catches up over several ticks.
const pruneBatch = 500

// Prune removes rows that can no longer be used (OPS-05): sessions whose
// expiry, idle deadline or revocation is older than the retention window,
// one-time tokens that were redeemed or expired, and expired MFA challenges.
// The operations sweeper calls it on its own tick, so identity starts no timer.
// Every step is one short transaction and never touches a usable credential.
func (s *Service) Prune(ctx context.Context, now time.Time) error {
	now = now.UTC().Truncate(time.Millisecond)
	cutoff := formatTime(now.Add(-s.sessionRetention))
	current := formatTime(now)

	sessions, err := s.pruneRows(ctx, `DELETE FROM sessions WHERE session_id IN (
		SELECT session_id FROM sessions
		WHERE expires_at <= ? OR idle_expires_at <= ? OR (revoked_at <> '' AND revoked_at <= ?)
		ORDER BY expires_at LIMIT ?)`, cutoff, cutoff, cutoff)
	if err != nil {
		return err
	}
	tokens, err := s.pruneRows(ctx, `DELETE FROM one_time_tokens WHERE token_id IN (
		SELECT token_id FROM one_time_tokens WHERE used_at <> '' OR expires_at <= ?
		ORDER BY expires_at LIMIT ?)`, current)
	if err != nil {
		return err
	}
	challenges, err := s.pruneRows(ctx, `DELETE FROM mfa_challenges WHERE id_hash IN (
		SELECT id_hash FROM mfa_challenges WHERE expires_at <= ? ORDER BY expires_at LIMIT ?)`, current)
	if err != nil {
		return err
	}
	pending, err := s.pruneRows(ctx, `DELETE FROM credentials WHERE credential_id IN (
		SELECT credential_id FROM credentials WHERE type='totp_pending'
		AND json_extract(data, '$.expires_at') <= ? ORDER BY created_at LIMIT ?)`, current)
	if err != nil {
		return err
	}
	if sessions+tokens+challenges+pending > 0 {
		s.log.InfoContext(ctx, "identity: pruned expired rows",
			"sessions", sessions, "one_time_tokens", tokens, "mfa_challenges", challenges, "pending_totp", pending)
	}
	return nil
}

// pruneRows runs one bounded delete and returns how many rows it removed.
func (s *Service) pruneRows(ctx context.Context, query string, args ...any) (int, error) {
	var pruned int
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		out, err := tx.ExecContext(ctx, query, append(args, pruneBatch)...)
		if err != nil {
			return err
		}
		n, err := out.RowsAffected()
		pruned = int(n)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("identity: prune: %w", err)
	}
	return pruned, nil
}
