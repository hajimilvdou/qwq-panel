// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/storage"
)

func TestCapabilitySessionFactsExcludeRevokedExpiredAndForeignUsers(t *testing.T) {
	db := testDB(t)
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	stamp := storage.FormatTime(now)
	err := db.Update(t.Context(), func(tx *storage.Tx) error {
		for _, user := range []struct {
			id, name string
			disabled int
		}{{"usr_a", "alice", 0}, {"usr_b", "bob", 0}, {"usr_c", "disabled", 1}} {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO users(user_id,username,role,disabled,created_at,updated_at) VALUES (?,?,'admin',?,?,?)`, user.id, user.name, user.disabled, stamp, stamp); err != nil {
				return err
			}
		}
		for index, session := range []struct {
			user, ip, revoked string
			expired           bool
		}{
			{"usr_a", "192.0.2.1", "", false}, {"usr_a", "::ffff:192.0.2.1", "", false}, {"usr_a", "2001:db8::1", "", false},
			{"usr_a", "192.0.2.2", stamp, false}, {"usr_a", "192.0.2.3", "", true}, {"usr_b", "192.0.2.4", "", false}, {"usr_c", "192.0.2.5", "", false},
		} {
			id := string(rune('a' + index))
			digest := sha256.Sum256([]byte("TEST-ONLY-session-" + id))
			expires := now.Add(time.Hour)
			if session.expired {
				expires = now.Add(-time.Hour)
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO sessions(session_id,user_id,token_hash,csrf_token,created_at,last_seen_at,idle_expires_at,expires_at,revoked_at,client_ip)
				VALUES (?,?,?,'TEST-ONLY-csrf',?,?,?,?,?,?)`, id, session.user, digest[:], stamp, stamp, storage.FormatTime(expires), storage.FormatTime(expires), session.revoked, session.ip); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := activeSessionAddresses(context.Background(), db, "usr_a", now)
	if err != nil || !slices.Equal(addresses, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatal("management address facts included expired, revoked or foreign sessions")
	}
	addresses, err = activeSessionAddresses(t.Context(), db, "usr_c", now)
	if err != nil || len(addresses) != 0 {
		t.Fatal("disabled owner retained session facts")
	}
	if err := db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE sessions SET client_ip='invalid' WHERE session_id='a'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := activeSessionAddresses(t.Context(), db, "usr_a", now); err == nil {
		t.Fatal("invalid address was silently accepted")
	}
}
