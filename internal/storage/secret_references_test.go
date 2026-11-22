// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretReferenceMigrationAndSharedRetention 从真实旧 schema 升级，固定历史回填、
// AAD 材料保留、共享引用、默认 token 槽与删除事务的行为；不把合成密文当加密验证。
func TestSecretReferenceMigrationAndSharedRetention(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	old, err := Open(ctx, Options{Path: path, Migrations: migrationsBefore(t, 18)})
	if err != nil {
		t.Fatal(err)
	}
	const user = "usr_00000000000000000000000001"
	const ciphertext = "TEST-ONLY-migration-ciphertext"
	err = old.Update(ctx, func(tx *Tx) error {
		now := FormatTime(tx.Now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO users
			(user_id, username, display_name, role, created_at, updated_at) VALUES (?, 'alice', 'Alice', 'admin', ?, ?)`, user, now, now); err != nil {
			return err
		}
		for _, row := range []struct{ id, owner, purpose string }{
			{"sec_totp_live", "system", "identity.totp"},
			{"sec_totp_orphan", "users/" + user, "identity.totp"},
			{"sec_config_live", "plugins/alpha", "plugin.config"},
			{"sec_config_orphan", "plugins/alpha", "plugin.config"},
			{"sec_operation_live", "plugins/alpha", "plugin.operation"},
			{"sec_key_keep", "system", "operation.fingerprint"},
			{"sec_provider_keep", "providers/default", "ai.provider"},
		} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO secrets
				(id, owner, purpose, key_id, nonce, ciphertext, created_at) VALUES (?, ?, ?, 'key-fixture', ?, ?, ?)`,
				row.id, row.owner, row.purpose, []byte("TEST-ONLY-nonce"), []byte(ciphertext), now); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO credentials
			(credential_id, user_id, type, secret, created_at, updated_at)
			VALUES ('cred_fixture', ?, 'totp', 'sec_totp_live', ?, ?)`, user, now, now); err != nil {
			return err
		}
		for _, revision := range []int{1, 2} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_configs
				(plugin_id, revision, config_json, created_at) VALUES ('alpha', ?, '{"password":{"$secret":"sec_config_live"}}', ?)`, revision, now); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO plans
			(plan_id, action, action_meta, target, args, args_digest, plannable, changes, changes_truncated,
			 violations, warnings, preconditions, effective_risk, requires_approval, requires_mfa, executable,
			 actor_kind, actor_id, created_at, expires_at, revision)
			VALUES ('pln_fixture', 'alpha.write', '{}', '{"plugin_id":"alpha"}',
			 '{"password":{"$secret":"sec_operation_live"}}', 'digest', 1, '[]', 0, '[]', '[]', '[]',
			 'high', 1, 0, 1, 'human', ?, ?, ?, 0)`, user, now, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO operations
			(operation_id, action, action_meta, status, target, plugin_id, actor_kind, actor_id,
			 effective_risk, declared_risk, effect, mode, args, args_digest, timeout_ms, created_at, updated_at, revision, plan_id)
			VALUES ('op_fixture', 'alpha.write', '{}', 'SUCCEEDED', '{"plugin_id":"alpha"}', 'alpha', 'human', ?,
			 'high', 'high', 'write', 'invoke', '{"password":{"$secret":"sec_operation_live"}}', 'digest', 1000, ?, ?, 0, 'pln_fixture')`, user, now, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO plugin_credentials (plugin_id, token_sha256, issued_at) VALUES ('alpha', ?, ?)`, strings.Repeat("a", 64), now)
		return err
	})
	closeErr := old.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	upgraded, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	assertCount := func(query string, want int) {
		t.Helper()
		var count int
		if err := upgraded.Reader().QueryRowContext(ctx, query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("migration/lifecycle count=%d, want=%d", count, want)
		}
	}
	assertCount(`SELECT COUNT(*) FROM secret_references`, 5)
	assertCount(`SELECT COUNT(*) FROM secrets`, 5)
	var stored []byte
	var previous string
	if err := upgraded.Reader().QueryRowContext(ctx, `SELECT ciphertext FROM secrets WHERE id='sec_totp_live'`).Scan(&stored); err != nil || !bytes.Equal(stored, []byte(ciphertext)) {
		t.Fatal("migration changed existing ciphertext")
	}
	if err := upgraded.Reader().QueryRowContext(ctx, `SELECT prev_token_sha256 FROM plugin_credentials WHERE plugin_id='alpha'`).Scan(&previous); err != nil || previous != "" {
		t.Fatal("the compatibility token slot changed existing authentication data")
	}
	rollback := errors.New("TEST-ONLY-resource-delete-rollback")
	if err := upgraded.Update(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_configs`); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal("resource deletion did not roll back")
	}
	assertCount(`SELECT COUNT(*) FROM secret_references`, 5)
	for _, step := range []struct {
		delete, retained string
		count            int
	}{
		{`DELETE FROM plans`, `SELECT COUNT(*) FROM secrets WHERE id='sec_operation_live'`, 1},
		{`DELETE FROM operations`, `SELECT COUNT(*) FROM secrets WHERE id='sec_operation_live'`, 0},
		{`DELETE FROM plugin_configs WHERE revision=1`, `SELECT COUNT(*) FROM secrets WHERE id='sec_config_live'`, 1},
		{`DELETE FROM plugin_configs`, `SELECT COUNT(*) FROM secrets WHERE id='sec_config_live'`, 0},
		{`DELETE FROM users`, `SELECT COUNT(*) FROM secrets WHERE id='sec_totp_live'`, 0},
	} {
		if err := upgraded.Update(ctx, func(tx *Tx) error {
			_, err := tx.ExecContext(ctx, step.delete)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		assertCount(step.retained, step.count)
	}
	assertCount(`SELECT COUNT(*) FROM secret_references`, 0)
	assertCount(`SELECT COUNT(*) FROM secrets`, 2)
}

func TestSecretMigrationRollsBackWhenOldConfigurationCannotBeInspected(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "malformed-config.db")
	oldMigrations := migrationsBefore(t, 18)
	old, err := Open(ctx, Options{Path: path, Migrations: oldMigrations})
	if err != nil {
		t.Fatal(err)
	}
	err = old.Update(ctx, func(tx *Tx) error {
		now := FormatTime(tx.Now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO secrets
			(id, owner, purpose, key_id, nonce, ciphertext, created_at)
			VALUES ('sec_fixture', 'plugins/alpha', 'plugin.config', 'key-fixture', ?, ?, ?)`,
			[]byte("TEST-ONLY-nonce"), []byte("TEST-ONLY-ciphertext"), now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO plugin_configs
			(plugin_id, revision, config_json, created_at) VALUES ('alpha', 1, 'TEST-ONLY-malformed-JSON', ?)`, now)
		return err
	})
	closeErr := old.Close()
	if err != nil || closeErr != nil {
		t.Fatal("legacy fixture could not be saved")
	}
	if failed, err := Open(ctx, Options{Path: path}); err == nil {
		_ = failed.Close()
		t.Fatal("uninspectable legacy data was treated as having no secret references")
	}
	reopened, err := Open(ctx, Options{Path: path, Migrations: oldMigrations, NoMigrate: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	for query, want := range map[string]int{
		`SELECT COUNT(*) FROM secrets`:                                                                1,
		`SELECT COUNT(*) FROM sqlite_schema WHERE name='secret_references'`:                           0,
		`SELECT COUNT(*) FROM pragma_table_info('plugin_credentials') WHERE name='prev_token_sha256'`: 0,
	} {
		var count int
		if err := reopened.Reader().QueryRowContext(ctx, query).Scan(&count); err != nil || count != want {
			t.Fatal("failed migration changed secrets or partially committed its schema")
		}
	}
}
