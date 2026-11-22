// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestConfigurationReferencesRetainSharedSecretsUntilLastDelete(t *testing.T) {
	ctx := t.Context()
	s, db, _ := newTestStore(t)
	const schema = `{"properties":{"password":{"writeOnly":true}}}`
	config, extracted, err := s.ExtractSecrets(ctx, []byte(schema), []byte(`{"password":"TEST-ONLY-config-lifecycle"}`), ExtractOptions{
		Owner: "plugins/alpha", Purpose: "plugin.config",
	})
	if err != nil || len(extracted) != 1 {
		t.Fatal("configuration secret extraction failed")
	}
	ref := extracted[0].Ref
	if err := db.Update(ctx, func(tx *storage.Tx) error {
		for _, revision := range []int{1, 2} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_configs
				(plugin_id, revision, config_json, created_at) VALUES ('alpha', ?, ?, ?)`,
				revision, string(config), storage.FormatTime(tx.Now())); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// 后端提交快照后再报错时，失败补偿必须保留已经绑定的密文。
	if err := s.DiscardExtracted(ctx, extracted); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("TEST-ONLY-config-delete-rollback")
	if err := db.Update(ctx, func(tx *storage.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_configs WHERE plugin_id='alpha'`); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal("configuration deletion did not roll back")
	}
	for _, revision := range []int{1, 2} {
		if err := db.Update(ctx, func(tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, `DELETE FROM plugin_configs WHERE plugin_id='alpha' AND revision=?`, revision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		value, err := s.RevealOwned(ctx, ref, "plugins/alpha", "plugin.config")
		value.Clear()
		if revision == 1 && err != nil {
			t.Fatal("retention of an older config deleted a shared secret")
		}
		if revision == 2 && !problem.HasCode(err, problem.NotFound) {
			t.Fatal("the last config deletion left orphan ciphertext")
		}
	}
	if err := s.DiscardExtracted(ctx, extracted); err != nil {
		t.Fatal("repeated compensation is not idempotent")
	}
}

func TestUnusedExtractionCompensationDeletesOnlyNewReferences(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	const schema = `{"properties":{"password":{"writeOnly":true}}}`
	_, extracted, err := s.ExtractSecrets(ctx, []byte(schema), []byte(`{"password":"TEST-ONLY-uncommitted"}`), ExtractOptions{
		Owner: "plugins/alpha", Purpose: "plugin.operation",
	})
	if err != nil || len(extracted) != 1 {
		t.Fatal("temporary extraction failed")
	}
	if err := s.DiscardExtracted(ctx, extracted); err != nil {
		t.Fatal(err)
	}
	_, err = s.RevealOwned(ctx, extracted[0].Ref, "plugins/alpha", "plugin.operation")
	if !problem.HasCode(err, problem.NotFound) {
		t.Fatal("unused operation extraction retained ciphertext")
	}
}
