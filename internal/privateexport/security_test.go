// SPDX-License-Identifier: AGPL-3.0-only

package privateexport

import (
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

func TestPrivateExportAuditFailureDoesNotConsume(t *testing.T) {
	f := fixture(t)
	call, raw := prepare(t, f)
	defer clear(raw)
	if err := f.service.Finish(t.Context(), call, strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `CREATE TRIGGER test_deny_export_audit BEFORE INSERT ON audit_log WHEN NEW.action='private_export.consume'
			BEGIN SELECT RAISE(ABORT,'TEST-ONLY audit failure'); END;`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	secret, err := f.service.Consume(t.Context(), f.user, call.ExportID)
	if err == nil || !secret.IsEmpty() {
		secret.Clear()
		t.Fatal("audit failure exposed or consumed private material")
	}
	if err := f.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DROP TRIGGER test_deny_export_audit`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	secret, err = f.service.Consume(t.Context(), f.user, call.ExportID)
	if err != nil || secret.IsEmpty() {
		t.Fatal("failed audit did not roll back consumption")
	}
	secret.Clear()
}

func TestPrivateExportQuotaAndCipherOwnerBinding(t *testing.T) {
	t.Run("quota", func(t *testing.T) {
		f := fixture(t)
		for range activeLimit {
			if _, err := f.service.Create(t.Context(), f.user, f.request); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.service.Create(t.Context(), f.user, f.request); !problem.HasCode(err, problem.RateLimited) {
			t.Fatal("active export quota was not enforced")
		}
	})
	t.Run("cipher owner", func(t *testing.T) {
		f := fixture(t)
		call, raw := prepare(t, f)
		defer clear(raw)
		if err := f.service.Finish(t.Context(), call, strings.Repeat("e", 64)); err != nil {
			t.Fatal(err)
		}
		if err := f.db.Update(t.Context(), func(tx *storage.Tx) error {
			_, err := tx.ExecContext(t.Context(), `UPDATE secrets SET owner='private_exports/foreign' WHERE owner=?`, secretOwner(call.ExportID))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		secret, err := f.service.Consume(t.Context(), f.user, call.ExportID)
		if err == nil || !secret.IsEmpty() {
			secret.Clear()
			t.Fatal("foreign cipher owner was revealed")
		}
	})
}

func TestPrivateExportSurvivesMasterKeyRotation(t *testing.T) {
	f := fixture(t)
	call, raw := prepare(t, f)
	defer clear(raw)
	if _, err := f.secrets.Keys().Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.secrets.Rotate(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Finish(t.Context(), call, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	secret, err := f.service.Consume(t.Context(), f.user, call.ExportID)
	if err != nil || secret.Len() != len(raw) {
		t.Fatal("encrypted export was lost after master key rotation")
	}
	secret.Clear()
}
