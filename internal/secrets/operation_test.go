// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestOperationProtectorPersistenceAndOwnership(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	p, err := NewOperationProtector(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := NewOperationProtector(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("TEST-ONLY-operation-input")
	if p.Fingerprint("scope-a", raw) != p2.Fingerprint("scope-a", raw) {
		t.Fatal("fingerprint changed after reloading")
	}
	if p.Fingerprint("scope-a", raw) == p.Fingerprint("scope-b", raw) {
		t.Fatal("fingerprint scopes were not separated")
	}
	if _, err := s.Keys().Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate(ctx, 100); err != nil {
		t.Fatal(err)
	}
	p3, err := NewOperationProtector(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint("scope-a", raw) != p3.Fingerprint("scope-a", raw) {
		t.Fatal("master key rotation changed the request fingerprint")
	}
	const schema = `{"type":"object","properties":{"password":{"type":"string","writeOnly":true}}}`
	const input = `{"password":"TEST-ONLY-operation-password"}`
	protected, cleanup, err := p.Protect(ctx, []byte(schema), []byte(input), "plugins/security.basic", "plugin.operation")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protected, []byte("TEST-ONLY-operation-password")) {
		t.Fatal("protected arguments retained plaintext")
	}
	var doc map[string]any
	if err := json.Unmarshal(protected, &doc); err != nil {
		t.Fatal(err)
	}
	ref, ok := RefFromObject(doc["password"])
	if !ok {
		t.Fatal("protected argument is not a reference")
	}
	secret, err := s.RevealOwned(ctx, ref, "plugins/security.basic", "plugin.operation")
	if err != nil {
		t.Fatal(err)
	}
	secret.Clear()
	_, err = s.RevealOwned(ctx, ref, "plugins/core.xray", "plugin.operation")
	requireCode(t, err, problem.NotFound)
	_, err = s.RevealOwned(ctx, ref, "plugins/security.basic", "plugin.config")
	requireCode(t, err, problem.NotFound)
	if err := cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.Reader().QueryRowContext(ctx, "SELECT COUNT(*) FROM secrets WHERE purpose = ?", operationFingerprintPurpose).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("fingerprint key was duplicated or removed by argument cleanup")
	}
	_, err = s.RevealOwned(ctx, ref, "plugins/security.basic", "plugin.operation")
	requireCode(t, err, problem.NotFound)
}
