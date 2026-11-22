// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

const referenceEditSchema = `{"type":"object","properties":{"fresh":{"type":"string","x-secret":true},"token":{"type":"string","x-secret":true}}}`

func countSecretRows(t *testing.T, db *storage.DB) int {
	t.Helper()
	var count int
	if err := db.Reader().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM secrets").Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// ======================== 引用保留与事务归属校验 ========================

func TestExistingConfigReferencesStayOwnedAndAreNotReencrypted(t *testing.T) {
	s, db, _ := newTestStore(t)
	ref := mustPut(t, s, db, "plugins/demo", "plugin.config", []byte(`"saved"`))
	input, err := json.Marshal(map[string]any{"token": RefObject(ref), "fresh": "added"})
	if err != nil {
		t.Fatal(err)
	}
	opts := ExtractOptions{Owner: "plugins/demo", Purpose: "plugin.config", AllowExistingReferences: true}
	output, created, err := s.ExtractSecrets(t.Context(), []byte(referenceEditSchema), input, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 || created[0].Pointer != "/fresh" || countSecretRows(t, db) != 2 {
		t.Fatal("existing reference was reencrypted or included in new-reference cleanup")
	}
	var decoded map[string]any
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatal(err)
	}
	if got, ok := RefFromObject(decoded["token"]); !ok || got != ref {
		t.Fatal("configuration edit replaced the existing reference")
	}
	second, created, err := s.ExtractSecrets(t.Context(), []byte(referenceEditSchema), output, opts)
	if err != nil || len(created) != 0 || string(second) != string(output) || countSecretRows(t, db) != 2 {
		t.Fatalf("unchanged configuration created new secrets: %v", err)
	}
}

func TestForeignOrUnmarkedReferencesCannotCreateSecrets(t *testing.T) {
	for _, scenario := range []string{"default", "foreign-owner", "foreign-purpose", "missing", "unmarked", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			s, db, _ := newTestStore(t)
			ref := mustPut(t, s, db, "plugins/demo", "plugin.config", []byte(`"saved"`))
			opts := ExtractOptions{Owner: "plugins/demo", Purpose: "plugin.config", AllowExistingReferences: true}
			input := map[string]any{"fresh": "must-rollback", "token": RefObject(ref)}
			want := problem.NotFound
			switch scenario {
			case "default":
				opts.AllowExistingReferences, want = false, problem.ValidationFailed
			case "foreign-owner":
				opts.Owner = "plugins/other"
			case "foreign-purpose":
				opts.Purpose = "plugin.operation"
			case "missing":
				input["token"] = RefObject(Ref("sec_00000000000000000000000000"))
			case "unmarked":
				input["extra"], input["token"], want = RefObject(ref), "plain", problem.ValidationFailed
			case "malformed":
				input["token"], want = map[string]any{RefKey: string(ref), "extra": true}, problem.ValidationFailed
			}
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = s.ExtractSecrets(t.Context(), []byte(referenceEditSchema), raw, opts)
			if !problem.HasCode(err, want) {
				t.Fatalf("reference error = %v, want %s", err, want)
			}
			if countSecretRows(t, db) != 1 {
				t.Fatal("rejected reference left newly created ciphertext behind")
			}
		})
	}
}

// ======================== 批量解密只能使用宿主显式范围 ========================

func TestResolveSecretsRequiresExactOwnerAndPurposes(t *testing.T) {
	s, db, _ := newTestStore(t)
	config := mustPut(t, s, db, "plugins/demo", "plugin.config", []byte(`"config-value"`))
	operation := mustPut(t, s, db, "plugins/demo", "plugin.operation", []byte(`"operation-value"`))
	raw, err := json.Marshal([]any{RefObject(config), RefObject(operation)})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := s.ResolveSecrets(t.Context(), raw, "plugins/demo", "plugin.config", "plugin.operation")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(resolved)
	if string(resolved) != `["config-value","operation-value"]` {
		t.Fatal("allowed owned references did not resolve")
	}
	for _, test := range []struct {
		owner    string
		purposes []string
		want     problem.Code
	}{
		{"plugins/other", []string{"plugin.config", "plugin.operation"}, problem.NotFound},
		{"plugins/demo", []string{"plugin.config"}, problem.NotFound},
		{"plugins/demo", []string{"*"}, problem.ValidationFailed},
		{"plugins/demo", nil, problem.ValidationFailed},
		{"", []string{"plugin.config"}, problem.ValidationFailed},
	} {
		result, err := s.ResolveSecrets(t.Context(), raw, test.owner, test.purposes...)
		clear(result)
		if !problem.HasCode(err, test.want) {
			t.Fatalf("resolve outside explicit scope = %v, want %s", err, test.want)
		}
	}
	if _, err := s.ResolveSecrets(t.Context(), []byte(`{"$secret":"invalid","extra":true}`), "plugins/demo", "plugin.config"); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("malformed reference resolved silently: %v", err)
	}
}

func TestClientReferenceScanIsBoundedAndAllowsOrdinaryText(t *testing.T) {
	for _, raw := range []string{`{"plain":"$secret"}`, `{"nested":[1,true,"safe"]}`} {
		if err := RejectClientReferences([]byte(raw)); err != nil {
			t.Fatalf("ordinary input rejected: %v", err)
		}
	}
	for _, raw := range []string{`{"nested":[{"$secret":"invalid"}]}`, strings.Repeat("[", maxSchemaDepth+2) + "0" + strings.Repeat("]", maxSchemaDepth+2)} {
		if err := RejectClientReferences([]byte(raw)); !problem.HasCode(err, problem.ValidationFailed) {
			t.Fatalf("unbounded or reserved input accepted: %v", err)
		}
	}
}
