// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/logging"
	"github.com/qwq-panel/qwq/internal/storage"
)

const canary = "log-leak-canary-value"

func TestSecretRedactsEveryStringForm(t *testing.T) {
	secret := newSecret([]byte(canary))
	// Format strings are variables so that staticcheck does not rewrite the
	// cases under test into String() calls.
	formatValue, formatString, formatGoSyntax := "%v", "%s", "%#v"
	forms := map[string]string{
		"String":     secret.String(),
		"Sprint":     fmt.Sprint(secret),
		"v":          fmt.Sprintf(formatValue, secret),
		"s":          fmt.Sprintf(formatString, secret),
		"#v":         fmt.Sprintf(formatGoSyntax, secret),
		"in a slice": fmt.Sprint([]any{secret}),
		"LogValue":   secret.LogValue().String(),
	}
	for name, form := range forms {
		if strings.Contains(form, canary) {
			t.Fatalf("%s leaks the plaintext: %q", name, form)
		}
		if !strings.Contains(form, redacted) {
			t.Fatalf("%s is not redacted: %q", name, form)
		}
	}

	if got := string(secret.Bytes()); got != canary {
		t.Fatalf("Bytes = %q", got)
	}
	if _, err := json.Marshal(secret); err == nil {
		t.Fatal("json.Marshal accepted secret material")
	}
	if secret.Len() != len(canary) || secret.IsEmpty() {
		t.Fatalf("Len = %d, IsEmpty = %v", secret.Len(), secret.IsEmpty())
	}
	secret.Clear()
	if !secret.IsEmpty() || secret.Len() != 0 {
		t.Fatalf("Clear left %d bytes", secret.Len())
	}
}

func TestStoreLogsNoPlaintext(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	log := logging.New(&buf, logging.Options{Level: slog.LevelDebug, Format: "json"})
	s, db, _ := newTestStoreWith(t, log)

	ref := mustPut(t, s, db, testOwner, testPurpose, []byte(canary))
	sealed, err := s.Seal(ctx, testPurpose, []byte(canary))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	secret, err := s.Reveal(ctx, ref, testPurpose)
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	log.Info("revealed a value", "value", secret)
	if _, err := s.Open(ctx, sealed); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Keys().Rotate(); err != nil {
		t.Fatalf("Rotate key: %v", err)
	}
	if _, err := s.Rotate(ctx, 1); err != nil {
		t.Fatalf("Rotate rows: %v", err)
	}
	if err := db.Update(ctx, func(tx *storage.Tx) error { return s.Delete(ctx, tx, ref) }); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	out := buf.String()
	if out == "" {
		t.Fatal("the store wrote no log records")
	}
	if strings.Contains(out, canary) {
		t.Fatalf("log output leaks the plaintext:\n%s", out)
	}
	if !strings.Contains(out, "sec_") {
		t.Fatalf("log output does not name references:\n%s", out)
	}
	if !strings.Contains(out, redacted) {
		t.Fatalf("log output does not use the redaction marker:\n%s", out)
	}
	if !strings.Contains(out, "key_id") {
		t.Fatalf("log output does not record the key id:\n%s", out)
	}
}

func TestSignatureOfLogFields(t *testing.T) {
	// A canary passed to the logger under a sensitive key is redacted by the
	// logging package, and the store never passes one anyway; this guards the
	// combination against a future refactor that logs the arguments directly.
	var buf bytes.Buffer
	log := logging.New(&buf, logging.Options{Level: slog.LevelDebug, Format: "json"})
	log.Info("store", "secret", canary, "password", canary)
	if strings.Contains(buf.String(), canary) {
		t.Fatalf("logger leaked the canary: %s", buf.String())
	}
}
