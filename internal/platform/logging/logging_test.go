// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func decode(t *testing.T, b *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %v: %s", err, b.String())
	}
	return m
}

func TestFieldsAndContext(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, Options{Service: "controller"})
	ctx := With(context.Background(), slog.String(KeyOperationID, "op_1"), slog.String(KeyTraceID, "t1"))
	ctx = With(ctx, slog.String(KeyTraceID, "t2")) // replaces t1
	l.InfoContext(ctx, "started", "node_id", "local")

	m := decode(t, &buf)
	for k, want := range map[string]string{
		"service": "controller", "operation_id": "op_1", "trace_id": "t2", "node_id": "local", "msg": "started", "level": "INFO",
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %s", k, m[k], want)
		}
	}
	ts, _ := m["timestamp"].(string)
	if !strings.HasSuffix(ts, "Z") {
		t.Errorf("timestamp %q is not UTC RFC 3339", ts)
	}
	if _, ok := m["time"]; ok {
		t.Error("time key not renamed")
	}
}

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, Options{})
	l.Info("x",
		"password", "hunter2",
		"session_token", "abc",
		"Authorization", "Bearer xyz",
		"api-key", "k",
		"db", map[string]any{"ok": 1},
		slog.Group("smtp", slog.String("password", "p"), slog.String("host", "mail")),
		"wrapped", Secret("s3"),
		"token_expires_at", "2026-11-01", // last segment is "at": not a secret
		"idempotency_key", "idk_1", // identifiers are not secrets
	)
	out := buf.String()
	for _, leak := range []string{"hunter2", `"abc"`, "Bearer xyz", `"k"`, `"p"`, "s3"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %s: %s", leak, out)
		}
	}
	m := decode(t, &buf)
	if m["token_expires_at"] != "2026-11-01" || m["idempotency_key"] != "idk_1" {
		t.Errorf("over-redacted: %s", out)
	}
	if g, _ := m["smtp"].(map[string]any); g["host"] != "mail" || g["password"] != redacted {
		t.Errorf("group = %v", g)
	}
}

func TestTruncate(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, Options{})
	long := strings.Repeat("界", MaxValueLen) // 3 bytes per rune
	l.Info("x", "detail", long)
	m := decode(t, &buf)
	s := m["detail"].(string)
	if len(s) > MaxValueLen+64 || !strings.Contains(s, "truncated") {
		t.Fatalf("not truncated: %d bytes", len(s))
	}
	if !strings.HasPrefix(s, "界") || strings.ContainsRune(s, '\uFFFD') {
		t.Fatal("cut inside a rune")
	}
}

func TestLevelAndFormat(t *testing.T) {
	var buf bytes.Buffer
	lvl, err := ParseLevel("warn")
	if err != nil {
		t.Fatal(err)
	}
	l := New(&buf, Options{Level: lvl, Format: "text"})
	l.Info("hidden")
	l.Warn("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Fatalf("level filter: %s", buf.String())
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Fatal("ParseLevel accepted an unknown level")
	}
}
