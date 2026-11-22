// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"strings"
	"testing"
	"time"
)

func TestAttachLogsRateLimitsPerPlugin(t *testing.T) {
	env := newEnv(t, func(o *Options) {
		o.LogLinesPerSecond = 2
		o.LogBytesPerSecond = 1 << 20
	})

	detach := env.sup.AttachLogs("alpha", "stdout", strings.NewReader("one\ntwo\nthree\nfour\nfive\n"))
	detach()

	lines := env.logs.recordsWithMessage("plugin output")
	if len(lines) != 2 {
		t.Fatalf("logged lines = %d, want 2 (budget)", len(lines))
	}
	for _, r := range lines {
		if got := recordAttr(t, r, "plugin_id").String(); got != "alpha" {
			t.Fatalf("plugin_id = %q", got)
		}
		if got := recordAttr(t, r, "stream").String(); got != "stdout" {
			t.Fatalf("stream = %q", got)
		}
		if recordAttr(t, r, "truncated").Bool() {
			t.Fatal("short line reported as truncated")
		}
	}
	if got := recordAttr(t, lines[0], "line").String(); got != "one" {
		t.Fatalf("first line = %q", got)
	}

	// The next window reports what it dropped, then logs again.
	env.clock.Advance(2 * time.Second)
	detach = env.sup.AttachLogs("alpha", "stderr", strings.NewReader("six\n"))
	detach()

	summaries := env.logs.recordsWithMessage("plugin output was rate limited")
	if len(summaries) != 1 {
		t.Fatalf("rate limit summaries = %d, want 1", len(summaries))
	}
	if got := recordAttr(t, summaries[0], "dropped_lines").Int64(); got != 3 {
		t.Fatalf("dropped_lines = %d, want 3", got)
	}
	if got := recordAttr(t, summaries[0], "dropped_bytes").Int64(); got <= 0 {
		t.Fatalf("dropped_bytes = %d, want > 0", got)
	}
	if lines := env.logs.recordsWithMessage("plugin output"); len(lines) != 3 {
		t.Fatalf("logged lines after the new window = %d, want 3", len(lines))
	}
}

func TestAttachLogsTruncatesLongLines(t *testing.T) {
	env := newEnv(t)
	long := strings.Repeat("x", 2*maxLogLine)

	detach := env.sup.AttachLogs("alpha", "stdout", strings.NewReader("short\n"+long+"\n"))
	detach()

	lines := env.logs.recordsWithMessage("plugin output")
	if len(lines) != 2 {
		t.Fatalf("logged lines = %d, want 2", len(lines))
	}
	if got := recordAttr(t, lines[0], "line").String(); got != "short" {
		t.Fatalf("first line = %q", got)
	}
	if got := len(recordAttr(t, lines[1], "line").String()); got != maxLogLine {
		t.Fatalf("long line length = %d, want %d", got, maxLogLine)
	}
	if !recordAttr(t, lines[1], "truncated").Bool() {
		t.Fatal("the long line is not marked truncated")
	}
}

func TestAttachLogsRejectsInvalidPluginID(t *testing.T) {
	env := newEnv(t)
	detach := env.sup.AttachLogs("../alpha", "stdout", strings.NewReader("line\n"))
	detach()
	if lines := env.logs.recordsWithMessage("plugin output"); len(lines) != 0 {
		t.Fatalf("invalid plugin id produced %d log records", len(lines))
	}
}

func TestAttachLogsNoReader(t *testing.T) {
	env := newEnv(t)
	detach := env.sup.AttachLogs("alpha", "stdout", nil)
	detach() // must not panic
}
