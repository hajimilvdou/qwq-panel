// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

// logsRunner records the journalctl invocation and replies with canned JSON.
type logsRunner struct {
	name string
	args []string
	out  string
	err  error
}

func (r *logsRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.name, r.args = name, args
	return r.out, r.err
}

const journalSample = `{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1700000000000000","MESSAGE":"hello","PRIORITY":"6"}
{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1700000001000000","MESSAGE":"boom","PRIORITY":"3"}
{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"1700000002000000","MESSAGE":"third","PRIORITY":"6"}`

// TestParseJournalPage: streams come from the priority, the page is bounded and
// reports truncation, and the cursor advances to the last returned line.
func TestParseJournalPage(t *testing.T) {
	page, err := parseJournalPage(journalSample, "", 2)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(page.Lines) != 2 || !page.Truncated || page.NextCursor != "c2" {
		t.Fatalf("page = %+v", page)
	}
	if page.Lines[0].Stream != "stdout" || page.Lines[1].Stream != "stderr" {
		t.Fatalf("streams = %+v", page.Lines)
	}
	if page.Lines[0].At == "" || !strings.HasPrefix(page.Lines[0].At, "2023-") {
		t.Fatalf("at = %q", page.Lines[0].At)
	}
	stderr, err := parseJournalPage(journalSample, "stderr", 10)
	if err != nil || len(stderr.Lines) != 1 || stderr.Lines[0].Line != "boom" {
		t.Fatalf("stderr page = %+v, %v", stderr, err)
	}
	// A byte-array MESSAGE (non-UTF-8 output) is decoded too.
	raw := `{"__CURSOR":"c9","__REALTIME_TIMESTAMP":"1700000000000000","MESSAGE":[104,105],"PRIORITY":6}`
	arr, err := parseJournalPage(raw, "", 10)
	if err != nil || len(arr.Lines) != 1 || arr.Lines[0].Line != "hi" {
		t.Fatalf("byte message = %+v, %v", arr, err)
	}
}

// TestJournalLineTruncation: one line never exceeds 4 KiB, and the cut stays on
// a rune boundary.
func TestJournalLineTruncation(t *testing.T) {
	long := strings.Repeat("é", 5000)
	raw := `{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1700000000000000","MESSAGE":` + quote(long) + `,"PRIORITY":"6"}`
	page, err := parseJournalPage(raw, "", 10)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	line := page.Lines[0].Line
	if len(line) > sandbox.MaxLogLineBytes {
		t.Fatalf("line = %d bytes, want at most %d", len(line), sandbox.MaxLogLineBytes)
	}
	if !utf8.ValidString(line) {
		t.Fatal("the cut broke a rune")
	}
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// TestLogsOnlyAddressesThePluginUnit: the helper builds every argument, so a
// request can neither name another unit nor inject a flag.
func TestLogsOnlyAddressesThePluginUnit(t *testing.T) {
	runner := &logsRunner{out: journalSample}
	srv, err := newHelperServer(defaultHelperConfig(), runner, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newHelperServer: %v", err)
	}
	resp := srv.logs(context.Background(), sandbox.HelperRequest{
		Op: sandbox.HelperOpLogs, ID: "acme.demo", Cursor: "c1", Limit: 2, Stream: "stdout",
	})
	if !resp.OK || resp.Logs == nil {
		t.Fatalf("response = %+v", resp)
	}
	if runner.name != "journalctl" {
		t.Fatalf("command = %q", runner.name)
	}
	joined := strings.Join(runner.args, " ")
	if !strings.Contains(joined, "--unit=qwq-plugin@acme.demo.service") ||
		!strings.Contains(joined, "--after-cursor=c1") || !strings.Contains(joined, "--output=json") {
		t.Fatalf("args = %v", runner.args)
	}
	for _, bad := range []string{"Acme.evil", "../evil", "-x", "a b"} {
		if resp := srv.logs(context.Background(), sandbox.HelperRequest{Op: sandbox.HelperOpLogs, ID: bad}); resp.OK {
			t.Fatalf("id %q was accepted", bad)
		}
	}
	if resp := srv.logs(context.Background(), sandbox.HelperRequest{
		Op: sandbox.HelperOpLogs, ID: "acme.demo", Cursor: "--file=/etc/shadow",
	}); resp.OK {
		t.Fatal("a flag-shaped cursor was accepted")
	}
	if resp := srv.logs(context.Background(), sandbox.HelperRequest{
		Op: sandbox.HelperOpLogs, ID: "acme.demo", Stream: "journal",
	}); resp.OK {
		t.Fatal("an unknown stream was accepted")
	}
}

// TestValidJournalCursor covers the cursor grammar.
func TestValidJournalCursor(t *testing.T) {
	for _, ok := range []string{"", "s=abc;i=1;b=2;m=3;t=4;x=5"} {
		if !validJournalCursor(ok) {
			t.Errorf("cursor %q was refused", ok)
		}
	}
	for _, bad := range []string{"-n", "a b", "a\nb", strings.Repeat("a", 513)} {
		if validJournalCursor(bad) {
			t.Errorf("cursor %q was accepted", bad)
		}
	}
}
