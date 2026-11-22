// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"
)

// ============================================================================
// 过滤后没有展示行也要推进实际扫描游标，否则客户端会反复读取同一页。
// ============================================================================

func TestFilteredJournalCursorAdvancesPastSkippedEntries(t *testing.T) {
	for _, test := range []struct {
		stream    string
		limit     int
		cursor    string
		lines     int
		truncated bool
	}{
		{"stderr", 1, "c1", 0, true},
		{"stderr", 3, "c3", 1, false},
		{"stdout", 2, "c2", 1, true},
	} {
		page, err := parseJournalPage(journalSample, test.stream, test.limit)
		if err != nil {
			t.Fatal(err)
		}
		if page.NextCursor != test.cursor || len(page.Lines) != test.lines || page.Truncated != test.truncated {
			t.Errorf("stream=%s limit=%d page=%+v; want cursor=%s lines=%d truncated=%v", test.stream, test.limit, page, test.cursor, test.lines, test.truncated)
		}
	}
	page, err := parseJournalPage(strings.Join(strings.Split(journalSample, "\n")[2:], "\n"), "stderr", 2)
	if err != nil || page.NextCursor != "c3" || len(page.Lines) != 0 {
		t.Fatalf("fully filtered page=%+v error=%v", page, err)
	}
}
