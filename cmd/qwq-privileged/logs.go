// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// logs reads one page of a plugin unit's journal (GAPS gap 7). Every journalctl
// argument is built here: the request supplies only an id, a cursor, a stream
// and a count, so a caller can neither address another unit nor inject a flag.
// The unit is always qwq-plugin@<id>.service, and the helper's socket activation
// and sandbox are unchanged — this verb only reads.
func (s *helperServer) logs(ctx context.Context, req sandbox.HelperRequest) sandbox.HelperResponse {
	if err := sandbox.ValidateID(req.ID); err != nil {
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	switch req.Stream {
	case "", "stdout", "stderr":
	default:
		return helperFailure(problem.ValidationFailed, "stream must be stdout or stderr.")
	}
	limit := req.Limit
	if limit <= 0 {
		limit = sandbox.DefaultLogLines
	}
	limit = min(limit, sandbox.MaxLogLines)
	if !validJournalCursor(req.Cursor) {
		return helperFailure(problem.ValidationFailed, "The cursor is not a journald cursor.")
	}
	unit, _, err := sandbox.UnitNames(req.ID)
	if err != nil {
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	// One extra entry tells whether more is available without a second call.
	args := []string{"--unit=" + unit, "--output=json", "--no-pager", "-n", strconv.Itoa(limit + 1)}
	if req.Cursor != "" {
		// One argument: the value can never become a flag of its own.
		args = append(args, "--after-cursor="+req.Cursor)
	}
	out, err := s.runner.Run(ctx, "journalctl", args...)
	if err != nil {
		s.logger.Error("journalctl failed", "id", req.ID, "err", err)
		return helperFailure(problem.Unavailable,
			fmt.Sprintf("The journal of plugin %s could not be read.", req.ID))
	}
	page, err := parseJournalPage(out, req.Stream, limit)
	if err != nil {
		s.logger.Error("journal page could not be parsed", "id", req.ID, "err", err)
		return helperFailure(problem.Internal,
			fmt.Sprintf("The journal of plugin %s could not be parsed.", req.ID))
	}
	return sandbox.HelperResponse{OK: true, Logs: &page}
}

// validJournalCursor accepts the journald cursor grammar (s=…;i=…;b=…;m=…;t=…;
// x=…) and the empty cursor. It is defense in depth: the value is passed as part
// of one --after-cursor argument, so it cannot become a flag either way.
func validJournalCursor(c string) bool {
	if c == "" {
		return true
	}
	if len(c) > 512 || c[0] == '-' {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			ch == '=' || ch == ';' || ch == ':' || ch == '.' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

// journalEntry is the subset of journald's JSON export the page needs. MESSAGE
// is a string for UTF-8 text and an array of bytes otherwise.
type journalEntry struct {
	Cursor    string          `json:"__CURSOR"`
	Timestamp string          `json:"__REALTIME_TIMESTAMP"`
	Message   json.RawMessage `json:"MESSAGE"`
	Priority  json.RawMessage `json:"PRIORITY"`
}

// parseJournalPage turns journalctl --output=json into one page. systemd writes
// a unit's stdout at LOG_INFO and its stderr at LOG_ERR, so the priority is what
// distinguishes the two streams; a requested stream filters the page.
func parseJournalPage(out, stream string, limit int) (sandbox.LogResult, error) {
	page := sandbox.LogResult{Lines: []sandbox.LogLine{}}
	entries := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e journalEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return sandbox.LogResult{}, err
		}
		entries++
		if entries > limit {
			page.Truncated = true
			break
		}
		at, err := journalTime(e.Timestamp)
		if err != nil {
			return sandbox.LogResult{}, err
		}
		text, err := journalMessage(e.Message)
		if err != nil {
			return sandbox.LogResult{}, err
		}
		lineStream := "stdout"
		if journalPriority(e.Priority) <= 3 {
			lineStream = "stderr"
		}
		// 游标代表实际扫描进度；过滤展示行不能让下一次请求重复读这一页。
		page.NextCursor = e.Cursor
		if stream != "" && stream != lineStream {
			continue
		}
		page.Lines = append(page.Lines, sandbox.LogLine{At: at, Stream: lineStream, Line: text})
	}
	return page, nil
}

// journalTime converts journald's microsecond epoch to RFC 3339 in UTC.
func journalTime(usec string) (string, error) {
	n, err := strconv.ParseInt(usec, 10, 64)
	if err != nil {
		return "", fmt.Errorf("timestamp %q: %w", usec, err)
	}
	return time.UnixMicro(n).UTC().Format(time.RFC3339Nano), nil
}

// journalMessage decodes MESSAGE and truncates it at the line limit on a rune
// boundary, so a plugin cannot blow up one response with a single line.
func journalMessage(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		var bytes []byte
		if err2 := json.Unmarshal(raw, &bytes); err2 != nil {
			return "", err
		}
		text = string(bytes)
	}
	if len(text) <= sandbox.MaxLogLineBytes {
		return text, nil
	}
	cut := sandbox.MaxLogLineBytes
	for cut > 0 && text[cut]&0xC0 == 0x80 {
		cut--
	}
	return text[:cut], nil
}

// journalPriority reads PRIORITY, which journald exports as a string or a
// number; an absent priority is informational.
func journalPriority(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 6
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
	}
	return 6
}
