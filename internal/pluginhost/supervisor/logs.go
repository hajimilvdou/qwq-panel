// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"
)

const (
	// maxLogLine bounds one structured log record; longer plugin lines are
	// truncated so a crashing plugin cannot blow up a journal record.
	maxLogLine = 8 << 10
	// logWindow is the rate limiting window.
	logWindow = time.Second
	// logStopTimeout bounds how long Close waits for a log pump whose reader the
	// host did not close.
	logStopTimeout = 5 * time.Second
)

// logAttachment is one attached plugin output stream.
type logAttachment struct {
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

// stopWithin cancels the pump and waits for it. A zero timeout waits forever; the
// contract is that the caller closes the reader, which is the only way to
// interrupt a blocking Read on a stream the supervisor does not own.
func (a *logAttachment) stopWithin(timeout time.Duration) {
	a.once.Do(func() {
		a.cancel()
		if timeout <= 0 {
			<-a.done
			return
		}
		select {
		case <-a.done:
		case <-time.After(timeout):
		}
	})
}

func (a *logAttachment) stop() { a.stopWithin(0) }

// AttachLogs forwards plugin output (stdout/stderr obtained by the host, usually
// from journald) to the structured logger. It is not a protocol channel: lines
// are untrusted text, rate limited per plugin and never parsed as ABI messages.
//
// The budget is per plugin, shared by all its streams, and counts lines and
// bytes per second. Lines over the budget are dropped and counted; when the next
// window starts one summary record reports how much was dropped.
//
// The returned detach function stops reading and waits for the pump. The caller
// must close (or otherwise unblock) r: the supervisor does not own the reader and
// cannot interrupt a blocking Read.
func (s *Supervisor) AttachLogs(pluginID, stream string, r io.Reader) func() {
	if r == nil {
		return func() {}
	}
	if err := validatePluginID(pluginID); err != nil {
		s.logger.Warn("refusing to attach plugin output", "plugin_id", pluginID, "error", err)
		return func() {}
	}
	if stream == "" {
		stream = "stdout"
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return func() {}
	}
	limiter := s.limiters[pluginID]
	if limiter == nil {
		limiter = newLogLimiter(s.opts.LogLinesPerSecond, s.opts.LogBytesPerSecond)
		s.limiters[pluginID] = limiter
	}
	gen := ""
	if inst := s.instances[pluginID]; inst != nil {
		gen = inst.Generation()
	}
	ctx, cancel := context.WithCancel(s.rootCtx)
	attachment := &logAttachment{cancel: cancel, done: make(chan struct{})}
	s.logs = append(s.logs, attachment)
	s.mu.Unlock()

	go s.pumpLogs(ctx, attachment, limiter, pluginID, gen, stream, r)
	return func() {
		s.mu.Lock()
		for i, a := range s.logs {
			if a == attachment {
				s.logs = append(s.logs[:i], s.logs[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		attachment.stop()
	}
}

// pumpLogs reads lines until the reader ends or fails and applies the per-plugin
// log budget.
func (s *Supervisor) pumpLogs(ctx context.Context, attachment *logAttachment, limiter *logLimiter,
	pluginID, gen, stream string, r io.Reader) {
	defer close(attachment.done)
	err := readLines(r, maxLogLine, func(line []byte, truncated bool) {
		allowed, droppedLines, droppedBytes := limiter.reserve(s.clock.Now(), len(line)+1)
		if droppedLines > 0 || droppedBytes > 0 {
			s.logger.WarnContext(ctx, "plugin output was rate limited",
				"plugin_id", pluginID, "generation", gen, "stream", stream,
				"dropped_lines", droppedLines, "dropped_bytes", droppedBytes,
				"lines_per_second", s.opts.LogLinesPerSecond,
				"bytes_per_second", s.opts.LogBytesPerSecond)
		}
		if !allowed {
			return
		}
		s.logger.LogAttrs(ctx, slog.LevelInfo, "plugin output",
			slog.String("plugin_id", pluginID),
			slog.String("generation", gen),
			slog.String("stream", stream),
			slog.String("line", string(line)),
			slog.Bool("truncated", truncated),
		)
	})
	if err != nil && ctx.Err() == nil {
		s.logger.WarnContext(ctx, "reading plugin output failed",
			"plugin_id", pluginID, "stream", stream, "error", err)
	}
}

// readLines calls fn for every line of r, truncating lines longer than max. A
// final line without a newline is reported too.
func readLines(r io.Reader, max int, fn func(line []byte, truncated bool)) error {
	reader := bufio.NewReaderSize(r, 4096)
	line := make([]byte, 0, 256)
	truncated := false
	emit := func() {
		out := line
		if n := len(out); n > 0 && out[n-1] == '\n' {
			out = out[:n-1]
			if m := len(out); m > 0 && out[m-1] == '\r' {
				out = out[:m-1]
			}
		}
		fn(out, truncated)
		line = line[:0]
		truncated = false
	}
	for {
		fragment, err := reader.ReadSlice('\n')
		if !truncated && len(fragment) > 0 {
			if room := max - len(line); room > 0 {
				if len(fragment) > room {
					line = append(line, fragment[:room]...)
					truncated = true
				} else {
					line = append(line, fragment...)
				}
			} else {
				truncated = true
			}
		}
		switch {
		case err == nil:
			emit()
		case errors.Is(err, bufio.ErrBufferFull):
			// The line is longer than the buffer; keep filling up to max.
		case errors.Is(err, io.EOF):
			if len(line) > 0 || truncated {
				emit()
			}
			return nil
		default:
			return err
		}
	}
}

// logLimiter is a fixed window line and byte budget.
type logLimiter struct {
	mu       sync.Mutex
	maxLines int
	maxBytes int
	window   time.Time
	lines    int
	bytes    int
	dropped  int
	droppedB int
}

func newLogLimiter(maxLines, maxBytes int) *logLimiter {
	return &logLimiter{maxLines: maxLines, maxBytes: maxBytes}
}

// reserve reports whether a line of n bytes may be logged now. When the window
// rolls over it also returns how many lines and bytes were dropped in the window
// that just ended, so the caller can log one summary.
func (l *logLimiter) reserve(now time.Time, n int) (ok bool, droppedLines, droppedBytes int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.window.IsZero() || now.Before(l.window) || now.Sub(l.window) >= logWindow {
		droppedLines, droppedBytes = l.dropped, l.droppedB
		l.window = now
		l.lines, l.bytes = 0, 0
		l.dropped, l.droppedB = 0, 0
	}
	if l.lines+1 > l.maxLines || l.bytes+n > l.maxBytes {
		l.dropped++
		l.droppedB += n
		return false, droppedLines, droppedBytes
	}
	l.lines++
	l.bytes += n
	return true, droppedLines, droppedBytes
}
