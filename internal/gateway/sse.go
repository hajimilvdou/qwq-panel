// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// defaultSSETopics is the subscription applied when `topics` is absent
// (openapi.yaml: resource.changed,operation.updated).
func defaultSSETopics() []string {
	return []string{"resource.changed", "operation.updated"}
}

// StreamReady is the `event: ready` data (StreamReady in the public schema).
type StreamReady struct {
	HeadSequence     string `json:"head_sequence"`
	HeartbeatSeconds int    `json:"heartbeat_seconds"`
}

// StreamHeartbeat is the `event: heartbeat` data.
type StreamHeartbeat struct {
	HeadSequence string `json:"head_sequence"`
	ServerTime   string `json:"server_time"`
}

// StreamResync is the `event: resync` data.
type StreamResync struct {
	Reason       string   `json:"reason"`
	HeadSequence string   `json:"head_sequence"`
	Topics       []string `json:"topics,omitempty"`
}

// streamEvents serves GET /api/v1/events: one SSE connection to the event hub.
//
// Frames follow openapi.yaml (StreamFrame):
//   - domain events: `id: <sequence>` and one `data:` line, no `event:` line,
//     so EventSource.onmessage receives them;
//   - `event: ready` first (with the head sequence), then `event: heartbeat`
//     every heartbeat interval (< 30 s);
//   - `event: resync` when the requested sequence is older than retention or
//     when this connection's bounded buffer overflowed, in which case the
//     stream closes afterwards.
func (g *Gateway) streamEvents(w http.ResponseWriter, r *http.Request) {
	if g.cfg.Events == nil {
		g.writeProblem(w, r, problem.New(problem.Unavailable, "The event stream is not available."))
		return
	}
	principal, ok := PrincipalFrom(r.Context())
	if !ok {
		g.writeProblem(w, r, problem.New(problem.Unauthenticated, "The request has no credentials."))
		return
	}
	topics, err := ParseTopics(r.URL.Query()["topics"], g.limits.SSETopicsMax)
	if err != nil {
		g.writeProblem(w, r, err)
		return
	}
	if len(topics) == 0 {
		topics = defaultSSETopics()
	}
	since, err := resumeSequence(r)
	if err != nil {
		g.writeProblem(w, r, err)
		return
	}

	key := string(principal.Actor.Kind) + ":" + principal.Actor.ID
	if !g.streams.acquire(key, g.stream.MaxPerActor) {
		e := problem.New(problem.RateLimited, "Too many event streams are open for this principal.")
		e.RetryAfterSec = 5
		e.Limit = &problem.Limit{Name: "sse_connections_per_principal", Max: int64(g.stream.MaxPerActor)}
		g.writeProblem(w, r, e)
		return
	}
	defer g.streams.release(key)

	sub, start, err := g.cfg.Events.Subscribe(r.Context(), events.SubscribeOptions{
		Filter:     events.Filter{Topics: topics},
		Visibility: g.cfg.Visibility,
		Actor:      principal.Actor,
		Since:      since,
		Buffer:     g.limits.SSEBufferEvents,
	})
	if err != nil {
		if errors.Is(err, events.ErrTooManySubscribers) || errors.Is(err, events.ErrClosed) {
			e := problem.New(problem.Unavailable, "The event stream is at capacity; retry shortly.")
			e.RetryAfterSec = 5
			g.writeProblem(w, r, e)
			return
		}
		g.writeProblem(w, r, problem.Wrap(err))
		return
	}
	defer sub.Close()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	rc, done := PrepareStream(w)
	defer done()
	_ = rc.Flush()

	sw := NewSSEWriter(w, g.stream.WriteTimeout)
	if start.Resync {
		// The task requires the resync before anything else: a client that
		// missed the retention window must reload its snapshots before it acts
		// on the frames that follow.
		if err := sw.Control("resync", StreamResync{
			Reason:       start.Reason,
			HeadSequence: strconv.FormatInt(start.Head, 10),
			Topics:       topics,
		}, 0); err != nil {
			return
		}
	}
	// StreamReady.heartbeat_seconds is 1..29: round up so a sub-second test
	// interval still reports a valid value.
	heartbeatSeconds := int((g.stream.Heartbeat + time.Second - 1) / time.Second)
	if heartbeatSeconds < 1 {
		heartbeatSeconds = 1
	}
	if err := sw.Control("ready", StreamReady{
		HeadSequence:     strconv.FormatInt(start.Head, 10),
		HeartbeatSeconds: heartbeatSeconds,
	}, g.stream.RetryMS); err != nil {
		return
	}

	heartbeat := g.clock.After(g.stream.Heartbeat)
	var heartbeatCount int
	sseCreds := credentialsFrom(r)
	sseCreds.NoTouch = true
	for {
		select {
		case e, ok := <-sub.Events():
			if !ok {
				if sub.Overflowed() {
					_ = sw.Control("resync", StreamResync{
						Reason:       events.ReasonBufferOverflow,
						HeadSequence: strconv.FormatInt(g.cfg.Events.Head(), 10),
						Topics:       topics,
					}, 0)
				}
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				g.log.ErrorContext(r.Context(), "encode event", slog.Any("error", err))
				return
			}
			if err := sw.Event(e.Sequence, data); err != nil {
				return
			}
		case <-heartbeat:
			heartbeatCount++
			if heartbeatCount%2 == 0 && g.cfg.Auth != nil && sseCreds.Session != "" {
				if _, aerr := g.cfg.Auth.Authenticate(r.Context(), sseCreds); aerr != nil {
					_ = sw.Control("session.expired", map[string]string{"reason": "session_invalid"}, 0)
					return
				}
			}
			if err := sw.Control("heartbeat", StreamHeartbeat{
				HeadSequence: strconv.FormatInt(g.cfg.Events.Head(), 10),
				ServerTime:   formatTimestamp(g.clock.Now()),
			}, 0); err != nil {
				return
			}
			heartbeat = g.clock.After(g.stream.Heartbeat)
		case <-r.Context().Done():
			return
		case <-g.closing:
			return
		}
	}
}

// resumeSequence returns the sequence to resume after, or -1 for a stream that
// starts live. The Last-Event-ID header wins over the query parameter, matching
// EventSource reconnects.
func resumeSequence(r *http.Request) (int64, error) {
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, ok := ParseSequence(v)
		if !ok {
			return 0, badRequest("header", "/Last-Event-ID", "INVALID",
				"Last-Event-ID must be a decimal event sequence.")
		}
		return n, nil
	}
	if v := r.URL.Query().Get("last_event_id"); v != "" {
		n, ok := ParseSequence(v)
		if !ok {
			return 0, badRequest("query", "/last_event_id", "INVALID",
				"last_event_id must be a decimal event sequence.")
		}
		return n, nil
	}
	return -1, nil
}

// PrepareStream readies a long-lived response (an SSE stream). It lifts the
// whole-request read deadline that Server.ReadTimeout armed: on HTTP/1.1 the
// background read would otherwise hit it and cancel the request context, so a
// stream would drop every ReadTimeout. The returned done clears the per-frame
// write deadline when the handler ends, so it does not leak into the next
// request on the same keep-alive connection.
func PrepareStream(w http.ResponseWriter) (rc *http.ResponseController, done func()) {
	rc = http.NewResponseController(w)
	// ErrNotSupported (httptest.ResponseRecorder) is fine: there is no
	// deadline to lift.
	_ = rc.SetReadDeadline(time.Time{})
	return rc, func() { _ = rc.SetWriteDeadline(time.Time{}) }
}

// SSEWriter writes one frame per call, flushes it and bounds the write with a
// deadline so a client that stops reading cannot pin the connection.
type SSEWriter struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
	buf     bytes.Buffer
}

// NewSSEWriter wraps a stream response. frameTimeout bounds each frame write;
// zero leaves writes unbounded. Call PrepareStream on w first.
func NewSSEWriter(w http.ResponseWriter, frameTimeout time.Duration) *SSEWriter {
	return &SSEWriter{w: w, rc: http.NewResponseController(w), timeout: frameTimeout}
}

// Event writes a domain event frame. The data is one line of JSON and the id is
// the event sequence, so Last-Event-ID works.
func (s *SSEWriter) Event(id string, data []byte) error {
	s.buf.Reset()
	s.buf.WriteString("id: ")
	s.buf.WriteString(id)
	s.buf.WriteString("\ndata: ")
	s.buf.Write(data)
	s.buf.WriteString("\n\n")
	return s.flush()
}

// Control writes a named frame (ready, heartbeat, resync). retryMS, when
// positive, adds the reconnect delay.
func (s *SSEWriter) Control(event string, payload any, retryMS int) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	s.buf.Reset()
	if retryMS > 0 {
		fmt.Fprintf(&s.buf, "retry: %d\n", retryMS)
	}
	s.buf.WriteString("event: ")
	s.buf.WriteString(event)
	s.buf.WriteString("\ndata: ")
	s.buf.Write(data)
	s.buf.WriteString("\n\n")
	return s.flush()
}

func (s *SSEWriter) flush() error {
	if s.timeout > 0 {
		// ErrNotSupported is fine: the test recorder and some wrappers have no
		// deadline support, and the write itself still bounds the loop.
		_ = s.rc.SetWriteDeadline(time.Now().Add(s.timeout))
	}
	if _, err := s.w.Write(s.buf.Bytes()); err != nil {
		return err
	}
	return s.rc.Flush()
}

// StreamSlots reports the event streams that are open now: the total and the
// number of distinct principals. It is for metrics and tests.
func (g *Gateway) StreamSlots() (total, principals int) { return g.streams.len() }

// streamLimiter bounds concurrent streams per principal and in total. Both map
// size and total are bounded, so a caller cannot grow host memory by
// reconnecting.
type streamLimiter struct {
	mu     sync.Mutex
	max    int
	total  int
	counts map[string]int
}

func newStreamLimiter(maxTotal int) *streamLimiter {
	return &streamLimiter{max: maxTotal, counts: make(map[string]int)}
}

func (l *streamLimiter) acquire(key string, perKey int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max > 0 && l.total >= l.max {
		return false
	}
	if perKey > 0 && l.counts[key] >= perKey {
		return false
	}
	l.counts[key]++
	l.total++
	return true
}

func (l *streamLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := l.counts[key]; n > 1 {
		l.counts[key] = n - 1
	} else {
		delete(l.counts, key)
	}
	if l.total > 0 {
		l.total--
	}
}

func (l *streamLimiter) len() (total, keys int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total, len(l.counts)
}
