// SPDX-License-Identifier: AGPL-3.0-only

package gateway_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// testHub opens a real database-backed journal and runs a hub on it. The SSE
// endpoint is tested against the production path: commit -> storage watermark ->
// hub tail loop -> SSE frame.
func testHub(t *testing.T, cfg events.Config) (*storage.DB, *events.Hub) {
	t.Helper()
	db, err := storage.Open(context.Background(), storage.Options{
		Path:  filepath.Join(t.TempDir(), "qwq.db"),
		Clock: clock.System{},
	})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if cfg.Journal == nil {
		cfg.Journal = db
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	hub, err := events.New(cfg)
	if err != nil {
		t.Fatalf("events.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		hub.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		hub.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("event hub did not stop")
		}
	})
	return db, hub
}

// streamGateway builds a gateway whose event stream reads the given hub.
func streamGateway(t *testing.T, hub *events.Hub, mutate func(*gateway.Config)) *gateway.Gateway {
	t.Helper()
	cfg := testConfig(nil)
	cfg.Events = hub
	cfg.Visibility = events.AllowAll
	if mutate != nil {
		mutate(&cfg)
	}
	return newGateway(t, cfg)
}

// appendEvent writes one journal event and returns its sequence.
func appendEvent(t *testing.T, db *storage.DB, typ, subject, payload string) int64 {
	t.Helper()
	var seq int64
	ctx := context.Background()
	err := db.Update(ctx, func(tx *storage.Tx) error {
		var err error
		seq, err = tx.AppendEvent(ctx, storage.Event{
			Type:          typ,
			SchemaVersion: "1",
			Subject:       subject,
			Payload:       json.RawMessage(payload),
		})
		return err
	})
	if err != nil {
		t.Fatalf("append event: %v", err)
	}
	return seq
}

// appendResourceChanged writes a resource.changed event through Tx.Changed, the
// path every real modification takes.
func appendResourceChanged(t *testing.T, db *storage.DB, subject string) int64 {
	t.Helper()
	ctx := context.Background()
	var revision int64
	err := db.Update(ctx, func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{
			Actor:       actor.Actor{Kind: actor.AIAgent, ID: "dlg_1", OnBehalfOf: "usr_alice"},
			OperationID: "op_00000000000000000000000000",
			TraceID:     "4bf92f3577b34da6a3ce929d0e0e4736",
		})
		var err error
		revision, err = tx.Changed(ctx, storage.Change{
			Subject:  subject,
			Kind:     storage.Updated,
			Pointers: []string{"/name"},
		})
		return err
	})
	if err != nil {
		t.Fatalf("resource.changed: %v", err)
	}
	return revision
}

// sseFrame is one parsed SSE frame.
type sseFrame struct {
	Event string
	ID    string
	Data  string
	Retry string
}

type sseClient struct {
	resp   *http.Response
	frames chan sseFrame
}

// dialSSE opens the event stream. A non-200 answer is returned to the caller.
func dialSSE(t *testing.T, srv *httptest.Server, path string, hdr http.Header) (*sseClient, *http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: gateway.SessionCookieName, Value: sessionToken})
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("dial event stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, resp, body
	}
	c := &sseClient{resp: resp, frames: make(chan sseFrame, 64)}
	go c.read()
	t.Cleanup(func() { _ = resp.Body.Close() })
	return c, resp, nil
}

// mustDialSSE opens the stream and fails the test on a non-200 answer.
func mustDialSSE(t *testing.T, srv *httptest.Server, hdr http.Header) *sseClient {
	t.Helper()
	c, resp, body := dialSSE(t, srv, "/api/v1/events", hdr)
	if c == nil {
		t.Fatalf("event stream status = %d, body %s", resp.StatusCode, body)
	}
	return c
}

func (c *sseClient) read() {
	defer close(c.frames)
	br := bufio.NewReader(c.resp.Body)
	var frame sseFrame
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			if frame != (sseFrame{}) {
				c.frames <- frame
				frame = sseFrame{}
			}
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			frame.Event = value
		case "id":
			frame.ID = value
		case "data":
			frame.Data = value
		case "retry":
			frame.Retry = value
		}
	}
}

func (c *sseClient) next(t *testing.T) sseFrame {
	t.Helper()
	select {
	case f, ok := <-c.frames:
		if !ok {
			t.Fatal("event stream closed while waiting for a frame")
		}
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an SSE frame")
		return sseFrame{}
	}
}

// nextDomain returns the next domain event frame, skipping heartbeats.
func (c *sseClient) nextDomain(t *testing.T) sseFrame {
	t.Helper()
	for {
		f := c.next(t)
		if f.Event == "heartbeat" {
			continue
		}
		if f.Event != "" {
			t.Fatalf("unexpected control frame %q (%s)", f.Event, f.Data)
		}
		if f.ID == "" {
			t.Fatalf("domain frame without id: %+v", f)
		}
		return f
	}
}

// waitControl skips heartbeats until the named control frame arrives.
func (c *sseClient) waitControl(t *testing.T, name string) sseFrame {
	t.Helper()
	for {
		f := c.next(t)
		if f.Event == "heartbeat" {
			continue
		}
		if f.Event != name {
			t.Fatalf("frame %q (%s), want %q", f.Event, f.Data, name)
		}
		return f
	}
}

// waitClosed consumes frames until the server closes the stream.
func (c *sseClient) close(t *testing.T) {
	t.Helper()
	_ = c.resp.Body.Close()
}

func (c *sseClient) waitClosed(t *testing.T) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-c.frames:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("event stream did not close")
		}
	}
}

func TestStreamSendsReadyFirst(t *testing.T) {
	_, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c := mustDialSSE(t, srv, nil)
	ready := c.next(t)
	if ready.Event != "ready" {
		t.Fatalf("first frame = %+v, want ready", ready)
	}
	if ready.Retry != "1500" {
		t.Fatalf("retry = %q, want 1500", ready.Retry)
	}
	var payload gateway.StreamReady
	if err := json.Unmarshal([]byte(ready.Data), &payload); err != nil {
		t.Fatalf("ready data: %v", err)
	}
	if payload.HeadSequence != "0" {
		t.Fatalf("head_sequence = %q, want 0", payload.HeadSequence)
	}
	if payload.HeartbeatSeconds < 1 || payload.HeartbeatSeconds > 29 {
		t.Fatalf("heartbeat_seconds = %d, want 1..29", payload.HeartbeatSeconds)
	}
}

func TestStreamDeliversEventAndHeartbeat(t *testing.T) {
	db, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c := mustDialSSE(t, srv, nil)
	c.waitControl(t, "ready")

	beats := 0
	for beats == 0 {
		f := c.next(t)
		if f.Event == "heartbeat" {
			var hb gateway.StreamHeartbeat
			if err := json.Unmarshal([]byte(f.Data), &hb); err != nil {
				t.Fatalf("heartbeat data: %v", err)
			}
			if hb.ServerTime == "" {
				t.Fatalf("heartbeat without server_time: %s", f.Data)
			}
			beats++
		}
	}

	seq := appendResourceChanged(t, db, "users/usr_1")
	f := c.nextDomain(t)
	if f.ID != "1" {
		t.Fatalf("id = %q, want 1", f.ID)
	}
	var ev events.Event
	if err := json.Unmarshal([]byte(f.Data), &ev); err != nil {
		t.Fatalf("event data: %v", err)
	}
	if ev.Sequence != "1" || ev.Type != "resource.changed" || ev.Subject != "users/usr_1" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.DeliveryClass != "reliable" {
		t.Fatalf("delivery_class = %q", ev.DeliveryClass)
	}
	if ev.Actor.Kind != "ai_agent" || ev.Actor.OnBehalfOf != "usr_alice" {
		t.Fatalf("actor = %+v", ev.Actor)
	}
	if seq != 1 {
		t.Fatalf("journal sequence = %d", seq)
	}
	if strings.Contains(f.Data, "\n") {
		t.Fatalf("data is not one line: %q", f.Data)
	}
}

func TestStreamResumesFromLastEventID(t *testing.T) {
	db, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	for i := 0; i < 3; i++ {
		appendEvent(t, db, "operation.updated", "operations/op_1", `{}`)
	}
	c := mustDialSSE(t, srv, http.Header{"Last-Event-Id": {"1"}})
	c.waitControl(t, "ready")
	if got := c.nextDomain(t).ID; got != "2" {
		t.Fatalf("first replayed id = %q, want 2", got)
	}
	if got := c.nextDomain(t).ID; got != "3" {
		t.Fatalf("second replayed id = %q, want 3", got)
	}
}

func TestStreamResumePrefersHeaderOverQuery(t *testing.T) {
	db, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	for i := 0; i < 3; i++ {
		appendEvent(t, db, "operation.updated", "operations/op_1", `{}`)
	}
	c, resp, body := dialSSE(t, srv, "/api/v1/events?last_event_id=0", http.Header{"Last-Event-Id": {"2"}})
	if c == nil {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	c.waitControl(t, "ready")
	if got := c.nextDomain(t).ID; got != "3" {
		t.Fatalf("id = %q, want only event 3", got)
	}
}

func TestStreamResumeFromZeroReplaysEverything(t *testing.T) {
	db, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	for i := 0; i < 2; i++ {
		appendEvent(t, db, "operation.updated", "operations/op_1", `{}`)
	}
	c, resp, body := dialSSE(t, srv, "/api/v1/events?last_event_id=0", nil)
	if c == nil {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	c.waitControl(t, "ready")
	if got := c.nextDomain(t).ID; got != "1" {
		t.Fatalf("id = %q, want 1", got)
	}
	if got := c.nextDomain(t).ID; got != "2" {
		t.Fatalf("id = %q, want 2", got)
	}
}

func TestStreamResyncAfterRetention(t *testing.T) {
	db, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	for i := 0; i < 5; i++ {
		appendEvent(t, db, "operation.updated", "operations/op_1", `{}`)
	}
	// Keep only the newest two events: the oldest retained sequence becomes 4.
	if _, err := db.PruneEvents(context.Background(), 2, -time.Hour, 100); err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}

	c := mustDialSSE(t, srv, http.Header{"Last-Event-Id": {"1"}})
	first := c.next(t)
	if first.Event != "resync" {
		t.Fatalf("first frame = %+v, want resync before ready", first)
	}
	var rs gateway.StreamResync
	if err := json.Unmarshal([]byte(first.Data), &rs); err != nil {
		t.Fatalf("resync data: %v", err)
	}
	if rs.Reason != events.ReasonRetentionExceeded {
		t.Fatalf("reason = %q", rs.Reason)
	}
	if rs.HeadSequence != "5" {
		t.Fatalf("head_sequence = %q, want 5", rs.HeadSequence)
	}
	c.waitControl(t, "ready")
}

func TestStreamResyncWhenClientIsAhead(t *testing.T) {
	_, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c := mustDialSSE(t, srv, http.Header{"Last-Event-Id": {"99"}})
	first := c.next(t)
	if first.Event != "resync" {
		t.Fatalf("first frame = %+v", first)
	}
	var rs gateway.StreamResync
	if err := json.Unmarshal([]byte(first.Data), &rs); err != nil {
		t.Fatalf("resync data: %v", err)
	}
	if rs.Reason != events.ReasonServerRestart {
		t.Fatalf("reason = %q", rs.Reason)
	}
}

func TestStreamTopicFilter(t *testing.T) {
	db, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c, resp, body := dialSSE(t, srv, "/api/v1/events?topics=operation.updated", nil)
	if c == nil {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	c.waitControl(t, "ready")

	appendEvent(t, db, "resource.changed", "users/usr_1", `{}`)
	appendEvent(t, db, "operation.updated", "operations/op_1", `{}`)

	f := c.nextDomain(t)
	if f.ID != "2" {
		t.Fatalf("id = %q, want the operation.updated event (2)", f.ID)
	}
	var ev events.Event
	if err := json.Unmarshal([]byte(f.Data), &ev); err != nil {
		t.Fatalf("event data: %v", err)
	}
	if ev.Type != "operation.updated" {
		t.Fatalf("type = %q", ev.Type)
	}
}

func TestStreamVisibilityIsEnforced(t *testing.T) {
	db, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, func(cfg *gateway.Config) {
		cfg.Visibility = func(_ actor.Actor, e events.Event) bool {
			return e.Subject == "users/visible"
		}
	})
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c := mustDialSSE(t, srv, nil)
	c.waitControl(t, "ready")
	appendEvent(t, db, "resource.changed", "users/hidden", `{}`)
	appendEvent(t, db, "resource.changed", "users/visible", `{}`)

	f := c.nextDomain(t)
	if f.ID != "2" {
		t.Fatalf("id = %q, want 2 (the visible subject)", f.ID)
	}
}

func TestStreamPerPrincipalLimit(t *testing.T) {
	_, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, func(cfg *gateway.Config) {
		cfg.Stream.MaxPerActor = 1
	})
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	first := mustDialSSE(t, srv, nil)
	first.waitControl(t, "ready")

	_, resp, body := dialSSE(t, srv, "/api/v1/events", nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	var p problem.Problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode problem: %v (%s)", err, body)
	}
	if p.Code != problem.RateLimited {
		t.Fatalf("code = %q", p.Code)
	}
	if p.Limit == nil || p.Limit.Name != "sse_connections_per_principal" || p.Limit.Max != 1 {
		t.Fatalf("limit = %+v", p.Limit)
	}

	// Releasing the stream frees the slot again.
	first.close(t)
	waitFor(t, "stream slot release", func() bool {
		total, _ := g.StreamSlots()
		return total == 0
	})
	if c, resp, body := dialSSE(t, srv, "/api/v1/events", nil); c == nil {
		t.Fatalf("second stream status = %d, body %s", resp.StatusCode, body)
	}
}

func TestStreamRejectsBadResumeSequence(t *testing.T) {
	_, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c, resp, body := dialSSE(t, srv, "/api/v1/events", http.Header{"Last-Event-Id": {"abc"}})
	if c != nil {
		t.Fatal("stream was opened with an invalid Last-Event-ID")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var p problem.Problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Violations[0].Pointer != "/Last-Event-ID" || p.Violations[0].In != "header" {
		t.Fatalf("violation = %+v", p.Violations[0])
	}
}

func TestStreamRejectsForeignOrigin(t *testing.T) {
	_, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c, resp, _ := dialSSE(t, srv, "/api/v1/events", http.Header{"Origin": {"https://evil.example"}})
	if c != nil {
		t.Fatal("cross-origin stream was accepted")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestStreamRequiresAuthentication(t *testing.T) {
	_, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/events", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestStreamClosesOnGatewayShutdown(t *testing.T) {
	_, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c := mustDialSSE(t, srv, nil)
	c.waitControl(t, "ready")
	g.Close()
	c.waitClosed(t)
}

func TestStreamOverflowSendsResyncAndCloses(t *testing.T) {
	db, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, func(cfg *gateway.Config) {
		cfg.Limits.SSEBufferEvents = 2
	})
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c := mustDialSSE(t, srv, nil)
	c.waitControl(t, "ready")

	payload := `{"blob":"` + strings.Repeat("x", 2048) + `"}`
	ctx := context.Background()
	err := db.Update(ctx, func(tx *storage.Tx) error {
		for i := 0; i < 120; i++ {
			if _, err := tx.AppendEvent(ctx, storage.Event{
				Type: "resource.changed", SchemaVersion: "1", Subject: "users/usr_1",
				Payload: json.RawMessage(payload),
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("append events: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case f, ok := <-c.frames:
			if !ok {
				t.Fatal("stream closed without a resync frame")
			}
			if f.Event != "resync" {
				continue
			}
			var rs gateway.StreamResync
			if err := json.Unmarshal([]byte(f.Data), &rs); err != nil {
				t.Fatalf("resync data: %v", err)
			}
			if rs.Reason != events.ReasonBufferOverflow {
				t.Fatalf("reason = %q, want buffer_overflow", rs.Reason)
			}
			c.waitClosed(t)
			return
		case <-deadline:
			t.Fatal("timed out waiting for the overflow resync")
		}
	}
}

// TestAIModificationReachesStreamWithinOneSecond is ADR-0004 acceptance 2 on the
// gateway side: a change committed by an AI actor must arrive on an already open
// stream in under a second.
func TestAIModificationReachesStreamWithinOneSecond(t *testing.T) {
	db, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c := mustDialSSE(t, srv, nil)
	c.waitControl(t, "ready")

	start := time.Now()
	revision := appendResourceChanged(t, db, "nodes/local")
	f := c.nextDomain(t)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("event took %v to reach the stream, want under 1s", elapsed)
	}

	var ev struct {
		Sequence string `json:"sequence"`
		Type     string `json:"type"`
		Subject  string `json:"subject"`
		Payload  struct {
			Revision        string   `json:"revision"`
			Kind            string   `json:"kind"`
			ChangedPointers []string `json:"changed_pointers"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(f.Data), &ev); err != nil {
		t.Fatalf("event data: %v", err)
	}
	if ev.Type != "resource.changed" || ev.Subject != "nodes/local" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Payload.Revision != f.ID || ev.Payload.Revision != strconv.FormatInt(revision, 10) {
		t.Fatalf("revision %q != sequence %q", ev.Payload.Revision, f.ID)
	}
	if ev.Payload.Kind != "update" {
		t.Fatalf("kind = %q", ev.Payload.Kind)
	}
	if len(ev.Payload.ChangedPointers) != 1 || ev.Payload.ChangedPointers[0] != "/name" {
		t.Fatalf("changed_pointers = %v", ev.Payload.ChangedPointers)
	}
}

// TestStreamSurvivesServerReadTimeout: an HTTP/1.1 stream must outlive the
// server's whole-request ReadTimeout; the handler lifts the read deadline.
func TestStreamSurvivesServerReadTimeout(t *testing.T) {
	_, hub := testHub(t, events.Config{Buffer: 16, MaxSubscribers: 8})
	g := streamGateway(t, hub, func(c *gateway.Config) { c.Stream.Heartbeat = 100 * time.Millisecond })
	srv := httptest.NewUnstartedServer(g)
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	c := mustDialSSE(t, srv, nil)
	c.waitControl(t, "ready")
	beats := 0
	deadline := time.After(1500 * time.Millisecond)
	for {
		select {
		case f, ok := <-c.frames:
			if !ok {
				t.Fatalf("stream closed after %d heartbeats", beats)
			}
			if f.Event == "heartbeat" {
				beats++
			}
		case <-deadline:
			if beats < 8 {
				t.Fatalf("heartbeats = %d, want >= 8", beats)
			}
			return
		}
	}
}
