// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// newAgentEnv builds the full host with a custom agent session service. The
// model endpoint is supplied through agentsession.Options.HTTPClient.
func newAgentEnv(t *testing.T, tune func(*agentsession.Options)) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.RunDir = filepath.Join(dir, "run")
	cfg.HTTP.PublicOrigins = []string{testOrigin}
	c, err := controller.New(t.Context(), controller.Options{Config: cfg})
	if err != nil {
		t.Fatalf("controller.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	clk := clock.System{}
	opts := agentsession.Options{
		DB: c.DB(), Clock: clk, IDs: ids.New(clk.Now),
		Logger: slog.New(slog.DiscardHandler), Secrets: c.Secrets(),
	}
	if tune != nil {
		tune(&opts)
	}
	svc, err := agentsession.New(opts)
	if err != nil {
		t.Fatalf("agentsession.New: %v", err)
	}
	t.Cleanup(svc.Close)
	deps := api.Deps{
		Config: c.Config(), DB: c.DB(), Clock: clk, IDs: ids.New(clk.Now),
		Logger: slog.New(slog.DiscardHandler), Identity: c.Identity(), Authz: c.Authorizer(),
		Ops: c.Operations(), Catalog: c.Catalog(), Secrets: c.Secrets(), TLS: c.TLS(),
		NodeID: "local", AgentSessions: svc,
	}
	if err := api.Register(c.Gateway(), deps); err != nil {
		t.Fatalf("api.Register: %v", err)
	}
	return &env{t: t, c: c}
}

// fakeModel is a minimal OpenAI-compatible endpoint for the API tests.
type fakeModel struct {
	mu       sync.Mutex
	calls    int
	reply    func(call int) string
	delay    time.Duration
	requests []map[string]any
	auth     []string
	srv      *httptest.Server
}

func newFakeModel(t *testing.T, delay time.Duration, reply func(call int) string) *fakeModel {
	t.Helper()
	m := &fakeModel{delay: delay, reply: reply}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		m.mu.Lock()
		call := m.calls
		m.calls++
		m.requests = append(m.requests, doc)
		m.auth = append(m.auth, r.Header.Get("Authorization"))
		m.mu.Unlock()
		if m.delay > 0 {
			select {
			case <-time.After(m.delay):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, m.reply(call))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

// authorizations returns the Authorization header of every request so far.
func (m *fakeModel) authorizations() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.auth...)
}

// textReply is a final-answer completion.
func textReply(text string) string {
	raw, _ := json.Marshal(text)
	return fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":%s},"finish_reason":"stop"}]}`, raw)
}

// configFor returns the native config of the fake model.
func configFor(url string) map[string]any {
	return map[string]any{"base_url": url, "model": "test-model"}
}

// createSession creates a session through the API and decodes it.
func createSession(t *testing.T, e *env, a auth, body map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp := e.do(a.sign(http.MethodPost, "/api/v1/agent-sessions", string(raw))).expect(t, http.StatusCreated)
	var out map[string]any
	resp.decode(t, &out)
	if mustString(t, out, "session_id") == "" {
		t.Fatalf("created session = %s", resp.body)
	}
	return out
}

// getSession loads one session through the API.
func getSession(t *testing.T, e *env, a auth, id string) map[string]any {
	t.Helper()
	resp := e.do(a.sign(http.MethodGet, "/api/v1/agent-sessions/"+id, "")).expect(t, http.StatusOK)
	var out map[string]any
	resp.decode(t, &out)
	return out
}

// sendMessage posts a user message.
func sendMessage(t *testing.T, e *env, a auth, id, content string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"content": content})
	resp := e.do(a.sign(http.MethodPost, "/api/v1/agent-sessions/"+id+"/messages", string(body))).expect(t, http.StatusCreated)
	var out map[string]any
	resp.decode(t, &out)
	return out
}

// waitSessionStatus polls the API until the session reaches status. The pause
// between polls grows: a session usually settles within milliseconds, and the
// gateway throttles a client that keeps polling faster than its sustained
// per-IP rate (gateway.DefaultPreAuthRate).
func waitSessionStatus(t *testing.T, e *env, a auth, id, status string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	pause := 5 * time.Millisecond
	var last map[string]any
	for time.Now().Before(deadline) {
		last = getSession(t, e, a, id)
		if last["status"] == status {
			return last
		}
		time.Sleep(pause)
		pause = min(2*pause, 200*time.Millisecond)
	}
	t.Fatalf("session %s never reached %s (last: %v)", id, status, last)
	return nil
}

// TestAgentSessionCRUD covers create, read, list, patch and delete.
func TestAgentSessionCRUD(t *testing.T) {
	model := newFakeModel(t, 0, func(int) string { return textReply("hi") })
	e := newAgentEnv(t, func(o *agentsession.Options) { o.HTTPClient = model.srv.Client() })
	admin := e.setupAdmin(adminUser)

	created := createSession(t, e, admin, map[string]any{
		"title": "Ops chat", "core": "native", "permission_mode": "safe", "config": configFor(model.srv.URL),
	})
	id := mustString(t, created, "session_id")
	if mustString(t, created, "title") != "Ops chat" || mustString(t, created, "status") != "idle" ||
		mustString(t, created, "core") != "native" || mustString(t, created, "permission_mode") != "safe" {
		t.Fatalf("created = %v", created)
	}
	if _, ok := created["config"].(map[string]any); !ok {
		t.Fatalf("config = %v", created["config"])
	}

	detail := getSession(t, e, admin, id)
	if msgs, ok := detail["messages"].([]any); !ok || len(msgs) != 0 {
		t.Fatalf("messages = %v", detail["messages"])
	}
	if approvals, ok := detail["approvals"].([]any); !ok || len(approvals) != 0 {
		t.Fatalf("approvals = %v", detail["approvals"])
	}
	if _, ok := detail["revision"].(string); !ok {
		t.Fatalf("detail has no revision: %v", detail)
	}

	// The list shows the session and supports the attention filter.
	resp := e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions", "")).expect(t, http.StatusOK)
	var page struct {
		Items      []map[string]any `json:"items"`
		Revision   string           `json:"revision"`
		NextCursor string           `json:"next_cursor"`
		Delta      bool             `json:"delta"`
	}
	resp.decode(t, &page)
	if len(page.Items) != 1 || page.Items[0]["session_id"] != id || page.Revision == "" || page.Delta {
		t.Fatalf("list = %+v", page)
	}
	att := e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions?status=attention", "")).expect(t, http.StatusOK)
	var attPage struct {
		Items []map[string]any `json:"items"`
	}
	att.decode(t, &attPage)
	if len(attPage.Items) != 0 {
		t.Fatalf("attention = %+v", attPage.Items)
	}
	badStatus := e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions?status=nope", "")).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if len(badStatus.Violations) == 0 || badStatus.Violations[0].Pointer != "/status" {
		t.Fatalf("violations = %+v", badStatus.Violations)
	}

	// PATCH changes the mode with the revision guard.
	revision := mustString(t, detail, "revision")
	body := fmt.Sprintf(`{"permission_mode":"full","title":"Renamed","expected_revision":%q}`, revision)
	patched := e.do(admin.sign(http.MethodPatch, "/api/v1/agent-sessions/"+id, body)).expect(t, http.StatusOK)
	var updated map[string]any
	patched.decode(t, &updated)
	if updated["permission_mode"] != "full" || updated["title"] != "Renamed" {
		t.Fatalf("patched = %v", updated)
	}
	e.do(admin.sign(http.MethodPatch, "/api/v1/agent-sessions/"+id, body)).
		expectProblem(t, http.StatusConflict, problem.RevisionConflict)
	e.do(admin.sign(http.MethodPatch, "/api/v1/agent-sessions/"+id, `{"permission_mode":"yolo","expected_revision":"`+revision+`"}`)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// Another principal (a service account) sees NOT_FOUND everywhere.
	token := e.serviceToken(admin)
	e.do(bearer(http.MethodGet, "/api/v1/agent-sessions/"+id, "", token)).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
	e.do(bearer(http.MethodPatch, "/api/v1/agent-sessions/"+id, `{"permission_mode":"read_only","expected_revision":"`+revision+`"}`, token)).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
	e.do(bearer(http.MethodDelete, "/api/v1/agent-sessions/"+id, "", token)).
		expectProblem(t, http.StatusNotFound, problem.NotFound)

	// DELETE answers 204 and the session disappears.
	e.do(admin.sign(http.MethodDelete, "/api/v1/agent-sessions/"+id, "")).expect(t, http.StatusNoContent)
	e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions/"+id, "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
}

// TestAgentSessionCreateValidation covers the rejected create bodies and the
// unavailability of an external core.
func TestAgentSessionCreateValidation(t *testing.T) {
	e := newAgentEnv(t, nil)
	admin := e.setupAdmin(adminUser)

	badMode := e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions", `{"permission_mode":"yolo"}`)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if !strings.Contains(badMode.Detail, "invalid") {
		t.Fatalf("detail = %q", badMode.Detail)
	}
	e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions", `{"core":"gpt"}`)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions", `{"config":{"api_key":"sk-live"}}`)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions", `{}`)).
		expect(t, http.StatusCreated)

	// An unconfigured native session answers 503 UNAVAILABLE on send.
	created := createSession(t, e, admin, map[string]any{})
	e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions/"+mustString(t, created, "session_id")+"/messages", `{"content":"hi"}`)).
		expectProblem(t, http.StatusServiceUnavailable, problem.Unavailable)
	// An external CLI core is not wired yet.
	cli := createSession(t, e, admin, map[string]any{"core": "codex"})
	e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions/"+mustString(t, cli, "session_id")+"/messages", `{"content":"hi"}`)).
		expectProblem(t, http.StatusServiceUnavailable, problem.Unavailable)
	// A concurrent send conflict needs a running turn; the 409 path is covered
	// by the cancel test.
}

// TestAgentSessionAPIKeyRoute covers PUT and DELETE
// /agent-sessions/{id}/api-key (AGT-02): the key reaches the model as the
// bearer token, while no response carries the key or a secret reference; only
// the owner can change it, a browser needs the CSRF token, and a session config
// can no longer name a secret.
func TestAgentSessionAPIKeyRoute(t *testing.T) {
	model := newFakeModel(t, 0, func(int) string { return textReply("hi") })
	e := newAgentEnv(t, func(o *agentsession.Options) { o.HTTPClient = model.srv.Client() })
	admin := e.setupAdmin(adminUser)
	created := createSession(t, e, admin, map[string]any{"config": configFor(model.srv.URL)})
	id := mustString(t, created, "session_id")
	if created["has_api_key"] != false {
		t.Fatalf("created session = %v", created)
	}
	path := "/api/v1/agent-sessions/" + id + "/api-key"
	const key = "sk-route-secret-value"
	body := `{"api_key":"` + key + `"}`
	noSecret := func(what string, r response) {
		t.Helper()
		if strings.Contains(string(r.body), "sk-route") || strings.Contains(string(r.body), "sec_") {
			t.Fatalf("%s leaks the key or its reference: %s", what, r.body)
		}
	}

	// Refused writes: no CSRF token, another principal, bad bodies.
	noCSRF := admin.sign(http.MethodPut, path, body)
	noCSRF.Header.Del("X-CSRF-Token")
	e.do(noCSRF).expectProblem(t, http.StatusForbidden, problem.CSRFFailed)
	other := e.serviceToken(admin)
	e.do(bearer(http.MethodPut, path, body, other)).expectProblem(t, http.StatusNotFound, problem.NotFound)
	e.do(bearer(http.MethodDelete, path, "", other)).expectProblem(t, http.StatusNotFound, problem.NotFound)
	e.do(admin.sign(http.MethodPut, path, `{"api_key":""}`)).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	e.do(admin.sign(http.MethodPut, path, `{"api_key":"`+key+`","extra":1}`)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	spaced := e.do(admin.sign(http.MethodPut, path, `{"api_key":"sk-route with space"}`))
	spaced.expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	noSecret("a refused PUT", spaced)

	// PUT stores the key; the session shows has_api_key and nothing else.
	put := e.do(admin.sign(http.MethodPut, path, body)).expect(t, http.StatusOK)
	noSecret("PUT", put)
	set := put.decodeMap(t)
	if set["has_api_key"] != true || set["revision"] == created["revision"] {
		t.Fatalf("PUT answer = %v", set)
	}
	detail := e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions/"+id, "")).expect(t, http.StatusOK)
	noSecret("GET", detail)
	if detail.decodeMap(t)["has_api_key"] != true {
		t.Fatalf("detail = %s", detail.body)
	}
	noSecret("the list", e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions", "")).expect(t, http.StatusOK))

	// The stored key is the bearer token of the next turn.
	sendMessage(t, e, admin, id, "hello")
	waitSessionStatus(t, e, admin, id, "idle")
	if auth := model.authorizations(); len(auth) != 1 || auth[0] != "Bearer "+key {
		t.Fatalf("authorization headers = %q", auth)
	}

	// DELETE removes it: the next turn sends no Authorization header.
	del := e.do(admin.sign(http.MethodDelete, path, "")).expect(t, http.StatusOK)
	noSecret("DELETE", del)
	if cleared := del.decodeMap(t); cleared["has_api_key"] != false {
		t.Fatalf("DELETE answer = %v", cleared)
	}
	sendMessage(t, e, admin, id, "again")
	waitSessionStatus(t, e, admin, id, "idle")
	if auth := model.authorizations(); len(auth) != 2 || auth[1] != "" {
		t.Fatalf("authorization headers after DELETE = %q", auth)
	}

	// A session config can no longer name a secret, whatever it points to.
	refused := e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions",
		`{"config":{"base_url":"https://x.test","model":"m","api_key_secret":"sec_0123456789abcdefghjkmnpqrs"}}`)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if len(refused.Violations) != 1 || refused.Violations[0].Pointer != "/config/api_key_secret" {
		t.Fatalf("violations = %+v", refused.Violations)
	}
}

// TestAgentSessionSendAndSSE covers the message flow and the stream framing.
func TestAgentSessionSendAndSSE(t *testing.T) {
	model := newFakeModel(t, 0, func(int) string { return textReply("model says hi") })
	e := newAgentEnv(t, func(o *agentsession.Options) { o.HTTPClient = model.srv.Client() })
	admin := e.setupAdmin(adminUser)
	created := createSession(t, e, admin, map[string]any{"config": configFor(model.srv.URL)})
	id := mustString(t, created, "session_id")

	sent := sendMessage(t, e, admin, id, "hello")
	if sent["message"] == nil {
		t.Fatalf("send response = %v", sent)
	}
	waitSessionStatus(t, e, admin, id, "idle")
	// A retried send with the same client_message_id returns the same seq.
	body := `{"content":"hello","client_message_id":"client-1"}`
	first := e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions/"+id+"/messages", body)).expect(t, http.StatusCreated)
	waitSessionStatus(t, e, admin, id, "idle")
	second := e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions/"+id+"/messages", body)).expect(t, http.StatusCreated)
	var firstOut, secondOut struct {
		Message struct {
			Seq int64 `json:"seq"`
		} `json:"message"`
	}
	first.decode(t, &firstOut)
	second.decode(t, &secondOut)
	if firstOut.Message.Seq == 0 || firstOut.Message.Seq != secondOut.Message.Seq {
		t.Fatalf("idempotent send seqs = %d / %d", firstOut.Message.Seq, secondOut.Message.Seq)
	}

	// The transcript holds user and assistant messages with content_json on the
	// assistant tool/answer step only.
	detail := getSession(t, e, admin, id)
	msgs, _ := detail["messages"].([]any)
	if len(msgs) < 4 {
		t.Fatalf("messages = %v", detail["messages"])
	}
	last, _ := msgs[len(msgs)-1].(map[string]any)
	if last["role"] != "assistant" || last["content"] != "model says hi" {
		t.Fatalf("last message = %v", last)
	}

	// Read the stream from the start: the ring replays the whole turn.
	ts := httptest.NewServer(e.c.Handler())
	defer ts.Close()
	frames := readSSE(t, ts.URL+"/api/v1/agent-sessions/"+id+"/events", admin, "0", 4)
	if frames[0].event != "ready" {
		t.Fatalf("first frame = %+v", frames[0])
	}
	var eventTypes []string
	for _, f := range frames[1:] {
		var ev map[string]any
		if err := json.Unmarshal(f.data, &ev); err != nil {
			t.Fatalf("frame data %s: %v", f.data, err)
		}
		eventTypes = append(eventTypes, ev["type"].(string))
		if f.id == "" {
			t.Fatalf("domain frame has no id: %+v", f)
		}
	}
	want := []string{"message.delta", "message.completed", "turn.completed"}
	if strings.Join(eventTypes, ",") != strings.Join(want, ",") {
		t.Fatalf("event types = %v, want %v", eventTypes, want)
	}

	// Reconnecting after the first event replays the rest, without a resync.
	replay := readSSE(t, ts.URL+"/api/v1/agent-sessions/"+id+"/events", admin, frames[1].id, 2)
	if replay[0].event != "ready" {
		t.Fatalf("replay first frame = %+v", replay[0])
	}
	var replayed string
	{
		var ev map[string]any
		if err := json.Unmarshal(replay[1].data, &ev); err != nil {
			t.Fatalf("replay data: %v", err)
		}
		replayed, _ = ev["type"].(string)
	}
	if replayed != "message.completed" {
		t.Fatalf("replay first domain event = %q, want message.completed", replayed)
	}

	// A stale position gets a resync frame instead of a partial replay.
	small := newAgentEnv(t, func(o *agentsession.Options) {
		o.HTTPClient = model.srv.Client()
		o.Config.RingSize = 2
	})
	admin2 := small.setupAdmin(adminUser)
	created2 := createSession(t, small, admin2, map[string]any{"config": configFor(model.srv.URL)})
	id2 := mustString(t, created2, "session_id")
	sendMessage(t, small, admin2, id2, "hello")
	waitSessionStatus(t, small, admin2, id2, "idle")
	ts2 := httptest.NewServer(small.c.Handler())
	defer ts2.Close()
	frames = readSSE(t, ts2.URL+"/api/v1/agent-sessions/"+id2+"/events", admin2, "1", 1)
	if frames[0].event != "resync" {
		t.Fatalf("stale position frame = %+v", frames[0])
	}
	var resync struct {
		Reason       string `json:"reason"`
		HeadSequence int64  `json:"head_sequence"`
	}
	if err := json.Unmarshal(frames[0].data, &resync); err != nil || resync.Reason != "out_of_window" || resync.HeadSequence == 0 {
		t.Fatalf("resync payload = %+v, %v", resync, err)
	}

	// Another principal cannot open the stream.
	other := e.serviceToken(admin)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/agent-sessions/"+id+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+other)
	badResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("other owner SSE: %v", err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusNotFound {
		t.Fatalf("other owner SSE status = %d", badResp.StatusCode)
	}
}

// sseFrame is one parsed SSE frame.
type sseFrame struct {
	id    string
	event string
	data  []byte
}

// readSSE opens the stream as a browser session and reads count frames.
func readSSE(t *testing.T, url string, a auth, lastEventID string, count int) []sseFrame {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new SSE request: %v", err)
	}
	req.Header.Set("Cookie", gateway.SessionCookieName+"="+a.cookie)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("SSE status = %d (%s)", resp.StatusCode, data)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		resp.Body.Close()
		t.Fatalf("SSE content type = %q", ct)
	}
	// Close before returning so that a deferred httptest.Server.Close in the
	// caller does not wait for this stream; the defer also runs when a frame
	// assertion fails.
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	out := make([]sseFrame, 0, count)
	for len(out) < count {
		out = append(out, readFrame(t, br))
	}
	return out
}

// readFrame reads one frame with a deadline.
func readFrame(t *testing.T, br *bufio.Reader) sseFrame {
	t.Helper()
	type result struct {
		frame sseFrame
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		var f sseFrame
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				ch <- result{err: err}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				ch <- result{frame: f}
				return
			}
			switch {
			case strings.HasPrefix(line, "id: "):
				f.id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "event: "):
				f.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				f.data = []byte(strings.TrimPrefix(line, "data: "))
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("read SSE frame: %v", r.err)
		}
		return r.frame
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading an SSE frame")
		return sseFrame{}
	}
}

// TestAgentSessionHeartbeat checks the heartbeat control frame.
func TestAgentSessionHeartbeat(t *testing.T) {
	e := newAgentEnv(t, func(o *agentsession.Options) { o.Config.Heartbeat = 20 * time.Millisecond })
	admin := e.setupAdmin(adminUser)
	created := createSession(t, e, admin, map[string]any{})
	id := mustString(t, created, "session_id")
	ts := httptest.NewServer(e.c.Handler())
	defer ts.Close()
	frames := readSSE(t, ts.URL+"/api/v1/agent-sessions/"+id+"/events", admin, "", 2)
	if frames[0].event != "ready" || frames[1].event != "heartbeat" {
		t.Fatalf("frames = %+v", frames)
	}
	var beat struct {
		HeadSequence int64  `json:"head_sequence"`
		ServerTime   string `json:"server_time"`
	}
	if err := json.Unmarshal(frames[1].data, &beat); err != nil || beat.ServerTime == "" {
		t.Fatalf("heartbeat = %+v, %v", beat, err)
	}
}

// TestAgentSessionCancelAndApprovals covers cancel and the pending approvals
// list through the API.
func TestAgentSessionCancelAndApprovals(t *testing.T) {
	model := newFakeModel(t, 0, func(call int) string {
		if call == 0 {
			return `{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"host_users_create","arguments":"{\"username\":\"bob\"}"}}]},"finish_reason":"tool_calls"}]}`
		}
		return textReply("done")
	})
	tools := []agentsession.ToolSpec{{
		Action: "host.users.create", Summary: "Create a user", Effect: "write", Risk: "high",
		Approval: "confirm", Description: "Creates a panel user.",
	}}
	runner := agentsession.RunnerFunc(func(ctx context.Context, call agentsession.ToolCall) (agentsession.ToolResult, error) {
		return agentsession.ToolResult{
			Status: agentsession.ToolAwaitingApproval,
			Approval: &agentsession.ApprovalInfo{
				ApprovalID: "apv_test", OperationID: "op_test", Summary: "Create a user",
				Description: "Creates a panel user.", Risk: "high", Approval: "confirm",
			},
		}, nil
	})
	e := newAgentEnv(t, func(o *agentsession.Options) {
		o.HTTPClient = model.srv.Client()
		o.Catalog = agentsession.StaticCatalog{Tools: tools}
		o.Runner = runner
	})
	admin := e.setupAdmin(adminUser)
	created := createSession(t, e, admin, map[string]any{"config": configFor(model.srv.URL)})
	id := mustString(t, created, "session_id")
	sub := readSSEStart(t, e, admin, id)
	sendMessage(t, e, admin, id, "create bob")
	waitSessionStatus(t, e, admin, id, "waiting_approval")

	// The pending approval is visible with the plugin text.
	resp := e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions/"+id+"/approvals", "")).expect(t, http.StatusOK)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	resp.decode(t, &list)
	if len(list.Items) != 1 {
		t.Fatalf("approvals = %+v", list.Items)
	}
	item := list.Items[0]
	if item["approval_id"] != "apv_test" || item["operation_id"] != "op_test" ||
		item["summary"] != "Create a user" || item["action"] != "host.users.create" {
		t.Fatalf("approval = %v", item)
	}
	if item["status"] != "awaiting_approval" || item["description"] == "" {
		t.Fatalf("approval = %v", item)
	}
	// A second send while waiting is a conflict.
	e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions/"+id+"/messages", `{"content":"again"}`)).
		expectProblem(t, http.StatusConflict, problem.StateConflict)

	// Cancel ends the paused turn; the pending list empties.
	cancelled := e.do(admin.sign(http.MethodPost, "/api/v1/agent-sessions/"+id+"/cancel", `{"reason":"stop"}`)).
		expect(t, http.StatusOK)
	var cancelledOut map[string]any
	cancelled.decode(t, &cancelledOut)
	if cancelledOut["status"] != "cancelled" {
		t.Fatalf("cancel response = %v", cancelledOut)
	}
	empty := e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions/"+id+"/approvals", "")).expect(t, http.StatusOK)
	var emptyList struct {
		Items []map[string]any `json:"items"`
	}
	empty.decode(t, &emptyList)
	if len(emptyList.Items) != 0 {
		t.Fatalf("approvals after cancel = %+v", emptyList.Items)
	}
	// The stream saw the approval and the cancellation.
	frames := drainSSE(t, sub, 6)
	var types []string
	for _, f := range frames {
		var ev map[string]any
		_ = json.Unmarshal(f.data, &ev)
		if typ, ok := ev["type"].(string); ok {
			types = append(types, typ)
		}
	}
	joined := strings.Join(types, ",")
	for _, want := range []string{"approval_required", "tool_result", "turn.completed"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("events = %v", types)
		}
	}
}

// sseStream is an open session stream.
type sseStream struct {
	frames chan sseFrame
	stop   func()
}

// readSSEStart opens a live stream in the background.
func readSSEStart(t *testing.T, e *env, a auth, id string) *sseStream {
	t.Helper()
	ts := httptest.NewServer(e.c.Handler())
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/agent-sessions/"+id+"/events", nil)
	if err != nil {
		t.Fatalf("new SSE request: %v", err)
	}
	req.Header.Set("Cookie", gateway.SessionCookieName+"="+a.cookie)
	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		ts.Close()
		t.Fatalf("SSE connect: %v", err)
	}
	out := &sseStream{frames: make(chan sseFrame, 16), stop: func() {
		cancel()
		resp.Body.Close()
		ts.Close()
	}}
	t.Cleanup(out.stop)
	go func() {
		defer close(out.frames)
		br := bufio.NewReader(resp.Body)
		for {
			var f sseFrame
			var ok bool
			f, ok = readFrameQuiet(br)
			if !ok {
				return
			}
			select {
			case out.frames <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// readFrameQuiet reads one frame without failing the test.
func readFrameQuiet(br *bufio.Reader) (sseFrame, bool) {
	var f sseFrame
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return sseFrame{}, false
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return f, true
		}
		switch {
		case strings.HasPrefix(line, "id: "):
			f.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			f.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			f.data = []byte(strings.TrimPrefix(line, "data: "))
		}
	}
}

// drainSSE collects n data frames (control frames are skipped).
func drainSSE(t *testing.T, s *sseStream, n int) []sseFrame {
	t.Helper()
	var out []sseFrame
	timeout := time.After(5 * time.Second)
	for len(out) < n {
		select {
		case f, ok := <-s.frames:
			if !ok {
				t.Fatalf("stream closed after %d frames", len(out))
			}
			if f.event != "" {
				continue
			}
			out = append(out, f)
		case <-timeout:
			t.Fatalf("timed out after %d frames", len(out))
		}
	}
	return out
}

// TestAgentStreamSurvivesServerReadTimeout: an HTTP/1.1 session stream must
// outlive the server's whole-request ReadTimeout.
func TestAgentStreamSurvivesServerReadTimeout(t *testing.T) {
	e := newAgentEnv(t, func(o *agentsession.Options) { o.Config.Heartbeat = 100 * time.Millisecond })
	admin := e.setupAdmin(adminUser)
	id := mustString(t, createSession(t, e, admin, map[string]any{}), "session_id")
	ts := httptest.NewUnstartedServer(e.c.Handler())
	ts.Config.ReadTimeout = 300 * time.Millisecond
	ts.Start()
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/agent-sessions/"+id+"/events", nil)
	if err != nil {
		t.Fatalf("new SSE request: %v", err)
	}
	req.Header.Set("Cookie", gateway.SessionCookieName+"="+admin.cookie)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE status = %d", resp.StatusCode)
	}
	br := bufio.NewReader(resp.Body)
	beats := 0
	for end := time.Now().Add(1500 * time.Millisecond); time.Now().Before(end); {
		if readFrame(t, br).event == "heartbeat" {
			beats++
		}
	}
	if beats < 8 {
		t.Fatalf("heartbeats = %d, want >= 8", beats)
	}
}

// TestAgentSessionMessagesPagination covers GET .../messages with before_seq
// and limit (gap 6): owner only, the 200 cap, and last_message_preview on the
// session members.
func TestAgentSessionMessagesPagination(t *testing.T) {
	model := newFakeModel(t, 0, func(call int) string { return textReply(fmt.Sprintf("reply %d", call)) })
	e := newAgentEnv(t, func(o *agentsession.Options) { o.HTTPClient = model.srv.Client() })
	admin := e.setupAdmin(adminUser)
	created := createSession(t, e, admin, map[string]any{"config": configFor(model.srv.URL)})
	id := mustString(t, created, "session_id")
	for i := 0; i < 2; i++ {
		sendMessage(t, e, admin, id, fmt.Sprintf("question %d", i))
		waitSessionStatus(t, e, admin, id, "idle")
	}
	// Four messages are retained: question 0, reply 0, question 1, reply 1.

	resp := e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions/"+id+"/messages?limit=2", "")).expect(t, http.StatusOK)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	resp.decode(t, &page)
	if len(page.Items) != 2 || page.Items[0]["role"] != "user" || page.Items[1]["role"] != "assistant" {
		t.Fatalf("newest page = %+v", page.Items)
	}
	newest := int64(page.Items[0]["seq"].(float64))
	older := e.do(admin.sign(http.MethodGet,
		fmt.Sprintf("/api/v1/agent-sessions/%s/messages?before_seq=%d&limit=1", id, newest), "")).expect(t, http.StatusOK)
	var olderPage struct {
		Items []map[string]any `json:"items"`
	}
	older.decode(t, &olderPage)
	if len(olderPage.Items) != 1 || olderPage.Items[0]["content"] != "reply 0" {
		t.Fatalf("older page = %+v", olderPage.Items)
	}

	// A limit above the cap and a malformed before_seq are 400.
	e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions/"+id+"/messages?limit=1000", "")).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions/"+id+"/messages?before_seq=nope", "")).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// Another principal cannot page a foreign session.
	token := e.serviceToken(admin)
	e.do(bearer(http.MethodGet, "/api/v1/agent-sessions/"+id+"/messages", "", token)).
		expectProblem(t, http.StatusNotFound, problem.NotFound)

	// The list previews the newest message (plain text, at most 120 chars).
	lresp := e.do(admin.sign(http.MethodGet, "/api/v1/agent-sessions", "")).expect(t, http.StatusOK)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	lresp.decode(t, &list)
	if len(list.Items) != 1 || list.Items[0]["last_message_preview"] != "reply 1" {
		t.Fatalf("list preview = %+v", list.Items)
	}
}
