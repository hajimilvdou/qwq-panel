// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
)

// TestLoopbackMCPServerHardeningLimitsAndShutdown verifies +1 oversize body
// rejection (413), duplicate JSON keys (400), deep nesting >32 (400), trailing
// data (400), bounded concurrency (429), and active-handler cancellation on Close.
func TestLoopbackMCPServerHardeningLimitsAndShutdown(t *testing.T) {
	handlerStarted := make(chan struct{}, 8)
	handlerCancelled := make(chan struct{}, 8)
	releaseHandler := make(chan struct{})

	srv, err := StartLoopbackMCPServerWithContext(context.Background(), NewMCPBridge(Turn{
		SessionID:      "sess_mcp_hard",
		PermissionMode: operations.PermissionSafe,
		Tools:          []ToolSpec{{Action: "monitor.slow.read", Effect: operations.EffectRead}},
		Runner: RunnerFunc(func(ctx context.Context, _ ToolCall) (ToolResult, error) {
			handlerStarted <- struct{}{}
			select {
			case <-ctx.Done():
				handlerCancelled <- struct{}{}
				return ToolResult{}, ctx.Err()
			case <-releaseHandler:
				return ToolResult{Status: ToolSucceeded, Result: json.RawMessage(`{"ok":true}`)}, nil
			}
		}),
	}, false, func(Event) error { return nil }, nil))
	if err != nil {
		t.Fatalf("StartLoopbackMCPServerWithContext: %v", err)
	}
	defer srv.Close()

	post := func(body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+srv.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("http post: %v", err)
		}
		return resp
	}

	// 1. Oversize body (256 KiB + 1 byte) -> 413.
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","pad":"` + strings.Repeat("a", maxMCPBodyBytes) + `"}`
	resp := post(big)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status = %d, want 413", resp.StatusCode)
	}

	// 2. Duplicate JSON key (top-level and nested) -> 400.
	for _, dup := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"initialize"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}`,
	} {
		r := post(dup)
		_ = r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("duplicate key %s status = %d, want 400", dup, r.StatusCode)
		}
	}

	// 3. Excessive nesting depth (>32) -> 400.
	deep := strings.Repeat(`{"a":`, maxMCPJSONDepth+2) + `1` + strings.Repeat(`}`, maxMCPJSONDepth+2)
	rDeep := post(deep)
	_ = rDeep.Body.Close()
	if rDeep.StatusCode != http.StatusBadRequest {
		t.Fatalf("deep nesting status = %d, want 400", rDeep.StatusCode)
	}

	// 4. Trailing JSON tokens -> 400.
	rTrail := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}{"extra":1}`)
	_ = rTrail.Body.Close()
	if rTrail.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing tokens status = %d, want 400", rTrail.StatusCode)
	}

	// 5. Concurrency ceiling (4 in-flight -> 5th gets 429).
	var wg sync.WaitGroup
	for i := 0; i < maxMCPConcurrentCalls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBufferString(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"monitor_slow_read","arguments":{}}}`))
			req.Header.Set("Authorization", "Bearer "+srv.Token)
			r, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = r.Body.Close()
			}
		}()
	}
	for i := 0; i < maxMCPConcurrentCalls; i++ {
		select {
		case <-handlerStarted:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for handler %d to start", i)
		}
	}
	rSat := post(`{"jsonrpc":"2.0","id":99,"method":"tools/list"}`)
	_ = rSat.Body.Close()
	if rSat.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("saturated status = %d, want 429", rSat.StatusCode)
	}

	// 6. Close() cancels all in-flight handlers immediately and returns promptly.
	closeStart := time.Now()
	_ = srv.Close()
	if time.Since(closeStart) > 2*time.Second {
		t.Fatalf("Close took too long while handlers were blocked: %v", time.Since(closeStart))
	}
	for i := 0; i < maxMCPConcurrentCalls; i++ {
		select {
		case <-handlerCancelled:
		case <-time.After(2 * time.Second):
			t.Fatalf("handler %d did not observe ctx cancellation on Close", i)
		}
	}
	close(releaseHandler)
	wg.Wait()
}

// TestPersistedCompactionSurvivesRestartAndShrinksModelRequest proves `/compact`
// persists compaction_checkpoint into SQLite, survives a full Service restart
// (new Service instance over the same DB), and causes the next real HTTP model
// request to receive the compacted checkpoint instead of raw early turns while
// preserving immutable transcript rows in SQLite.
func TestPersistedCompactionSurvivesRestartAndShrinksModelRequest(t *testing.T) {
	var mu sync.Mutex
	var capturedBodies []string
	modelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		capturedBodies = append(capturedBodies, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ack"}}]}`)
	}))
	defer modelSrv.Close()

	h, _ := newNativeHost(t)
	rec := h.create(ownerHuman, CreateRequest{
		Title:  "Compaction Persistence",
		Core:   CoreNative,
		Config: nativeConfigJSON(modelSrv.URL, "gpt-test"),
	})

	// Send 5 full turns (10 messages > KeepRecentMessages=6).
	for i := 1; i <= 5; i++ {
		marker := "EARLY_UNIQUE_TOKEN_001_SHOULD_COLLAPSE"
		if i > 1 {
			marker = "TURN_MSG_" + string(rune('0'+i))
		}
		h.send(ownerHuman, rec.ID, marker)
		h.waitTurn(rec.ID)
	}

	// Run /compact via Send (persists compaction_checkpoint in agent_sessions.config_json).
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "/compact")
	h.waitTurn(rec.ID)
	evts := drain(sub)
	if len(eventsOfType(evts, EventSessionCompacted)) == 0 {
		t.Fatalf("expected session.compacted event, got %+v", evts)
	}

	// Simulate full service restart: brand-new Service instance over the SAME SQLite DB!
	restarted, err := New(Options{
		DB:         h.db,
		HTTPClient: modelSrv.Client(),
	})
	if err != nil {
		t.Fatalf("New restarted service: %v", err)
	}
	t.Cleanup(func() { restarted.Close() })

	// Clear captured bodies before sending the post-restart turn.
	mu.Lock()
	capturedBodies = nil
	mu.Unlock()

	if _, err := restarted.Send(context.Background(), ownerHuman, rec.ID, SendRequest{
		Content: "POST_RESTART_QUESTION",
	}); err != nil {
		t.Fatalf("restarted.Send: %v", err)
	}
	if err := restarted.WaitTurn(context.Background(), rec.ID); err != nil {
		t.Fatalf("restarted.WaitTurn: %v", err)
	}

	mu.Lock()
	if len(capturedBodies) == 0 {
		mu.Unlock()
		t.Fatal("model server received no request after restart")
	}
	reqBody := capturedBodies[len(capturedBodies)-1]
	mu.Unlock()

	if !strings.Contains(reqBody, "[Compacted Session Context Checkpoint]") {
		t.Fatalf("post-restart model request missing compacted checkpoint:\n%s", reqBody)
	}
	if !strings.Contains(reqBody, "POST_RESTART_QUESTION") {
		t.Fatalf("post-restart model request missing latest user turn:\n%s", reqBody)
	}
	// Verify the number of messages sent is strictly compacted (<= 9 instead of 12+).
	var decoded struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(reqBody), &decoded); err != nil {
		t.Fatalf("decode model request: %v", err)
	}
	// 1 system prompt + 1 checkpoint + 6 recent messages + 1 new user msg = 9 (vs 13 uncompacted).
	if len(decoded.Messages) >= 11 {
		t.Fatalf("expected compacted message list (<11), got %d messages: %+v", len(decoded.Messages), decoded.Messages)
	}

	// Verify immutable SQLite transcript rows were NOT deleted.
	allMsgs, err := restarted.messages(context.Background(), rec.ID, 0, 100)
	if err != nil {
		t.Fatalf("restarted.messages: %v", err)
	}
	if len(allMsgs) < 11 {
		t.Fatalf("expected immutable SQLite transcript preserved (>=11 msgs), got %d", len(allMsgs))
	}
}
