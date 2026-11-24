// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestStreamingMultiChunkAccumulationAndPersistence locks down the exact live
// regression where multi-token SSE deltas (like Ollama/DeepSeek emitting one
// token per frame with empty MessageID) were assigned a brand-new message_id
// per chunk and persisted only the final 1-char token ("。") to SQLite.
func TestStreamingMultiChunkAccumulationAndPersistence(t *testing.T) {
	tokens := []string{"**", "签名", "或", "来源", "校验", "失败", "**", "：", "请", "检查", "公钥", "。"}
	wantText := strings.Join(tokens, "")
	var turnCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := turnCount.Add(1)
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		flusher, _ := w.(http.Flusher)
		if n == 1 {
			// Turn 1: simulate Ollama/DeepSeek single-token SSE deltas + inline <think> tags.
			chunks := append([]string{"<thi", "nk>先排查", "证书链</th", "ink>\n"}, tokens...)
			for _, tok := range chunks {
				b, _ := json.Marshal(map[string]any{
					"choices": []map[string]any{
						{"delta": map[string]any{"content": tok}},
					},
				})
				fmt.Fprintf(w, "data: %s\n\n", b)
				if flusher != nil {
					flusher.Flush()
				}
			}
		} else {
			// Turn 2: confirm a fresh distinct message_id is minted without PK conflict.
			for _, tok := range []string{"第二轮", "回复", "正常", "。"} {
				b, _ := json.Marshal(map[string]any{
					"choices": []map[string]any{
						{"delta": map[string]any{"content": tok}},
					},
				})
				fmt.Fprintf(w, "data: %s\n\n", b)
			}
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	h := newTestHost(t, func(o *Options) {
		o.HTTPClient = srv.Client()
	})

	cfg, _ := json.Marshal(map[string]any{
		"base_url": srv.URL,
		"model":    "deepseek-v4.1-flash:1017",
		"stream":   true,
	})
	rec := h.create(ownerHuman, CreateRequest{
		Title:  "streaming-regression",
		Core:   CoreNative,
		Config: cfg,
	})
	sub := h.subscribe(ownerHuman, rec.ID)

	h.send(ownerHuman, rec.ID, "xray这个插件怎么安装不了？")
	h.waitTurn(rec.ID)

	events := drain(sub)
	deltas := eventsOfType(events, EventMessageDelta)
	if len(deltas) < 2 {
		t.Fatalf("expected multiple streamed message.delta events, got %d", len(deltas))
	}
	firstMsgID := deltas[0].MessageID
	if firstMsgID == "" {
		t.Fatal("first message.delta has empty message_id")
	}
	var streamed strings.Builder
	for i, d := range deltas {
		if d.MessageID != firstMsgID {
			t.Fatalf("delta[%d] minted a new message_id %q != %q (token-per-bubble regression!)", i, d.MessageID, firstMsgID)
		}
		streamed.WriteString(d.Delta)
	}
	if streamed.String() != wantText {
		t.Fatalf("streamed text = %q, want %q", streamed.String(), wantText)
	}

	// Verify inline <think>...</think> was routed to reasoning.delta cleanly.
	var reasonBuf strings.Builder
	for _, ev := range events {
		if ev.Type == EventReasoningDelta && len(ev.Result) > 0 {
			var p struct {
				Delta string `json:"delta"`
			}
			if json.Unmarshal(ev.Result, &p) == nil {
				reasonBuf.WriteString(p.Delta)
			}
		}
	}
	if reasonBuf.String() != "先排查证书链" {
		t.Fatalf("reasoning stream = %q, want %q", reasonBuf.String(), "先排查证书链")
	}

	// Verify EventMessageCompleted did NOT duplicate text on the wire.
	completed := eventsOfType(events, EventMessageCompleted)
	if len(completed) != 1 || completed[0].MessageID != firstMsgID || completed[0].Delta != "" {
		t.Fatalf("unexpected message.completed: %+v", completed)
	}

	// Verify SQLite persisted the FULL accumulated assistant reply (not "。").
	msgs, err := h.svc.Messages(context.Background(), ownerHuman, rec.ID, 20)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 persisted messages (user + assistant), got %d", len(msgs))
	}
	if msgs[1].MessageID != firstMsgID || msgs[1].Content != wantText {
		t.Fatalf("persisted assistant message = (%q, %q), want (%q, %q)",
			msgs[1].MessageID, msgs[1].Content, firstMsgID, wantText)
	}

	// Turn 2: ensure a new distinct assistant message_id is created and persisted.
	h.send(ownerHuman, rec.ID, "继续")
	h.waitTurn(rec.ID)

	msgs2, err := h.svc.Messages(context.Background(), ownerHuman, rec.ID, 20)
	if err != nil {
		t.Fatalf("Messages turn 2: %v", err)
	}
	if len(msgs2) != 4 {
		t.Fatalf("expected 4 persisted messages after 2 turns, got %d", len(msgs2))
	}
	if msgs2[3].MessageID == firstMsgID || msgs2[3].Content != "第二轮回复正常。" {
		t.Fatalf("turn 2 assistant = (%q, %q)", msgs2[3].MessageID, msgs2[3].Content)
	}
}

// TestStreamingOpenAI400FallbackAndMultiToolNoIndex verifies two OpenCode/DSH
// compatibility mitigations:
//  1. Automatic retry without `stream_options` / `reasoning_effort` on HTTP 400;
//  2. Multi-tool SSE chunks where Ollama omits `index` (or reuses 0 with distinct IDs).
func TestStreamingOpenAI400FallbackAndMultiToolNoIndex(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		n := attempts.Add(1)
		if n == 1 {
			if _, hasSO := body["stream_options"]; !hasSO {
				t.Errorf("expected stream_options on first attempt")
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"unknown parameter stream_options"}}`))
			return
		}
		if _, hasSO := body["stream_options"]; hasSO {
			t.Errorf("retry should strip stream_options")
		}
		if _, hasRE := body["reasoning_effort"]; hasRE {
			t.Errorf("retry should strip reasoning_effort")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		// Two tool calls both omitting "index" (defaulting to 0) with distinct IDs.
		fmt.Fprint(w, `data: {"choices":[{"delta":{"tool_calls":[{"id":"call_a","type":"function","function":{"name":"tool_one","arguments":""}}]}}]}`+"\n\n")
		fmt.Fprint(w, `data: {"choices":[{"delta":{"tool_calls":[{"id":"call_b","type":"function","function":{"name":"tool_two","arguments":"{\"k\":1}"}}]}}]}`+"\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	streamTrue := true
	core := NewNativeCore(NativeOptions{Client: srv.Client()})
	prov := &streamingOpenAIProvider{
		core: core,
		cfg: &enhancedNativeConfig{
			nativeConfig:    nativeConfig{BaseURL: srv.URL, Model: "o3-mini"},
			ReasoningEffort: "high",
			Stream:          &streamTrue,
		},
		telemetry:      &TelemetrySnapshot{},
		thinkingKeeper: NewAnthropicThinkingKeeper(),
	}
	resp, err := prov.Complete(context.Background(), ProviderRequest{
		Messages: []ModelMessage{{Role: LoopRoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete failed after 400 retry: %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
	if len(resp.ToolCalls) != 2 {
		t.Fatalf("expected 2 distinct tool calls, got %+v", resp.ToolCalls)
	}
	if resp.ToolCalls[0].CallID != "call_a" || resp.ToolCalls[0].Name != "tool_one" || string(resp.ToolCalls[0].Arguments) != "{}" {
		t.Fatalf("tool[0] = %+v", resp.ToolCalls[0])
	}
	if resp.ToolCalls[1].CallID != "call_b" || resp.ToolCalls[1].Name != "tool_two" || string(resp.ToolCalls[1].Arguments) != `{"k":1}` {
		t.Fatalf("tool[1] = %+v", resp.ToolCalls[1])
	}
}

// TestAnthropicSSEStreaming verifies true SSE streaming for anthropic_compatible
// endpoints (thinking_delta + signature_delta + text_delta + usage).
func TestAnthropicSSEStreaming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["stream"] != true {
			t.Errorf("expected stream=true in Anthropic request")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100,\"cache_read_input_tokens\":40}}}\n\n")
		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\"}}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"分析中\"}}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig_abc\"}}\n\n")
		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\"}}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"你好\"}}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"世界\"}}\n\n")
		fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":25}}\n\n")
	}))
	defer srv.Close()

	var deltas []string
	var reasons []string
	streamTrue := true
	core := NewNativeCore(NativeOptions{Client: srv.Client()})
	prov := &streamingOpenAIProvider{
		core:         core,
		providerKind: ProviderKindAnthropic,
		cfg: &enhancedNativeConfig{
			nativeConfig: nativeConfig{BaseURL: srv.URL, Model: "claude-sonnet-4-5"},
			Stream:       &streamTrue,
		},
		emit: func(e Event) error {
			if e.Type == EventMessageDelta {
				deltas = append(deltas, e.Delta)
			}
			if e.Type == EventReasoningDelta {
				var p struct {
					Delta string `json:"delta"`
				}
				if json.Unmarshal(e.Result, &p) == nil {
					reasons = append(reasons, p.Delta)
				}
			}
			return nil
		},
		telemetry:      &TelemetrySnapshot{},
		thinkingKeeper: NewAnthropicThinkingKeeper(),
	}
	resp, err := prov.Complete(context.Background(), ProviderRequest{
		Messages: []ModelMessage{{Role: LoopRoleUser, Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("Anthropic SSE Complete: %v", err)
	}
	if resp.Content != "你好世界" {
		t.Fatalf("content = %q, want 你好世界", resp.Content)
	}
	if strings.Join(deltas, "") != "你好世界" || len(deltas) != 2 {
		t.Fatalf("deltas = %v", deltas)
	}
	if strings.Join(reasons, "") != "分析中" {
		t.Fatalf("reasons = %v", reasons)
	}
	if prov.telemetry.Tokens.Input != 140 || prov.telemetry.Tokens.CachedRead != 40 || prov.telemetry.Tokens.Output != 25 {
		t.Fatalf("unexpected Anthropic telemetry tokens: %+v", prov.telemetry.Tokens)
	}
}
