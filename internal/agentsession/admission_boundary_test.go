// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 真实 SQLite 并发重试：只创建一条用户消息和一次模型回合 ========================

func TestClientMessageConcurrentRetry(t *testing.T) {
	const workers = 32
	var runs atomic.Int32
	releaseTurn := make(chan struct{})
	core := &scriptCore{name: "native", run: func(ctx context.Context, _ Turn, emit Emit) error {
		runs.Add(1)
		select {
		case <-releaseTurn:
			return emit(Event{Type: EventMessageCompleted, Delta: "done"})
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	h := newTestHost(t, func(o *Options) { o.Cores = []Core{core} })
	rec := h.create(ownerHuman, defaultCreate())
	rt := h.svc.runtimeFor(rec)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type answer struct {
		result *SendResult
		err    error
	}
	answers := make(chan answer, workers)
	var started sync.WaitGroup
	started.Add(workers)
	// 原锁外查询会让并发请求都读到不存在，再在此真实运行时锁等待首写。
	rt.mu.Lock()
	for range workers {
		go func() {
			started.Done()
			result, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "once", ClientMessageID: "concurrent-retry"})
			answers <- answer{result: result, err: err}
		}()
	}
	started.Wait()
	time.Sleep(100 * time.Millisecond)
	rt.mu.Unlock()
	var first *Message
	var failures []string
	for range workers {
		select {
		case got := <-answers:
			if got.err != nil {
				failures = append(failures, got.err.Error())
				continue
			}
			if got.result == nil {
				failures = append(failures, "send returned no result")
				continue
			}
			msg := got.result.Message
			if first == nil {
				first = &msg
			} else if msg.MessageID != first.MessageID || msg.Seq != first.Seq {
				t.Fatalf("same client id returned different messages: %+v, %+v", first, msg)
			}
		case <-ctx.Done():
			t.Fatal("concurrent retries did not finish")
		}
	}
	if len(failures) != 0 {
		t.Fatalf("concurrent same-id retries failed: %d/%d; %v", len(failures), workers, failures)
	}
	if _, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "different", ClientMessageID: "another-key"}); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("different key while busy = %v", err)
	}
	close(releaseTurn)
	h.waitTurn(rec.ID)
	if runs.Load() != 1 {
		t.Fatalf("model turns = %d, want 1", runs.Load())
	}
	msgs, err := h.svc.Messages(ctx, ownerHuman, rec.ID, 0)
	if err != nil || len(msgs) != 2 || msgs[0].Role != RoleUser || msgs[1].Role != RoleAssistant {
		t.Fatalf("retried transcript = %+v, %v", msgs, err)
	}
}

// ======================== 未知工具：不通过 gate/runner，其他已知调用仍正常推进 ========================

func TestRunLoopUnknownToolAlongsideKnown(t *testing.T) {
	unknownName := strings.Repeat("not_in_catalog", 32)
	provider := &fakeProvider{replies: []ProviderResponse{
		{ToolCalls: []ModelToolCall{
			{CallID: "missing", Name: unknownName, Arguments: json.RawMessage(`{}`)},
			{CallID: "known", Name: "host.users.list", Arguments: json.RawMessage(`{}`)},
		}},
		{Content: "finished"},
	}}
	tools := &fakeTools{defs: toolDefs()}
	gate := GateFunc(func(_ context.Context, _ ToolDef, call ModelToolCall) (GateDecision, error) {
		if call.Name != "host.users.list" {
			t.Error("an unavailable tool reached the permission gate")
		}
		return GateDecision{Kind: GateAllow}, nil
	})
	recorder := &loopRecorder{}
	result, err := RunLoop(context.Background(), provider, tools, gate, recorder.emit, LoopOptions{})
	if err != nil || result.Status != LoopCompleted {
		t.Fatalf("mixed tool step = %+v, %v", result, err)
	}
	if len(tools.executed) != 1 || tools.executed[0].CallID != "known" {
		t.Fatalf("executed tools = %+v", tools.executed)
	}
	var outcomes []*ToolOutcome
	for _, event := range recorder.events {
		if event.Type == LoopEventToolResult {
			outcomes = append(outcomes, event.Outcome)
		}
	}
	if len(outcomes) != 2 || outcomes[0].Status != ToolFailed || outcomes[1].Status != ToolSucceeded {
		t.Fatalf("mixed tool outcomes = %+v", outcomes)
	}
	second := provider.reqs[1].Messages
	if len(second) != 3 || len(second[0].ToolCalls) != 2 || second[1].ToolCallID != "missing" || second[2].ToolCallID != "known" {
		t.Fatalf("mixed transcript is not paired: %+v", second)
	}
	if len(second[0].ToolCalls[0].Name) > 128 {
		t.Fatal("unavailable tool name grew the model history without a bound")
	}
}

func TestClientMessageDeletedAfterFirstRead(t *testing.T) {
	var runs atomic.Int32
	h := newTestHost(t, func(o *Options) {
		o.Cores = []Core{&scriptCore{name: "native", run: func(context.Context, Turn, Emit) error {
			runs.Add(1)
			return nil
		}}}
	})
	rec := h.create(ownerHuman, defaultCreate())
	rt := h.svc.runtimeFor(rec)
	before := rt.lastUsed.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	rt.mu.Lock()
	go func() {
		_, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "late", ClientMessageID: "late-key"})
		result <- err
	}()
	// lastUsed 的原子更新证明 Send 已通过首读，并在原运行时锁处等待。
	for rt.lastUsed.Load() == before {
		if ctx.Err() != nil {
			rt.mu.Unlock()
			t.Fatal("send did not reach the held runtime")
		}
		time.Sleep(time.Millisecond)
	}
	// 真实删除事务不设置 closed，强制验证锁内实际行重查这条独立门禁。
	if err := h.svc.deleteSession(ctx, ownerHuman, rec.ID); err != nil {
		rt.mu.Unlock()
		t.Fatalf("delete original row: %v", err)
	}
	rt.mu.Unlock()
	select {
	case err := <-result:
		if !problem.HasCode(err, problem.NotFound) {
			t.Fatalf("send after original row deletion = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("deleted send did not finish")
	}
	if runs.Load() != 0 {
		t.Fatal("a deleted session started the model")
	}
	var messages int
	if err := h.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_messages WHERE session_id = ?`, rec.ID).Scan(&messages); err != nil || messages != 0 {
		t.Fatalf("deleted session messages = %d, %v", messages, err)
	}
}

func TestNativeCoreUnknownToolPersist(t *testing.T) {
	runner := &fakeRunner{}
	h, _ := newNativeHost(t, func(o *Options) {
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
	})
	model := newModelServer(t,
		toolCallReply("missing", "not_in_catalog", `{}`),
		modelReply{content: "this tool is unavailable"},
	)
	rec := h.create(ownerHuman, CreateRequest{Core: CoreNative, PermissionMode: operations.PermissionFull,
		Config: nativeConfigJSON(model.srv.URL, "m")})
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "try this tool")
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusIdle)
	if calls, _ := runner.snapshot(); len(calls) != 0 {
		t.Fatalf("unavailable tool reached runner: %+v", calls)
	}
	events := drain(sub)
	calls := eventsOfType(events, EventToolCall)
	results := eventsOfType(events, EventToolResult)
	if len(calls) != 1 || len(results) != 1 || calls[0].Action != "not_in_catalog" ||
		results[0].CallID != calls[0].CallID || results[0].Status != string(ToolFailed) ||
		results[0].Error == nil || results[0].Error.Code != problem.Unavailable {
		t.Fatalf("persisted unavailable call/result = %+v, %+v", calls, results)
	}
	msgs, err := h.svc.Messages(context.Background(), ownerHuman, rec.ID, 0)
	if err != nil || len(msgs) != 4 || msgs[1].Role != RoleAssistant || msgs[2].Role != RoleTool ||
		msgs[3].Role != RoleAssistant || !strings.Contains(msgs[2].Content, "unknown tool") {
		t.Fatalf("persisted unknown tool transcript = %+v, %v", msgs, err)
	}
	if model.callCount() != 2 {
		t.Fatalf("model requests = %d, want 2", model.callCount())
	}
}
