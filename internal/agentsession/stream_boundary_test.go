// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 实际订阅入口达到硬上限，释放后应可重新进入 ========================

func TestAgentStreamPerSessionAdmissionAndRelease(t *testing.T) {
	h := newTestHost(t)
	rec := h.create(ownerHuman, defaultCreate())
	var streams []*Subscription
	for range 8 {
		streams = append(streams, h.subscribe(ownerHuman, rec.ID))
	}
	extra, err := h.svc.Subscribe(t.Context(), ownerHuman, rec.ID, -1)
	if extra != nil {
		extra.Close()
	}
	if err == nil || problem.From(err).Code != problem.RateLimited {
		t.Fatalf("每会话第9个订阅未拒绝: %v", err)
	}
	streams[0].Close()
	streams[0].Close()
	h.subscribe(ownerHuman, rec.ID)
}

func fullAgentStreamHost(t *testing.T, buffer int) (*testHost, []*Session, []*Subscription) {
	t.Helper()
	h := newTestHost(t, func(o *Options) { o.Config.SubscriberBuffer = buffer })
	var sessions []*Session
	var streams []*Subscription
	for range 8 {
		rec := h.create(ownerHuman, defaultCreate())
		sessions = append(sessions, rec)
		for range 8 {
			streams = append(streams, h.subscribe(ownerHuman, rec.ID))
		}
	}
	return h, sessions, streams
}

func TestAgentStreamGlobalAdmissionAndDeleteRelease(t *testing.T) {
	h, sessions, _ := fullAgentStreamHost(t, 2)
	next := h.create(ownerHuman, defaultCreate())
	extra, err := h.svc.Subscribe(t.Context(), ownerHuman, next.ID, -1)
	if extra != nil {
		extra.Close()
	}
	if err == nil || problem.From(err).Code != problem.RateLimited {
		t.Fatalf("全局第65个订阅未拒绝: %v", err)
	}
	if err := h.svc.Delete(t.Context(), ownerHuman, sessions[0].ID); err != nil {
		t.Fatal(err)
	}
	for range 8 {
		h.subscribe(ownerHuman, next.ID)
	}
	last := h.create(ownerHuman, defaultCreate())
	extra, err = h.svc.Subscribe(t.Context(), ownerHuman, last.ID, -1)
	if extra != nil {
		extra.Close()
	}
	if err == nil || problem.From(err).Code != problem.RateLimited {
		t.Fatalf("删除后配额被重复释放或丢失: %v", err)
	}
}

func TestAgentStreamConcurrentAdmissionAndClose(t *testing.T) {
	h := newTestHost(t, func(o *Options) { o.Config.SubscriberBuffer = 1 })
	var sessions []*Session
	for range 16 {
		sessions = append(sessions, h.create(ownerHuman, defaultCreate()))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	type result struct {
		stream *Subscription
		err    error
	}
	results := make(chan result, 128)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for _, rec := range sessions {
		for range 8 {
			workers.Add(1)
			go func(id string) {
				defer workers.Done()
				<-start
				stream, err := h.svc.Subscribe(ctx, ownerHuman, id, -1)
				results <- result{stream, err}
			}(rec.ID)
		}
	}
	close(start)
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("并发订阅没有在请求预算内退出")
	}
	close(results)
	var accepted []*Subscription
	for got := range results {
		if got.stream != nil {
			accepted = append(accepted, got.stream)
			t.Cleanup(got.stream.Close)
		} else if got.err == nil || problem.From(got.err).Code != problem.RateLimited {
			t.Fatalf("并发订阅返回非额度错误: %v", got.err)
		}
	}
	if len(accepted) != 64 {
		t.Fatalf("并发总额度没有收口为64: accepted=%d", len(accepted))
	}
	for _, stream := range accepted {
		workers.Add(1)
		go func() {
			defer workers.Done()
			stream.Close()
			_ = stream.Overflowed()
			stream.Close()
		}()
	}
	workers.Wait()
	for _, rec := range sessions[:8] {
		for range 8 {
			h.subscribe(ownerHuman, rec.ID)
		}
	}
}

func TestAgentStreamOverflowReleasesGlobalAdmission(t *testing.T) {
	h, sessions, streams := fullAgentStreamHost(t, 1)
	rt := h.svc.runtimeFor(sessions[0])
	rt.mu.Lock()
	rt.broadcastLocked(Event{Seq: 1, Type: EventMessageDelta, Delta: "a"}, h.svc.cfg.RingSize)
	rt.broadcastLocked(Event{Seq: 2, Type: EventMessageDelta, Delta: "b"}, h.svc.cfg.RingSize)
	rt.mu.Unlock()
	for _, stream := range streams[:8] {
		if !stream.Overflowed() {
			t.Fatal("真实缓冲溢出未通知订阅者")
		}
		stream.Close()
		stream.Close()
	}
	next := h.create(ownerHuman, defaultCreate())
	for range 8 {
		h.subscribe(ownerHuman, next.ID)
	}
	last := h.create(ownerHuman, defaultCreate())
	extra, err := h.svc.Subscribe(t.Context(), ownerHuman, last.ID, -1)
	if extra != nil {
		extra.Close()
	}
	if err == nil || problem.From(err).Code != problem.RateLimited {
		t.Fatalf("溢出和显式关闭重复释放全局额度: %v", err)
	}
}

// ======================== 真实关闭与事务失败不能留下脱离管理的订阅 ========================

func TestAgentStreamRejectsSubscribeAfterServiceClose(t *testing.T) {
	h := newTestHost(t)
	rec := h.create(ownerHuman, defaultCreate())
	h.svc.Close()
	stream, err := h.svc.Subscribe(t.Context(), ownerHuman, rec.ID, -1)
	if stream != nil {
		stream.Close()
	}
	if err == nil {
		t.Fatal("服务关闭后仍创建了无法由关闭流程回收的订阅")
	}
}

func TestAgentStreamFailedDeleteKeepsOriginalRuntime(t *testing.T) {
	h := newTestHost(t)
	rec := h.create(ownerHuman, defaultCreate())
	stream := h.subscribe(ownerHuman, rec.ID)
	if err := h.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `CREATE TRIGGER reject_agent_delete BEFORE DELETE ON agent_sessions
			BEGIN SELECT RAISE(ABORT, 'fixture delete blocked'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Delete(t.Context(), ownerHuman, rec.ID); err == nil {
		t.Fatal("真实删除事务未失败")
	}
	if _, err := h.svc.loadFor(t.Context(), ownerHuman, rec.ID); err != nil {
		t.Fatalf("失败删除改变了实际数据库行: %v", err)
	}
	h.svc.mu.Lock()
	managed := h.svc.sessions[rec.ID] == stream.rt
	h.svc.mu.Unlock()
	stream.rt.mu.Lock()
	closed := stream.rt.closed
	stream.rt.mu.Unlock()
	if !managed || closed {
		t.Fatalf("提交失败已丢失或关闭原运行时: managed=%v closed=%v", managed, closed)
	}
	select {
	case _, open := <-stream.Events:
		if !open {
			t.Fatal("提交失败已关闭原活跃订阅")
		}
	default:
	}
}

type agentStreamAdmissionClock struct {
	clock.Clock
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	active  atomic.Bool
}

func (c *agentStreamAdmissionClock) Now() time.Time {
	now := c.Clock.Now()
	if c.active.Load() {
		c.once.Do(func() { close(c.entered); <-c.release })
	}
	return now
}

func TestAgentStreamRejectsDeletedRowFromEarlierRead(t *testing.T) {
	gate := &agentStreamAdmissionClock{Clock: clock.System{}, entered: make(chan struct{}), release: make(chan struct{})}
	h := newTestHost(t, func(o *Options) { o.Clock = gate })
	rec := h.create(ownerHuman, defaultCreate())
	h.svc.runtimeFor(rec)
	gate.active.Store(true)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	t.Cleanup(release)
	type result struct {
		stream *Subscription
		err    error
	}
	done := make(chan result, 1)
	go func() {
		stream, err := h.svc.Subscribe(t.Context(), ownerHuman, rec.ID, -1)
		done <- result{stream, err}
	}()
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("订阅没有进入实际首读之后的时序窗口")
	}
	// runtimeFor 内的时钟接缝已证明首读完成；此处执行真实原删除事务。
	if err := h.svc.deleteSession(t.Context(), ownerHuman, rec.ID); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case got := <-done:
		if got.stream != nil {
			got.stream.Close()
		}
		if got.err == nil {
			t.Fatal("首读取得的旧行在删除提交后被恢复为活跃订阅")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("删除窗口内的订阅未退出")
	}
}

// ======================== 剩余字节预算必须保持 UTF-8，满额后停止广播 ========================

func publishAgentStreamDelta(t *testing.T, h *testHost, rt *sessionRuntime, text string) {
	t.Helper()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if err := h.svc.publishLocked(t.Context(), rt, Event{Type: EventMessageDelta, MessageID: "msg_stream", Delta: text}); err != nil {
		t.Fatal(err)
	}
}

func TestAgentStreamDeltaRespectsRuneAtRemainingByte(t *testing.T) {
	h := newTestHost(t)
	rec := h.create(ownerHuman, defaultCreate())
	stream := h.subscribe(ownerHuman, rec.ID)
	publishAgentStreamDelta(t, h, stream.rt, strings.Repeat("a", maxAssistantBytes-1))
	publishAgentStreamDelta(t, h, stream.rt, "中🙂")
	for _, event := range drain(stream) {
		if !utf8.ValidString(event.Delta) {
			t.Fatal("剩余字节处广播了被切断的 UTF-8 字符")
		}
	}
	stream.rt.mu.Lock()
	text := stream.rt.delta["msg_stream"].String()
	stream.rt.mu.Unlock()
	if !utf8.ValidString(text) || len(text) != maxAssistantBytes-1 {
		t.Fatal("累积文本的 UTF-8 或实际长度不正确")
	}
}

func TestAgentStreamDeltaStopsAfterTotalByteLimit(t *testing.T) {
	h := newTestHost(t)
	rec := h.create(ownerHuman, defaultCreate())
	stream := h.subscribe(ownerHuman, rec.ID)
	publishAgentStreamDelta(t, h, stream.rt, strings.Repeat("a", maxAssistantBytes))
	for range 20 {
		publishAgentStreamDelta(t, h, stream.rt, "超过预算后不再广播")
	}
	events := drain(stream)
	if len(events) != 1 {
		t.Fatalf("总预算满额后仍广播了额外文本: events=%d", len(events))
	}
	stream.rt.mu.Lock()
	seq := stream.rt.seq
	stream.rt.mu.Unlock()
	if seq != events[0].Seq {
		t.Fatal("丢弃文本仍推进了不可回放的事件序号")
	}
}

func TestAgentStreamAssistantLimitMatchesApproved256KiB(t *testing.T) {
	if maxAssistantBytes != 256<<10 {
		t.Fatalf("助手文本总字节预算未对齐256KiB施工契约: %d", maxAssistantBytes)
	}
}
