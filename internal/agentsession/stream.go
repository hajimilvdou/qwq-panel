// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Limits of one session's in-memory state and of the values an event carries.
const (
	maxAssistantBytes = 256 << 10
	maxSessionStreams = 8
	maxServiceStreams = 64
	maxResultBytes    = 32 << 10
	maxEventRing      = 2048
	// maxRingBytes bounds the retained events of one session.
	maxRingBytes = 1 << 20
	// eventOverhead is the rough cost of an event besides its variable fields.
	eventOverhead = 256
)

// subscriber is one live SSE consumer of a session.
type subscriber struct {
	ch        chan Event
	overflow  atomic.Bool
	closeOnce sync.Once
	release   func()
}

// close 在订阅关闭、溢出或宿主退出时共用一次释放，额度与 channel 生命周期一致。
func (sub *subscriber) close() {
	sub.closeOnce.Do(func() {
		close(sub.ch)
		if sub.release != nil {
			sub.release()
		}
	})
}

// pendingApproval is the one call a paused session is waiting for.
type pendingApproval struct {
	callID      string
	approvalID  string
	operationID string
	action      string
	args        json.RawMessage
	messageID   string
	cancel      context.CancelFunc
	done        chan struct{}
	// withdrawing marks an approval a user is taking back: only the goroutine
	// that claimed it may end the pause.
	withdrawing bool
}

// sessionRuntime is the in-memory state of one open session: the latest row, the
// event ring and the live subscribers. All fields are guarded by mu.
type sessionRuntime struct {
	mu      sync.Mutex
	session Session
	seq     int64
	ring    []Event
	// ringBytes is the eventBytes sum of ring.
	ringBytes int
	subs      map[*subscriber]struct{}
	// lastUsed is the unix-nano time runtimeFor last handed this runtime out.
	// runtimeFor stores it under s.mu, which is what keeps the sweeper from
	// evicting a runtime a request has just received.
	lastUsed atomic.Int64

	running  bool
	cancel   context.CancelCauseFunc
	turnDone chan struct{}

	delta          map[string]*strings.Builder
	reasoning      strings.Builder
	currentMessage string
	lastAssistant  string
	pending        *pendingApproval
	closed         bool
	// wg tracks the turn and approval goroutines of this runtime so Close and
	// Delete can wait for them.
	wg sync.WaitGroup
}

// owner returns the session's owner actor.
func (rt *sessionRuntime) owner() actor.Actor {
	return actor.Actor{Kind: rt.session.OwnerKind, ID: rt.session.OwnerID}
}

// nextSeq reserves the next event sequence. Callers must hold mu.
func (rt *sessionRuntime) nextSeqLocked() int64 {
	rt.seq++
	return rt.seq
}

// snapshot returns a copy of the current session row.
func (rt *sessionRuntime) snapshot() Session {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.session
}

// eventBytes estimates what a retained event costs.
func eventBytes(e Event) int {
	n := eventOverhead + len(e.Delta) + len(e.Args) + len(e.Result) + len(e.Detail) +
		len(e.Summary) + len(e.Description) + len(e.Comment)
	if e.Error != nil {
		n += len(e.Error.Detail)
	}
	for _, call := range e.ToolCalls {
		n += eventOverhead + len(call.Arguments)
	}
	return n
}

// appendRingLocked retains e within the count and byte limits, always keeping
// the newest event. Trimming copies to a new slice: a reslice would keep the
// dropped events reachable through the backing array.
func (rt *sessionRuntime) appendRingLocked(e Event, ringSize int) {
	rt.ring = append(rt.ring, e)
	rt.ringBytes += eventBytes(e)
	if ringSize <= 0 || ringSize > maxEventRing {
		ringSize = 256
	}
	drop := 0
	for drop < len(rt.ring)-1 && (len(rt.ring)-drop > ringSize || rt.ringBytes > maxRingBytes) {
		rt.ringBytes -= eventBytes(rt.ring[drop])
		drop++
	}
	if drop > 0 {
		rt.ring = append(make([]Event, 0, len(rt.ring)-drop+1), rt.ring[drop:]...)
	}
}

// broadcastLocked appends e to the ring and fans it out. A subscriber whose
// buffer is full is closed and marked overflowed: the handler answers with a
// `resync` frame, exactly like the gateway's event stream.
func (rt *sessionRuntime) broadcastLocked(e Event, ringSize int) {
	rt.appendRingLocked(e, ringSize)
	for sub := range rt.subs {
		select {
		case sub.ch <- e:
		default:
			rt.removeSubscriberLocked(sub, true)
		}
	}
}

// removeSubscriberLocked 共用关闭与溢出路径；调用方持有原会话锁。
func (rt *sessionRuntime) removeSubscriberLocked(sub *subscriber, overflow bool) {
	if _, exists := rt.subs[sub]; !exists {
		return
	}
	if overflow {
		sub.overflow.Store(true)
	}
	delete(rt.subs, sub)
	sub.close()
}

func (rt *sessionRuntime) closeSubscribersLocked() {
	for sub := range rt.subs {
		rt.removeSubscriberLocked(sub, true)
	}
}

// replayLocked returns the ring events after seq, or resync=true when seq is
// older than the retained window. A position of 0 means "from the beginning of
// what is retained": sequence numbers are shared with messages, so an absent
// number in the range is not a gap and must not force a resync.
func (rt *sessionRuntime) replayLocked(after int64) (events []Event, resync bool) {
	if after < 0 {
		return nil, false
	}
	if after == 0 {
		// The client asked for the whole retained window. After a restart the
		// ring is empty while the row still has a sequence, so the window is not
		// complete and the client has to reload the snapshot.
		if len(rt.ring) == 0 && rt.seq > 0 {
			return nil, true
		}
		return append([]Event(nil), rt.ring...), false
	}
	if len(rt.ring) == 0 {
		return nil, after < rt.seq
	}
	if after < rt.ring[0].Seq-1 {
		return nil, true
	}
	for _, e := range rt.ring {
		if e.Seq > after {
			events = append(events, e)
		}
	}
	return events, false
}

// Subscription is one agent session SSE stream.
type Subscription struct {
	// Head is the highest sequence at subscribe time.
	Head int64
	// Resync tells the client to reload the session snapshot instead of
	// replaying a backlog that is no longer retained.
	Resync bool
	// Reason is the resync reason (out_of_window).
	Reason string
	// Replay is the retained backlog after the requested sequence.
	Replay []Event
	// Events is the live stream. It is closed when the subscription ends.
	Events <-chan Event

	svc *Service
	rt  *sessionRuntime
	sub *subscriber
}

// Close releases the subscription. It is safe to call more than once.
func (s *Subscription) Close() {
	if s == nil || s.sub == nil {
		return
	}
	s.rt.mu.Lock()
	s.rt.removeSubscriberLocked(s.sub, false)
	s.rt.mu.Unlock()
}

// Overflowed reports whether the live stream was closed because its bounded
// buffer overflowed; the client must resync.
func (s *Subscription) Overflowed() bool {
	return s != nil && s.sub != nil && s.sub.overflow.Load()
}

// Subscribe opens one session event stream for the owner. after is the seq of
// the last event the client saw (-1 for a fresh stream that starts live).
func (s *Service) Subscribe(ctx context.Context, owner actor.Actor, sessionID string, after int64) (*Subscription, error) {
	if s.closed.Load() {
		return nil, problem.New(problem.Unavailable, "The host is shutting down.")
	}
	rec, err := s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return nil, err
	}
	rt := s.runtimeFor(rec)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if s.closed.Load() || rt.closed {
		return nil, problem.New(problem.StateConflict, "The agent session is closed.")
	}
	// -----------------------------------------------------------------------
	// 首次读取和取得会话锁之间可能已完成删除；当前数据库归属不能由旧行替代。
	// 这里仅作短只读重查，不创建 writer，也不跨等待持有事务。
	// -----------------------------------------------------------------------
	rec, err = s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return nil, err
	}
	if len(rt.subs) >= maxSessionStreams {
		return nil, agentStreamLimit("agent_session_streams", maxSessionStreams)
	}
	if !s.reserveStream() {
		return nil, agentStreamLimit("agent_service_streams", maxServiceStreams)
	}
	if rt.seq < rec.LastSeq {
		rt.seq = rec.LastSeq
	}
	replay, resync := rt.replayLocked(after)
	sub := &subscriber{ch: make(chan Event, s.cfg.SubscriberBuffer), release: func() { s.streams.Add(-1) }}
	rt.subs[sub] = struct{}{}
	out := &Subscription{Head: rt.seq, Resync: resync, Replay: replay, Events: sub.ch, svc: s, rt: rt, sub: sub}
	if resync {
		out.Reason = "out_of_window"
	}
	return out, nil
}

func (s *Service) reserveStream() bool {
	for {
		active := s.streams.Load()
		if active >= maxServiceStreams {
			return false
		}
		if s.streams.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func agentStreamLimit(name string, max int64) error {
	return &problem.Error{Code: problem.RateLimited, Detail: "The agent event stream limit has been reached.",
		RetryAfterSec: 1, Limit: &problem.Limit{Name: name, Max: max}}
}

// SessionDetailSnapshot bundles a coherent view of the persisted session,
// transcript messages, pending approvals, and in-flight live streaming buffer
// captured under rt.mu so in_flight.head_seq never outruns returned messages.
type SessionDetailSnapshot struct {
	Session   *Session
	Messages  []Message
	Approvals []PendingApproval
	InFlight  *InFlightSnapshot
}

// SessionSnapshot returns a consistent snapshot of session metadata, messages,
// pending approvals, and any in-flight live delta buffer.
func (s *Service) SessionSnapshot(ctx context.Context, owner actor.Actor, sessionID string) (*SessionDetailSnapshot, error) {
	rec, err := s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return nil, err
	}
	rt := s.runtimeFor(rec)

	rt.mu.Lock()
	defer rt.mu.Unlock()

	freshRec, err := s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return nil, err
	}
	msgs, err := s.messages(ctx, sessionID, 0, 0)
	if err != nil {
		return nil, err
	}
	if msgs == nil {
		msgs = []Message{}
	}
	recs, err := s.toolCallsWithStatus(ctx, sessionID, ToolAwaitingApproval)
	if err != nil {
		return nil, err
	}
	approvals := make([]PendingApproval, 0, len(recs))
	for _, r := range recs {
		pa := PendingApproval{
			CallID: r.CallID, ApprovalID: r.ApprovalID, OperationID: r.OperationID,
			Action: r.Action, Args: r.Args, Status: r.Status, CreatedAt: r.CreatedAt,
		}
		if tool, ok := s.toolFor(ctx, r.Action); ok {
			pa.Summary, pa.Description = tool.Summary, tool.Description
		}
		approvals = append(approvals, pa)
	}
	var inFlight *InFlightSnapshot
	if rt.running && !rt.closed {
		var content string
		if rt.currentMessage != "" {
			if b := rt.delta[rt.currentMessage]; b != nil {
				content = b.String()
			}
		}
		reasoning := rt.reasoning.String()
		if content != "" || reasoning != "" {
			msgID := rt.currentMessage
			if msgID == "" {
				msgID = "in_flight"
			}
			inFlight = &InFlightSnapshot{
				MessageID: msgID,
				Reasoning: reasoning,
				Content:   content,
				HeadSeq:   rt.seq,
			}
		}
	}
	return &SessionDetailSnapshot{
		Session:   freshRec,
		Messages:  msgs,
		Approvals: approvals,
		InFlight:  inFlight,
	}, nil
}

// InFlight returns the in-memory streaming snapshot (buffered assistant text
// and reasoning deltas not yet persisted to SQLite) when a turn is actively
// streaming, or nil when idle / between messages.
func (s *Service) InFlight(ctx context.Context, owner actor.Actor, sessionID string) *InFlightSnapshot {
	if _, err := s.loadFor(ctx, owner, sessionID); err != nil {
		return nil
	}
	s.mu.Lock()
	rt := s.sessions[sessionID]
	s.mu.Unlock()
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !rt.running || rt.closed {
		return nil
	}
	var content string
	if rt.currentMessage != "" {
		if b := rt.delta[rt.currentMessage]; b != nil {
			content = b.String()
		}
	}
	reasoning := rt.reasoning.String()
	if content == "" && reasoning == "" {
		return nil
	}
	msgID := rt.currentMessage
	if msgID == "" {
		msgID = "in_flight"
	}
	return &InFlightSnapshot{
		MessageID: msgID,
		Reasoning: reasoning,
		Content:   content,
		HeadSeq:   rt.seq,
	}
}

// publishLocked persists what e implies and broadcasts it; the caller holds
// rt.mu. It is the only writer of session state, so seq order, the database and
// the SSE stream never disagree.
func (s *Service) publishLocked(ctx context.Context, rt *sessionRuntime, e Event) error {
	if rt.closed {
		return problem.New(problem.StateConflict, "The agent session is closed.")
	}
	// If an external adapter or core emits a tool_call while unclosed assistant
	// text is buffered in memory, auto-flush it first so last_seq never jumps
	// ahead of unpersisted deltas and post-tool text gets its own bubble.
	if e.Type == EventToolCall {
		if rt.currentMessage != "" {
			if b := rt.delta[rt.currentMessage]; b != nil && b.Len() > 0 {
				if err := s.publishLocked(ctx, rt, Event{
					Type:      EventMessageCompleted,
					MessageID: rt.currentMessage,
				}); err != nil {
					return err
				}
			} else {
				// Reasoning-only pre-tool step: drop stale host placeholder ID
				// and reasoning buffer so they do not bleed into the next step.
				rt.currentMessage = ""
				rt.reasoning.Reset()
			}
		} else if rt.reasoning.Len() > 0 {
			rt.reasoning.Reset()
		}
	}
	// Ignore redundant empty completion frames from external adapters whose
	// buffered text was already auto-flushed before a tool call.
	if e.Type == EventMessageCompleted {
		targetID := e.MessageID
		if targetID == "" {
			targetID = rt.currentMessage
		}
		hasDelta := targetID != "" && rt.delta[targetID] != nil && rt.delta[targetID].Len() > 0
		if !hasDelta && e.Delta == "" && len(e.ToolCalls) == 0 && e.ReasoningContent == "" && rt.reasoning.Len() == 0 {
			if targetID != "" && targetID == rt.lastAssistant {
				return nil
			}
			if e.MessageID == "" && rt.currentMessage == "" && rt.lastAssistant != "" {
				return nil
			}
		}
	}
	// ======================== 先收紧总字节预算，再分配可回放的序号 ========================
	if e.Type == EventReasoningDelta {
		rd := e.Delta
		if rd == "" && len(e.Result) > 0 {
			var p struct {
				Delta string `json:"delta"`
			}
			if json.Unmarshal(e.Result, &p) == nil {
				rd = p.Delta
			}
		}
		if rd != "" {
			if rt.currentMessage == "" {
				rt.currentMessage = s.ids.New(messagePrefix)
			}
			if remain := maxAssistantBytes - rt.reasoning.Len(); remain > 0 {
				rt.reasoning.WriteString(clipText(rd, remain))
			}
		}
	}
	if e.Type == EventMessageDelta {
		if e.Delta == "" {
			return nil
		}
		if e.MessageID == "" {
			if rt.currentMessage == "" {
				rt.currentMessage = s.ids.New(messagePrefix)
			}
			e.MessageID = rt.currentMessage
		} else if rt.currentMessage == "" || (rt.currentMessage != e.MessageID && rt.delta[rt.currentMessage] == nil) {
			// Adopt explicit provider message ID when currentMessage was unset
			// or only a reasoning-only host placeholder with no text deltas.
			rt.currentMessage = e.MessageID
		}
		b := rt.deltaLocked(e.MessageID)
		remain := maxAssistantBytes - b.Len()
		if remain <= 0 {
			return nil
		}
		e.Delta = clipText(e.Delta, remain)
		if e.Delta == "" {
			return nil
		}
		b.WriteString(e.Delta)
	}
	if e.SessionID == "" {
		e.SessionID = rt.session.ID
	}
	if e.Seq == 0 {
		e.Seq = rt.nextSeqLocked()
	}
	if e.At.IsZero() {
		e.At = s.clock.Now().UTC().Truncate(time.Millisecond)
	}
	owner := rt.owner()
	switch e.Type {
	case EventMessageCompleted:
		if e.MessageID == "" {
			if rt.currentMessage != "" {
				e.MessageID = rt.currentMessage
			} else {
				e.MessageID = s.ids.New(messagePrefix)
			}
		}
		var content string
		var streamed bool
		if b := rt.delta[e.MessageID]; b != nil {
			content = b.String()
			streamed = content != ""
			delete(rt.delta, e.MessageID)
		}
		if !streamed {
			content = clipText(e.Delta, maxAssistantBytes)
		} else if e.Delta == "" || e.Delta == content {
			// Deltas were already streamed to live SSE subscribers; strip
			// duplicate full text from the completion frame so clients don't
			// append the entire message a second time.
			e.Delta = ""
		} else {
			remain := maxAssistantBytes - len(content)
			if remain > 0 {
				tail := clipText(e.Delta, remain)
				content += tail
				e.Delta = tail
			} else {
				e.Delta = ""
			}
		}
		msg := &Message{
			SessionID: rt.session.ID, Seq: e.Seq, MessageID: e.MessageID, Role: RoleAssistant, Content: content, CreatedAt: e.At,
		}
		reasoning := clipText(e.ReasoningContent, maxAssistantBytes)
		if reasoning == "" {
			reasoning = clipText(rt.reasoning.String(), maxAssistantBytes)
		}
		rt.reasoning.Reset()
		// Clear ReasoningContent and ThinkingBlocks from the broadcast Event so
		// rt.ring does not pin unbounded reasoning/signature payloads invisible to
		// maxRingBytes accounting.
		thinkingBlocks := boundThinkingBlocks(e.ThinkingBlocks, maxAssistantBytes)
		e.ReasoningContent = ""
		e.ThinkingBlocks = nil
		if len(e.ToolCalls) > 0 || reasoning != "" || len(thinkingBlocks) > 0 {
			for i := range e.ToolCalls {
				e.ToolCalls[i].Arguments = storableArgs(e.ToolCalls[i].Arguments)
			}
			raw, err := json.Marshal(assistantContent{
				ReasoningContent: reasoning,
				ThinkingBlocks:   thinkingBlocks,
				ToolCalls:        e.ToolCalls,
			})
			if err != nil {
				return err
			}
			msg.ContentJSON = raw
		}
		if _, err := s.insertMessage(ctx, owner, msg, rt.session.Status, s.cfg.RetainMessages); err != nil {
			return err
		}
		if rt.currentMessage == e.MessageID {
			rt.currentMessage = ""
		}
		rt.lastAssistant = e.MessageID
	case EventToolCall:
		if e.CallID == "" {
			return problem.New(problem.Internal, "The core proposed a tool call without an id.")
		}
		e.Args = storableArgs(e.Args)
		rec := &ToolRecord{
			CallID: e.CallID, SessionID: rt.session.ID, Seq: e.Seq, Action: e.Action, Args: e.Args,
			Status: ToolProposed, CreatedAt: e.At, UpdatedAt: e.At,
		}
		if err := s.insertToolCall(ctx, owner, rec); err != nil {
			return err
		}
	case EventToolResult:
		if err := s.writeToolResultLocked(ctx, rt, e); err != nil {
			return err
		}
		e.Result = clipJSON(e.Result, maxResultBytes)
	case EventApprovalRequired:
		e.Args = storableArgs(e.Args)
		rec, err := s.loadToolCall(ctx, rt.session.ID, e.CallID)
		if err != nil {
			if problem.HasCode(err, problem.NotFound) && e.CallID != "" {
				// External CLI permission prompts (Codex / OpenCode / ACP) may
				// request approval before emitting a separate tool_call event.
				rec = &ToolRecord{
					CallID:      e.CallID,
					SessionID:   rt.session.ID,
					Seq:         e.Seq,
					Action:      firstNonEmpty(e.Action, "external.permission"),
					Args:        e.Args,
					Status:      ToolAwaitingApproval,
					ApprovalID:  e.ApprovalID,
					OperationID: e.OperationID,
					CreatedAt:   e.At,
					UpdatedAt:   e.At,
				}
				if insErr := s.insertToolCall(ctx, owner, rec); insErr != nil {
					return insErr
				}
			} else {
				return err
			}
		} else {
			rec.Status = ToolAwaitingApproval
			rec.ApprovalID = e.ApprovalID
			if rec.OperationID == "" {
				rec.OperationID = e.OperationID
			}
			if err := s.updateToolCall(ctx, owner, rec); err != nil {
				return err
			}
		}
		if err := s.setRuntimeStatusLocked(ctx, rt, StatusWaitingApproval, e.Seq); err != nil {
			return err
		}
		rt.pending = &pendingApproval{
			callID: e.CallID, approvalID: e.ApprovalID, operationID: e.OperationID,
			action: e.Action, args: e.Args, messageID: rt.lastAssistant,
		}
	case EventTurnCompleted:
		rt.reasoning.Reset()
		st := Status(e.Status)
		if !st.Valid() {
			st = StatusFailed
		}
		if err := s.setRuntimeStatusLocked(ctx, rt, st, e.Seq); err != nil {
			return err
		}
	case EventError:
		// Persist turn errors as a structured system message (filtered out of
		// model context by historyMessages) so first-turn failures and reloads
		// always show the real diagnostic card instead of a blank transcript.
		if rawErr, err := buildPersistedErrorJSON(e.Code, e.Detail); err == nil {
			errMsg := &Message{
				SessionID:   rt.session.ID,
				Seq:         e.Seq,
				MessageID:   s.ids.New(messagePrefix),
				Role:        RoleSystem,
				Content:     clipText(e.Detail, 2000),
				ContentJSON: rawErr,
				CreatedAt:   e.At,
			}
			if _, err := s.insertMessage(ctx, owner, errMsg, rt.session.Status, s.cfg.RetainMessages); err != nil {
				return err
			}
		}
	case EventApprovalDecided:
		// When an external CLI turn waited inline for an approval while
		// rt.running remained true, clear the pending marker and restore
		// StatusRunning once the human decides.
		if rt.running && rt.pending != nil && (e.ApprovalID == "" || rt.pending.approvalID == e.ApprovalID) {
			rt.pending = nil
			if rt.session.Status == StatusWaitingApproval {
				_ = s.setRuntimeStatusLocked(ctx, rt, StatusRunning, e.Seq)
			}
		}
	}
	rt.broadcastLocked(e, s.cfg.RingSize)
	return nil
}

// deltaLocked returns the accumulation buffer of messageID, creating it when
// needed (nil for an empty id).
func (rt *sessionRuntime) deltaLocked(messageID string) *strings.Builder {
	if messageID == "" {
		return nil
	}
	if rt.delta == nil {
		rt.delta = map[string]*strings.Builder{}
	}
	b := rt.delta[messageID]
	if b == nil {
		b = &strings.Builder{}
		rt.delta[messageID] = b
	}
	return b
}

// writeToolResultLocked stores a tool outcome and its transcript entry.
func (s *Service) writeToolResultLocked(ctx context.Context, rt *sessionRuntime, e Event) error {
	owner := rt.owner()
	rec, err := s.loadToolCall(ctx, rt.session.ID, e.CallID)
	if err != nil {
		return err
	}
	rec.Status = ToolStatus(e.Status)
	if !rec.Status.Valid() {
		rec.Status = ToolFailed
	}
	if e.OperationID != "" {
		rec.OperationID = e.OperationID
	}
	if e.ApprovalID != "" {
		rec.ApprovalID = e.ApprovalID
	}
	rec.Result = clipJSON(e.Result, maxResultBytes)
	rec.Error = e.Error.Problem()
	if err := s.updateToolCall(ctx, owner, rec); err != nil {
		return err
	}
	tc := toolContent{
		CallID: e.CallID, Action: rec.Action, Status: string(rec.Status),
		Result: rec.Result, Error: e.Error, OperationID: rec.OperationID, ApprovalID: rec.ApprovalID,
	}
	raw, err := json.Marshal(tc)
	if err != nil {
		return err
	}
	content := resultText(rec)
	msg := &Message{
		SessionID: rt.session.ID, Seq: e.Seq, MessageID: s.ids.New(messagePrefix), Role: RoleTool, Content: content,
		ContentJSON: raw, OperationID: rec.OperationID, ApprovalID: rec.ApprovalID, CreatedAt: e.At,
	}
	_, err = s.insertMessage(ctx, owner, msg, rt.session.Status, s.cfg.RetainMessages)
	return err
}

// setRuntimeStatusLocked writes the status and updates the runtime's copy.
func (s *Service) setRuntimeStatusLocked(ctx context.Context, rt *sessionRuntime, st Status, seq int64) error {
	rev, err := s.setSessionStatus(ctx, rt.owner(), rt.session.ID, st, seq)
	if err != nil {
		return err
	}
	rt.session.Status = st
	rt.session.Revision = rev
	if seq > rt.session.LastSeq {
		rt.session.LastSeq = seq
	}
	return nil
}

// resultText is the plain-text form of a tool outcome.
func resultText(rec *ToolRecord) string {
	if rec.Error != nil {
		return rec.Error.Detail
	}
	if len(rec.Result) == 0 {
		return ""
	}
	if len(rec.Result) <= 4096 {
		return string(rec.Result)
	}
	return "(result omitted: larger than 4096 bytes; see content_json)"
}

// clipJSON shortens a raw JSON document without breaking it: an oversized
// document is replaced by a bounded summary object.
func clipJSON(raw json.RawMessage, max int) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) <= max {
		return raw
	}
	out, _ := json.Marshal(map[string]any{
		"truncated": true,
		"bytes":     len(raw),
	})
	return out
}

// clipText bounds a string to at most n bytes on a rune boundary.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// boundThinkingBlocks preserves signed Anthropic thinking blocks up to maxBytes
// atomically: if the complete thinking sequence exceeds maxBytes, it drops the
// whole sequence rather than keeping a partial prefix (which Anthropic rejects).
func boundThinkingBlocks(in []AnthropicThinkingBlock, maxBytes int) []AnthropicThinkingBlock {
	if len(in) == 0 || maxBytes <= 0 {
		return nil
	}
	total := 0
	for _, blk := range in {
		if blk.Type == "thinking" && blk.Signature == "" {
			return nil
		}
		if blk.Type == "redacted_thinking" && blk.Data == "" {
			return nil
		}
		total += len(blk.Type) + len(blk.Thinking) + len(blk.Signature) + len(blk.Data)
		if total > maxBytes {
			return nil
		}
	}
	out := make([]AnthropicThinkingBlock, len(in))
	copy(out, in)
	return out
}
