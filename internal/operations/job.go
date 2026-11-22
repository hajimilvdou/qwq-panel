// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// jobQueue is a bounded FIFO of operation IDs waiting for a worker. The queue
// is in memory on purpose: the operation row is the durable record, and a
// restart re-queues PENDING jobs (see Recover).
type jobQueue struct {
	mu      sync.Mutex
	queue   []string
	running int
	closed  bool
	signal  chan struct{}
	// idle is closed exactly while the queue is empty and nothing is running.
	idle    chan struct{}
	idleSet bool
}

func newJobQueue(int) *jobQueue {
	q := &jobQueue{signal: make(chan struct{}, 1), idle: make(chan struct{})}
	close(q.idle)
	q.idleSet = true
	return q
}

// push appends an operation ID. It reports false once the queue is closed.
func (q *jobQueue) push(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	q.queue = append(q.queue, id)
	q.markBusyLocked()
	select {
	case q.signal <- struct{}{}:
	default:
	}
	return true
}

// pop waits for the next ID. It reports false when the queue is closed and
// empty, which ends a worker.
func (q *jobQueue) pop(ctx context.Context) (string, bool) {
	for {
		q.mu.Lock()
		if len(q.queue) > 0 {
			id := q.queue[0]
			q.queue = q.queue[1:]
			q.running++
			q.mu.Unlock()
			return id, true
		}
		if q.closed {
			q.mu.Unlock()
			return "", false
		}
		q.mu.Unlock()
		select {
		case <-q.signal:
		case <-ctx.Done():
			return "", false
		}
	}
}

func (q *jobQueue) done() {
	q.mu.Lock()
	if q.running > 0 {
		q.running--
	}
	q.markIdleLocked()
	q.mu.Unlock()
}

func (q *jobQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.signal)
	}
	q.markIdleLocked()
}

// wait blocks until no job is queued or running.
func (q *jobQueue) wait(ctx context.Context) error {
	for {
		q.mu.Lock()
		if q.idleSet {
			q.mu.Unlock()
			return nil
		}
		ch := q.idle
		q.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (q *jobQueue) markBusyLocked() {
	if q.idleSet {
		q.idle = make(chan struct{})
		q.idleSet = false
	}
}

// isClosed reports whether close was called; a closed queue is final.
func (q *jobQueue) isClosed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.closed
}

func (q *jobQueue) markIdleLocked() {
	if !q.idleSet && len(q.queue) == 0 && q.running == 0 {
		close(q.idle)
		q.idleSet = true
	}
}

// enqueue hands an operation to the workers. A shutdown leaves the operation
// PENDING, which the next start re-queues.
func (s *Service) enqueue(ctx context.Context, id string) {
	if !s.jobs.push(id) {
		s.log.WarnContext(ctx, "operations: job queue is closed; the operation will be recovered on the next start",
			"operation_id", id)
	}
}

// runWorker consumes the queue until it is closed.
func (s *Service) runWorker(ctx context.Context) {
	for {
		id, ok := s.jobs.pop(ctx)
		if !ok {
			return
		}
		s.runJob(ctx, id)
		s.jobs.done()
	}
}

// runJob executes one job operation: PENDING/APPROVED -> RUNNING -> terminal,
// with one short transaction per step (ADR-0008 §2).
func (s *Service) runJob(ctx context.Context, id string) {
	op, err := loadOperation(ctx, s.db.Reader(), id)
	if err != nil {
		s.log.ErrorContext(ctx, "operations: load queued job", "operation_id", id, "error", err)
		return
	}
	if op.Status != Pending && op.Status != Approved {
		return // canceled or decided while queued
	}
	if op.Meta.Source == HostSource {
		s.runHostJob(ctx, op)
		return
	}
	if s.dispatcher == nil {
		s.recordFailure(ctx, id, problem.New(problem.Unavailable, "No plugin dispatcher is configured."))
		return
	}
	jobCtx, cancel := context.WithTimeout(ctx, op.Timeout)
	defer cancel()
	// 先注册再进入 RUNNING：两者之间到达的 Cancel 也能找到执行者。
	if !s.registerRunningContext(id, cancel, jobCtx) {
		return
	}
	err = s.withOperation(ctx, id, func(ctx context.Context, tx *storage.Tx, cur *Operation) error {
		if isTerminal(cur.Status) || cur.Status == Running {
			return errSkip
		}
		if err := s.checkOperationPreconditions(ctx, tx, cur); err != nil {
			return err
		}
		if err := s.checkExpectedRevision(ctx, tx, cur); err != nil {
			return err
		}
		return s.enterRunning(ctx, tx, cur)
	})
	if err != nil {
		s.unregisterRunning(id)
	}
	if errors.Is(err, errSkip) {
		return
	}
	if err != nil {
		if ctx.Err() != nil {
			// The host is shutting down: leave the operation to recovery
			// instead of recording a failure it can no longer explain.
			return
		}
		s.recordFailure(ctx, id, err)
		return
	}
	streamErr := s.streamJob(jobCtx, id)
	s.unregisterRunning(id)
	if streamErr == nil {
		return
	}
	if ctx.Err() != nil {
		// Shutdown interrupted the stream; the operation stays RUNNING and the
		// next start fails or retries the attempt (ADR-0007 #15).
		return
	}
	if s.shouldRetry(ctx, id) {
		s.retryJob(ctx, id, streamErr)
		return
	}
	s.recordFailure(ctx, id, streamErr)
}

// streamJob consumes the RunJob stream and writes progress and the outcome.
func (s *Service) streamJob(ctx context.Context, id string) error {
	op, err := loadOperation(ctx, s.db.Reader(), id)
	if err != nil {
		return err
	}
	req := PluginRunJobRequest{
		Actor: op.Actor, OperationID: op.ID, ParentOperationID: op.ParentOperationID,
		Attempt: op.Attempt, TraceID: op.TraceID,
		RequestID: op.RequestID, NodeID: op.Target.NodeID, PluginID: op.Meta.PluginID,
		InstanceID: op.Target.InstanceID, Placement: op.Meta.Placement, Operation: op.Meta.Operation,
		APIVersion: op.Meta.APIVersion, Payload: op.Args, Preconditions: op.Preconditions,
	}
	throttle := &progressThrottle{interval: s.cfg.ProgressInterval}
	return s.dispatcher.RunJob(ctx, req, func(p JobProgress) error {
		return s.onProgress(ctx, id, p, throttle)
	})
}

// progressThrottle limits progress writes to one per interval. The terminal
// message and any message carrying resource changes are always written.
type progressThrottle struct {
	mu       sync.Mutex
	last     time.Time
	interval time.Duration
}

func (t *progressThrottle) due(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.interval > 0 && !t.last.IsZero() && now.Sub(t.last) < t.interval {
		return false
	}
	t.last = now
	return true
}

// onProgress applies one message of the stream.
func (s *Service) onProgress(ctx context.Context, id string, p JobProgress, throttle *progressThrottle) error {
	if p.Error != nil {
		return s.recordFailure(ctx, id, p.Error)
	}
	terminal := p.Completed
	if !terminal && len(p.Changes) == 0 && !throttle.due(s.clock.Now()) {
		// Throttled: the next message (or the terminal one) carries the state.
		return nil
	}
	err := s.withOperation(ctx, id, func(ctx context.Context, tx *storage.Tx, op *Operation) error {
		if isTerminal(op.Status) {
			return nil
		}
		if len(p.Changes) > 0 {
			// Plugin-owned changes become resource.changed right away so open
			// UIs follow a long job step by step (ADR-0004 D9).
			if err := s.applyChanges(ctx, tx, op, p.Changes); err != nil {
				return err
			}
		}
		if p.Completed {
			if progress := progressFromJob(p); progress != nil {
				op.Progress = progress
			}
			if len(p.Result) > 0 {
				op.Result = p.Result
			}
			return s.finishOperation(ctx, tx, op, Succeeded, nil)
		}
		progress := progressFromJob(p)
		if progress == nil {
			return nil
		}
		op.Progress = progress
		return s.writeOperation(ctx, tx, op, op.Status, []string{"/progress"})
	})
	if err != nil {
		return err
	}
	return nil
}

func progressFromJob(p JobProgress) *Progress {
	out := &Progress{
		Percent: p.Percent, Step: sanitizeStep(p.Step), StepIndex: p.StepIndex,
		StepCount: p.StepCount, Message: clipText(p.Message, 500),
	}
	if out.Percent == nil && out.Step == "" && out.StepIndex == 0 && out.StepCount == 0 && out.Message == "" {
		return nil
	}
	return out
}

var stepPattern = regexp.MustCompile(`^[a-z0-9_.-]{0,64}$`)

func sanitizeStep(step string) string {
	if stepPattern.MatchString(step) {
		return step
	}
	return ""
}

// clipText shortens untrusted text to n bytes on a rune boundary.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.ToValidUTF8(s[:n], "")
}

// shouldRetry reports whether an interrupted job may start another attempt:
// only idempotent operations, only before the attempt limit, and never after a
// cancel request (ADR-0007 #15, ARCH §7).
func (s *Service) shouldRetry(ctx context.Context, id string) bool {
	op, err := loadOperation(ctx, s.db.Reader(), id)
	if err != nil {
		return false
	}
	if isTerminal(op.Status) || op.CancelRequested {
		return false
	}
	return op.Meta.Idempotent && op.Attempt < s.cfg.MaxAttempts
}

// retryJob closes the failed attempt, bumps the attempt number and queues the
// operation again. The operation stays PENDING between attempts.
func (s *Service) retryJob(ctx context.Context, id string, cause error) {
	err := s.withOperation(ctx, id, func(ctx context.Context, tx *storage.Tx, op *Operation) error {
		if isTerminal(op.Status) {
			return nil
		}
		op.Error = s.problemOf(cause, op.RequestID, "/api/v1/operations/"+op.ID)
		if err := finishAttemptRow(ctx, tx, op, "failed"); err != nil {
			return err
		}
		previous := op.Status
		op.Attempt++
		op.Status = Pending
		op.Error = nil
		// A retry is not a transition of the state machine: the next attempt
		// starts from PENDING again.
		if err := s.writeOperation(ctx, tx, op, previous, []string{"/status", "/attempt"}); err != nil {
			return err
		}
		return audit(ctx, tx, AuditRecord{
			Actor: op.Actor, Action: op.Action, Subject: operationSubject(op.ID), Outcome: AuditFailure,
			OperationID: op.ID, NodeID: op.NodeID, TraceID: op.TraceID, RequestID: op.RequestID,
		}, map[string]any{"event": "retry", "attempt": op.Attempt, "error": cause.Error()})
	})
	if err != nil {
		s.recordFailure(ctx, id, err)
		return
	}
	s.enqueue(ctx, id)
}

// runHostJob executes a mode=job host action: RUNNING in one short transaction,
// the executor outside any transaction, the terminal state in another. A crash
// in between leaves RUNNING to recovery, which re-runs an idempotent action
// (ADR-0007 #15). The executor owns its own writes and events.
func (s *Service) runHostJob(ctx context.Context, op *Operation) {
	handler, ok := s.hostJob(op.Action)
	if !ok || handler == nil {
		s.recordFailure(ctx, op.ID, problem.New(problem.Unavailable, "The host action has no executor."))
		return
	}
	jobCtx, cancel := context.WithTimeout(ctx, op.Timeout)
	defer cancel()
	// 先注册再进入 RUNNING：两者之间到达的 Cancel 也能找到执行者。
	if !s.registerRunningContext(op.ID, cancel, jobCtx) {
		return
	}
	defer s.unregisterRunning(op.ID)
	err := s.withOperation(ctx, op.ID, func(ctx context.Context, tx *storage.Tx, cur *Operation) error {
		if isTerminal(cur.Status) || cur.Status == Running {
			return errSkip
		}
		if err := s.checkOperationPreconditions(ctx, tx, cur); err != nil {
			return err
		}
		if err := s.checkExpectedRevision(ctx, tx, cur); err != nil {
			return err
		}
		return s.enterRunning(ctx, tx, cur)
	})
	if errors.Is(err, errSkip) {
		return
	}
	if err != nil {
		if ctx.Err() != nil {
			return // shutdown: recovery explains it
		}
		s.recordFailure(ctx, op.ID, err)
		return
	}
	result, runErr := handler(jobCtx, s.hostRequest(op))
	if runErr != nil {
		if ctx.Err() != nil {
			return
		}
		s.recordFailure(ctx, op.ID, runErr)
		return
	}
	if err := s.withOperation(ctx, op.ID, func(ctx context.Context, tx *storage.Tx, cur *Operation) error {
		if isTerminal(cur.Status) {
			return nil
		}
		if len(result) > 0 {
			cur.Result = result
		}
		return s.finishOperation(ctx, tx, cur, Succeeded, nil)
	}); err != nil {
		s.recordFailure(ctx, op.ID, err)
	}
}
