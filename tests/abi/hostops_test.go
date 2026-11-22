// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// hostOp is the host's operation record (ARCH §7, ADR-0004 D7). The fields above the marker are
// fixed at creation; the others are guarded by fakeHost.mu.
type hostOp struct {
	id       string
	parentID string
	actor    *pb.Actor
	trace    string
	locale   string
	target   *hostInstance
	creator  *hostInstance // instance that created it with InvokePlugin; nil for gateway operations
	desc     *pb.OperationDescriptor
	risk     pb.RiskLevel
	payload  []byte
	preconds []*pb.Precondition
	done     chan struct{} // closed at a terminal state

	// guarded by fakeHost.mu
	state      pb.OperationState
	history    []pb.OperationState
	dispatched bool // a call carrying this operation_id is in flight to target
	planning   bool // that call is PlanOperation
	progress   []*pb.JobProgress
	result     []byte
	err        *pb.ErrorDetail
	cancel     context.CancelFunc
	changed    chan struct{} // closed and replaced on every change
}

type opSpec struct {
	target   *hostInstance
	op       string // must be declared by target
	actor    *pb.Actor
	payload  []byte
	preconds []*pb.Precondition
	parent   *hostOp       // child operations inherit actor and trace (ADR-0007 #5)
	creator  *hostInstance // set for InvokePlugin
	locale   string
}

func (h *fakeHost) newOp(s opSpec) *hostOp {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.newOpLocked(s)
}

func (h *fakeHost) newOpLocked(s opSpec) *hostOp {
	desc := findOp(s.target.plugin.desc, s.op)
	h.seq++
	op := &hostOp{
		id: fmt.Sprintf("op-%d", h.seq), trace: rand.Text(), locale: s.locale,
		target: s.target, creator: s.creator, desc: desc, risk: effectiveRisk(s.target.plugin.desc, desc),
		payload: s.payload, preconds: s.preconds, done: make(chan struct{}),
		state:   pb.OperationState_OPERATION_STATE_PENDING,
		history: []pb.OperationState{pb.OperationState_OPERATION_STATE_PENDING},
		changed: make(chan struct{}),
	}
	if s.actor != nil {
		op.actor = proto.Clone(s.actor).(*pb.Actor)
	}
	if s.parent != nil {
		op.parentID, op.actor, op.trace = s.parent.id, s.parent.actor, s.parent.trace
	}
	if op.locale == "" {
		op.locale = "zh-CN"
	}
	h.ops[op.id] = op
	return op
}

// setStateLocked records a transition; terminal states are final.
func (h *fakeHost) setStateLocked(op *hostOp, s pb.OperationState) bool {
	if terminal(op.state) {
		return false
	}
	op.state = s
	op.history = append(op.history, s)
	if terminal(s) {
		op.dispatched = false
		close(op.done)
		if op.cancel != nil {
			op.cancel()
		}
	}
	h.notifyLocked(op)
	return true
}

func (h *fakeHost) notifyLocked(op *hostOp) {
	close(op.changed)
	op.changed = make(chan struct{})
}

func (h *fakeHost) setState(op *hostOp, s pb.OperationState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.setStateLocked(op, s)
}

func (h *fakeHost) finish(op *hostOp, s pb.OperationState, result []byte, e *pb.ErrorDetail) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.setStateLocked(op, s) {
		op.result, op.err = result, e
	}
}

// cancelOp cancels op. A running call has its context canceled and the operation ends when the
// plugin's call returns: CANCELED, or SUCCEEDED if the terminal message won the race. An operation
// that never started is CANCELED at once.
func (h *fakeHost) cancelOp(op *hostOp) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case terminal(op.state):
	case op.cancel != nil:
		op.cancel()
	default:
		if h.setStateLocked(op, pb.OperationState_OPERATION_STATE_CANCELED) {
			op.err = &pb.ErrorDetail{Code: "CANCELED", Message: "operation canceled"}
		}
	}
}

// waitFor blocks until cond, evaluated under fakeHost.mu, holds for op.
func (h *fakeHost) waitFor(t *testing.T, op *hostOp, what string, cond func(*hostOp) bool) {
	t.Helper()
	deadline := time.After(testTimeout)
	for {
		h.mu.Lock()
		ok, changed := cond(op), op.changed
		h.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("timed out waiting for %s on %s", what, op.id)
		}
	}
}

// opView is a copy of an operation record for assertions.
type opView struct {
	State    pb.OperationState
	History  []pb.OperationState
	Progress []*pb.JobProgress
	Result   []byte
	Err      *pb.ErrorDetail
	ParentID string
	Actor    *pb.Actor
}

func (h *fakeHost) view(op *hostOp) opView {
	h.mu.Lock()
	defer h.mu.Unlock()
	return opView{State: op.state, History: append([]pb.OperationState(nil), op.history...),
		Progress: append([]*pb.JobProgress(nil), op.progress...), Result: op.result, Err: op.err,
		ParentID: op.parentID, Actor: op.actor}
}

// await waits for a terminal state.
func (h *fakeHost) await(t *testing.T, op *hostOp) opView {
	t.Helper()
	select {
	case <-op.done:
	case <-time.After(testTimeout):
		t.Fatalf("operation %s did not finish (state %v)", op.id, h.view(op).State)
	}
	return h.view(op)
}

// requestContext is the RequestContext of a call dispatched for op.
func (h *fakeHost) requestContext(op *hostOp) *pb.RequestContext {
	return &pb.RequestContext{
		RequestId:   h.nextID("req"),
		OperationId: op.id,
		TraceId:     op.trace,
		Actor:       op.actor,
		NodeId:      op.target.plugin.node,
		InstanceId:  op.target.id,
		Locale:      op.locale,
	}
}

// opContext marks op dispatched and returns the context of its plugin call, bounded by the
// operation's timeout. It returns nil when op was canceled before it started.
func (h *fakeHost) opContext(op *hostOp) context.Context {
	ctx, cancel := context.WithTimeout(h.ctx, time.Duration(op.desc.GetTimeoutMs())*time.Millisecond)
	h.mu.Lock()
	defer h.mu.Unlock()
	if terminal(op.state) {
		cancel()
		return nil
	}
	op.cancel, op.dispatched = cancel, true
	if op.state != pb.OperationState_OPERATION_STATE_RUNNING {
		h.setStateLocked(op, pb.OperationState_OPERATION_STATE_RUNNING)
	}
	return ctx
}

// dispatchInvoke is the gateway path for a mode=invoke operation that needs no approval: it creates
// the operation and calls Invoke in the background.
func (h *fakeHost) dispatchInvoke(t *testing.T, inst *hostInstance, opName string, actor *pb.Actor, payload []byte) *hostOp {
	t.Helper()
	if d := findOp(inst.plugin.desc, opName); d.GetMode() != pb.OperationMode_OPERATION_MODE_INVOKE {
		t.Fatalf("%s is not an invoke operation of %s", opName, inst.key())
	}
	op := h.newOp(opSpec{target: inst, op: opName, actor: actor, payload: payload})
	ctx := h.opContext(op)
	if ctx == nil {
		return op
	}
	h.wg.Go(func() {
		resp, err := inst.plugin.client.Invoke(ctx, &pb.InvokeRequest{
			Context: h.requestContext(op), Operation: opName, ApiVersion: op.desc.GetApiVersion(),
			PayloadJson: payload, Preconditions: op.preconds, Attempt: 1,
		})
		if err != nil {
			s, r, e := h.callFailure(ctx, err)
			h.finish(op, s, r, e)
			return
		}
		h.emitChanges(op, resp.GetChanges())
		if resp.GetError() != nil {
			h.finish(op, pb.OperationState_OPERATION_STATE_FAILED, nil, resp.GetError())
			return
		}
		h.finish(op, pb.OperationState_OPERATION_STATE_SUCCEEDED, resp.GetPayloadJson(), nil)
	})
	return op
}

// runJob starts attempt 1 of a mode=job operation in the background.
func (h *fakeHost) runJob(op *hostOp) {
	ctx := h.opContext(op)
	if ctx == nil {
		return
	}
	h.wg.Go(func() {
		s, result, e := h.followJob(ctx, op, 1)
		h.finish(op, s, result, e)
	})
}

// followJob runs one RunJob attempt and applies the stream rules of platform.proto: zero or more
// progress messages, then exactly one terminal message. A stream that breaks before the terminal
// message fails the attempt; it is never resumed.
func (h *fakeHost) followJob(ctx context.Context, op *hostOp, attempt uint32) (pb.OperationState, []byte, *pb.ErrorDetail) {
	stream, err := op.target.plugin.client.RunJob(ctx, &pb.RunJobRequest{
		Context: h.requestContext(op), Operation: op.desc.GetName(), ApiVersion: op.desc.GetApiVersion(),
		PayloadJson: op.payload, Attempt: attempt, Preconditions: op.preconds,
	})
	if err != nil {
		return h.callFailure(ctx, err)
	}
	var last *pb.JobProgress
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if last != nil {
				break // the terminal message arrived; the rest is stream teardown
			}
			return h.callFailure(ctx, err)
		}
		p := msg.GetProgress()
		switch {
		case p == nil:
			h.violation("%s: RunJob message without progress", op.id)
			continue
		case last != nil:
			h.violation("%s: message after the terminal message", op.id)
			continue
		case p.GetCompleted() && p.GetError() != nil:
			h.violation("%s: terminal message has both completed and error", op.id)
		}
		h.recordProgress(op, p)
		if p.GetCompleted() || p.GetError() != nil {
			last = p
		}
	}
	switch {
	case last == nil:
		return pb.OperationState_OPERATION_STATE_FAILED, nil,
			&pb.ErrorDetail{Code: "PROTOCOL_ERROR", Message: "RunJob ended without a terminal message"}
	case last.GetError() != nil:
		return pb.OperationState_OPERATION_STATE_FAILED, nil, last.GetError()
	}
	return pb.OperationState_OPERATION_STATE_SUCCEEDED, last.GetResultJson(), nil
}

// callFailure maps a failed plugin call to the operation outcome.
func (h *fakeHost) callFailure(ctx context.Context, err error) (pb.OperationState, []byte, *pb.ErrorDetail) {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return pb.OperationState_OPERATION_STATE_CANCELED, nil, &pb.ErrorDetail{Code: "CANCELED", Message: "operation canceled"}
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return pb.OperationState_OPERATION_STATE_FAILED, nil, &pb.ErrorDetail{Code: "DEADLINE_EXCEEDED", Message: "operation timed out"}
	}
	return pb.OperationState_OPERATION_STATE_FAILED, nil, errorFromStatus(err)
}

func (h *fakeHost) recordProgress(op *hostOp, p *pb.JobProgress) {
	h.emitChanges(op, p.GetChanges())
	h.mu.Lock()
	defer h.mu.Unlock()
	op.progress = append(op.progress, p)
	h.notifyLocked(op)
}

// emitChanges turns ResourceChange (relative subjects) into resource.changed events with the full
// subject, actor and operation_id (ADR-0007 #1, #2). A change with an invalid subject is dropped and
// recorded as a violation; the operation result stands, since its side effect already happened.
func (h *fakeHost) emitChanges(op *hostOp, changes []*pb.ResourceChange) {
	for _, c := range changes {
		subject, err := fullSubject(op.target, c.GetSubject())
		if err != nil {
			h.violation("%s: %v", op.id, err)
			continue
		}
		h.appendChange(subject, c, op.actor, op.id, op.trace, op.target.plugin.node)
	}
}

// resourceChanged is the payload the trial gives resource.changed. The ABI fixes the fields
// (ADR-0004 D3) but not their encoding in Event.payload_json (see report).
type resourceChanged struct {
	Revision        string   `json:"revision"`
	ChangedPointers []string `json:"changed_pointers"`
	Deleted         bool     `json:"deleted,omitempty"`
}

func (h *fakeHost) appendChange(subject string, c *pb.ResourceChange, actor *pb.Actor, opID, trace, node string) {
	payload := mustJSON(resourceChanged{Revision: c.GetRevision(),
		ChangedPointers: append([]string{}, c.GetChangedPointers()...), Deleted: c.GetDeleted()})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	h.events = append(h.events, &pb.Event{
		EventId: fmt.Sprintf("ev-%d", h.seq), Sequence: uint64(len(h.events) + 1),
		Type: "resource.changed", SchemaVersion: "1", Subject: subject,
		OccurredAtUnixMs: time.Now().UnixMilli(), Actor: actor, NodeId: node, TraceId: trace,
		OperationId: opID, DeliveryClass: pb.DeliveryClass_DELIVERY_CLASS_RELIABLE, PayloadJson: payload,
	})
}

// fullSubject prefixes a relative subject with the instance namespace and the fixed "resources"
// segment (platform.proto header, ADR-0007 #2), so plugin resources never collide with the host's
// own sub-resources of the instance path.
func fullSubject(inst *hostInstance, rel string) (string, error) {
	if err := validRelativeSubject(rel); err != nil {
		return "", err
	}
	p := inst.plugin
	if p.desc.GetPlacement() == pb.Placement_PLACEMENT_CONTROLLER {
		return "plugins/" + p.desc.GetPluginId() + "/resources/" + rel, nil
	}
	return "nodes/" + p.node + "/plugins/" + p.desc.GetPluginId() + "/instances/" + inst.id + "/resources/" + rel, nil
}

func (h *fakeHost) violation(format string, args ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.violations = append(h.violations, fmt.Sprintf(format, args...))
}

func (h *fakeHost) violationsSnapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.violations...)
}

// eventsOf returns the events of operation id; id "" returns events reported outside operations.
func (h *fakeHost) eventsOf(id string) []*pb.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*pb.Event
	for _, e := range h.events {
		if e.GetOperationId() == id {
			out = append(out, e)
		}
	}
	return out
}

func (h *fakeHost) childrenOf(parent *hostOp) []*hostOp {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*hostOp
	for _, op := range h.ops {
		if op.parentID == parent.id {
			out = append(out, op)
		}
	}
	return out
}
