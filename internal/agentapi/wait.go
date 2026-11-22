// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// waitPollInterval is how long the wait loop sleeps between two polls. The
// service signals state changes through the clock, so a short interval keeps
// the tool responsive without polling SQL in a tight loop.
const waitPollInterval = 100 * time.Millisecond

// waitRequest is the WaitRequest schema. TimeoutSeconds is a pointer so an
// explicit 0 is a schema violation (minimum 1) instead of the default.
type waitRequest struct {
	OperationID    string `json:"operation_id"`
	TimeoutSeconds *int   `json:"timeout_seconds,omitempty"`
}

// check validates the request against the schema.
func (req *waitRequest) check() error {
	if err := checkResourceID("/operation_id", req.OperationID); err != nil {
		return err
	}
	if req.TimeoutSeconds != nil &&
		(*req.TimeoutSeconds < 1 || *req.TimeoutSeconds > WaitTimeoutMaxSeconds) {
		return outOfRange("/timeout_seconds", "The timeout must be between 1 and 55 seconds.")
	}
	return nil
}

// wait implements POST /api/v1/agent/wait: a server-side long poll that returns
// as soon as the operation is terminal, as soon as it enters AWAITING_APPROVAL
// (unless it was already there when the call started), or when the timeout
// elapses with timed_out=true.
func (h *handlers) wait(w http.ResponseWriter, r *http.Request) {
	c, err := h.begin(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !c.view.allowsRead("host.operations") {
		h.fail(w, r, problem.New(problem.PermissionDenied, "The delegation cannot read operations."))
		return
	}
	var req waitRequest
	if err := h.decode(r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := req.check(); err != nil {
		h.fail(w, r, err)
		return
	}
	timeout := WaitTimeoutDefault
	if req.TimeoutSeconds != nil {
		timeout = time.Duration(*req.TimeoutSeconds) * time.Second
	}

	// At most agent_concurrent_waits_per_delegation waits at a time. The map of
	// the limiter only holds delegations with a wait in flight and is pruned to
	// empty, so it cannot grow with the history of tokens.
	key := c.actor.ID
	if !h.waits.acquire(key) {
		e := problem.New(problem.RateLimited,
			"At most %d wait calls can run at once for one delegation.", ConcurrentWaitsPerDelegation)
		e.Limit = &problem.Limit{
			Name: "agent_concurrent_waits_per_delegation",
			Max:  ConcurrentWaitsPerDelegation,
		}
		e.RetryAfterSec = 1
		h.fail(w, r, e)
		return
	}
	defer h.waits.release(key)

	ctx := r.Context()
	// The operation is loaded first for two reasons: an unknown operation is a
	// 404 before any polling, and the state at call time decides whether
	// AWAITING_APPROVAL ends the wait or is waited through.
	start, err := h.ops.Get(ctx, c.actor, req.OperationID)
	if err != nil {
		h.fail(w, r, notFoundOr(err))
		return
	}
	current, timedOut, err := h.await(ctx, c.actor, req.OperationID, start.Status, timeout)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := current.Outcome()
	out.TimedOut = timedOut
	body, err := outcomeBody(out)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.write(w, r, body)
}

// await long-polls one operation. It returns the operation and whether the
// timeout elapsed. A wait that started while the operation was already awaiting
// an approval keeps waiting for the human decision, as openapi.yaml requires.
func (h *handlers) await(ctx context.Context, a actor.Actor, id string,
	start operations.Status, timeout time.Duration) (*operations.Operation, bool, error) {
	deadline := h.clock.Now().Add(timeout)
	for {
		remaining := deadline.Sub(h.clock.Now())
		if remaining <= 0 {
			op, err := h.ops.Get(ctx, a, id)
			if err != nil {
				return nil, false, notFoundOr(err)
			}
			return op, true, nil
		}
		op, err := h.ops.Wait(ctx, a, id, remaining)
		if err != nil {
			return nil, false, notFoundOr(err)
		}
		if terminal(op.Status) ||
			(op.Status == operations.AwaitingApproval && start != operations.AwaitingApproval) {
			return op, false, nil
		}
		select {
		case <-ctx.Done():
			return nil, false, problem.From(ctx.Err())
		case <-h.clock.After(waitPollInterval):
		}
	}
}

// terminal reports whether no further transition is possible (the state machine
// of ADR-0004 D7).
func terminal(s operations.Status) bool {
	switch s {
	case operations.Succeeded, operations.Failed, operations.Canceled,
		operations.Rejected, operations.Expired:
		return true
	}
	return false
}

// waitLimiter counts concurrent waits per delegation. It is bounded by the
// number of waits in flight: an entry is removed when its last wait ends, so a
// long-lived host does not accumulate one entry per token it ever saw.
type waitLimiter struct {
	mu     sync.Mutex
	max    int
	active map[string]int
}

// newWaitLimiter returns a limiter allowing max concurrent waits per key.
func newWaitLimiter(max int) *waitLimiter {
	if max <= 0 {
		max = 1
	}
	return &waitLimiter{max: max, active: map[string]int{}}
}

// acquire reserves one wait slot for key.
func (l *waitLimiter) acquire(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[key] >= l.max {
		return false
	}
	l.active[key]++
	return true
}

// release returns one wait slot for key and forgets the key when it is idle.
func (l *waitLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.active[key] - 1
	if n <= 0 {
		delete(l.active, key)
		return
	}
	l.active[key] = n
}

// count reports the waits in flight for key (tests).
func (l *waitLimiter) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active[key]
}
