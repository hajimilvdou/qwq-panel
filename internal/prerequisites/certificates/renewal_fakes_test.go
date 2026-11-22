// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
)

type fakeRenewalConfirmations struct {
	mu                  sync.Mutex
	allowed             RenewalScope
	revoked             bool
	confirms, validates int
}

func (c *fakeRenewalConfirmations) Confirm(ctx context.Context, caller Caller, scope RenewalScope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if caller.OwnerID != "owner-1" || caller.PolicyID != "" || caller.OperationID == "" {
		return fault.New("PERMISSION_DENIED", "必须是当前人类确认 operation")
	}
	c.confirms++
	if c.allowed.CertificateID == "" {
		c.allowed = scope
	}
	return nil
}

func (c *fakeRenewalConfirmations) Validate(ctx context.Context, scope RenewalScope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.validates++
	if c.revoked || !sameRenewalScope(c.allowed, scope) {
		return fault.New("POLICY_REVOKED", "宿主注册范围或凭据已撤销")
	}
	return nil
}

type fakeRenewalOperations struct {
	mu               sync.Mutex
	begins, finishes int
	attempts         []string
	scopes           []RenewalScope
	finishFailure    bool
	beginFailure     bool
	wrongOwner       bool
}

// 只供原库协议fixture；不作为实际宿主private Context或运行proof。
type fakeRenewalContexts struct{}

func (fakeRenewalContexts) Context(ctx context.Context, request RenewalContextRequest) (context.Context, context.CancelFunc, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if validateCaller(request.Caller, true) != nil || request.Caller.PolicyID == "" || request.RunAttemptID == "" {
		return nil, nil, fault.New("PERMISSION_DENIED", "fixture原service请求无效")
	}
	bounded, cancel := context.WithCancel(ctx)
	return bounded, cancel, nil
}

func (o *fakeRenewalOperations) Begin(ctx context.Context, id, revision, attempt string, scope RenewalScope) (Caller, error) {
	if err := ctx.Err(); err != nil {
		return Caller{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.begins++
	o.attempts = append(o.attempts, attempt)
	o.scopes = append(o.scopes, scope)
	if o.beginFailure {
		return Caller{}, errors.New("DO-NOT-EXPOSE-OPERATION")
	}
	owner := scope.OwnerID
	if o.wrongOwner {
		owner = "other-owner"
	}
	return Caller{OwnerID: owner, OperationID: "service-" + attempt, PolicyID: id, PolicyRevision: revision}, nil
}

func (o *fakeRenewalOperations) Finish(ctx context.Context, _ Caller, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.finishes++
	if o.finishFailure {
		return errors.New("DO-NOT-EXPOSE-AUDIT")
	}
	return nil
}

type renewalFixture struct {
	fixture
	service       *RenewalService
	private       *testsupport.MemoryStore
	confirmations *fakeRenewalConfirmations
	operations    *fakeRenewalOperations
	scope         RenewalScope
}

func newRenewalFixture(t *testing.T, consumers ...Consumer) *renewalFixture {
	t.Helper()
	f := newFixture(t)
	view := f.issue(t, "initial-issue").View
	for index, bound := range consumers {
		result, err := f.manager.BindCertificate(context.Background(), BindRequest{Caller: f.caller, CertificateID: view.ID, AttemptID: "initial-bind-" + strconv.Itoa(index), ExpectedRevision: view.Revision, Generation: 1, Consumer: bound})
		if err != nil {
			t.Fatal(err)
		}
		view = result.View
	}
	slices.SortFunc(consumers, stringsCompareConsumer)
	r := &renewalFixture{fixture: f, private: &testsupport.MemoryStore{}, confirmations: &fakeRenewalConfirmations{}, operations: &fakeRenewalOperations{},
		scope: RenewalScope{OwnerID: f.caller.OwnerID, CertificateID: view.ID, Issuance: f.scope, Consumers: consumers}}
	r.restart(t)
	if _, err := r.service.Enable(context.Background(), r.caller, "policy-1", MissingRevision, r.scope); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *renewalFixture) restart(t *testing.T) {
	t.Helper()
	service, err := NewRenewalService(RenewalOptions{Repository: r.private, Manager: r.manager, Confirmations: r.confirmations, Operations: r.operations, Contexts: fakeRenewalContexts{}, Clock: r.clock, RetryBase: time.Minute, JobTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	r.service = service
	r.authorization.policyCheck = func(request Authorization) error { return service.Authorize(context.Background(), request) }
}

func (r *renewalFixture) due(t *testing.T) {
	t.Helper()
	view, err := r.service.Get(context.Background(), r.caller, "policy-1")
	if err != nil {
		t.Fatal(err)
	}
	if delay := view.NextAt.Sub(r.clock.Now()); delay > 0 {
		r.clock.Advance(delay)
	}
}

func (r *renewalFixture) policy(t *testing.T) renewalPolicy {
	t.Helper()
	ledger, _, err := r.service.load(context.Background())
	if err != nil || len(ledger.Policies) != 1 {
		t.Fatalf("ledger load error: %v, policy count: %d", err, len(ledger.Policies))
	}
	return ledger.Policies[0]
}
