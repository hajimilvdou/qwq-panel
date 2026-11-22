// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

type fakeResolver struct {
	mu            sync.Mutex
	clock         *clock.Fake
	calls         int
	values        []string
	error         error
	onlyRecursive bool
}

func (r *fakeResolver) Observe(_ context.Context, _ Scope, _ string, _ RecordType) ([]Observation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.error != nil {
		return nil, r.error
	}
	now := r.clock.Now()
	result := []Observation{{Source: "recursive-1", Kind: Recursive, Values: append([]string(nil), r.values...), CollectedAt: now}}
	if !r.onlyRecursive {
		result = append(result, Observation{Source: "authoritative-1", Kind: Authoritative, Values: append([]string(nil), r.values...), CollectedAt: now})
	}
	return result, nil
}

func (r *fakeResolver) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func checkerFixture(t *testing.T, f fixture, resolver *fakeResolver, attempts int) *Checker {
	t.Helper()
	checker, err := NewChecker(CheckerOptions{Resolver: resolver, Authorizer: f.authorization, Clock: f.clock, MaxAttempts: attempts,
		Interval: time.Second, MaxWait: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return checker
}

func propagationRequest(f fixture, record Record) PropagationRequest {
	return PropagationRequest{Caller: f.caller, Scope: f.scope, Record: record}
}

func waitTimer(t *testing.T, fake *clock.Fake) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for fake.Waiters() == 0 {
		select {
		case <-deadline:
			t.Fatal("fake clock timer was not armed")
		case <-ticker.C:
		}
	}
}

func TestPropagationRequiresBothAuthoritativeAndRecursive(t *testing.T) {
	f := newFixture(t)
	resolver := &fakeResolver{clock: f.clock, values: []string{"192.0.2.10"}}
	checker := checkerFixture(t, f, resolver, 3)
	request := propagationRequest(f, Record{Type: A, Name: "proxy.example.com", Value: "192.0.2.10", TTL: 300})
	result, err := checker.Check(context.Background(), request)
	if err != nil || !result.Ready || len(result.Observations) != 2 {
		t.Fatalf("check = %v, %v", result, err)
	}
	resolver.onlyRecursive = true
	_, err = checker.Check(context.Background(), request)
	requireCode(t, err, "DNS_NO_SOURCES")
}

func TestPropagationDistinguishesAAAAAndPreservesTXTSet(t *testing.T) {
	f := newFixture(t)
	resolver := &fakeResolver{clock: f.clock, values: []string{"2001:db8::11"}}
	checker := checkerFixture(t, f, resolver, 3)
	result, err := checker.Check(context.Background(), propagationRequest(f, Record{Type: AAAA, Name: "proxy.example.com", Value: "2001:db8::10", TTL: 300}))
	if err != nil || result.Ready || result.Code != "AAAA_NODE_MISMATCH" {
		t.Fatalf("AAAA check = %v, %v", result, err)
	}
	resolver.values = []string{"other-challenge", "ours"}
	result, err = checker.Check(context.Background(), propagationRequest(f, Record{Type: TXT, Name: "_acme-challenge.proxy.example.com", Value: "ours", TTL: 60}))
	if err != nil || !result.Ready {
		t.Fatalf("TXT check = %v, %v", result, err)
	}
}

func TestPropagationBoundedRetryHonorsProviderRetryAfter(t *testing.T) {
	f := newFixture(t)
	resolver := &fakeResolver{clock: f.clock, error: &fault.Error{Code: "RATE_LIMITED", RetryAt: f.clock.Now().Add(10 * time.Second)}}
	checker := checkerFixture(t, f, resolver, 2)
	request := propagationRequest(f, Record{Type: A, Name: "proxy.example.com", Value: "192.0.2.10", TTL: 300})
	done := make(chan error, 1)
	go func() { _, err := checker.Wait(context.Background(), request); done <- err }()
	waitTimer(t, f.clock)
	f.clock.Advance(9 * time.Second)
	if resolver.count() != 1 {
		t.Fatal("retried before Retry-After")
	}
	f.clock.Advance(time.Second)
	select {
	case err := <-done:
		requireCode(t, err, "RATE_LIMITED")
	case <-time.After(2 * time.Second):
		t.Fatal("bounded retry did not finish")
	}
	if resolver.count() != 2 {
		t.Fatalf("queries = %d", resolver.count())
	}
}

func TestPropagationCancellationAndRevocationStopQueries(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "revoke"}[revoked], func(t *testing.T) {
			f := newFixture(t)
			resolver := &fakeResolver{clock: f.clock, values: []string{}}
			checker := checkerFixture(t, f, resolver, 3)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := checker.Wait(ctx, propagationRequest(f, Record{Type: A, Name: "proxy.example.com", Value: "192.0.2.10", TTL: 300}))
				done <- err
			}()
			waitTimer(t, f.clock)
			if revoked {
				f.authorization.revoke()
				f.clock.Advance(time.Second)
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if revoked {
					requireCode(t, err, "CREDENTIAL_REVOKED")
				} else if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("wait did not stop")
			}
			if resolver.count() != 1 {
				t.Fatal("queries continued after cancel/revoke")
			}
		})
	}
}

func TestPropagationRetryCannotExceedTimeBudget(t *testing.T) {
	f := newFixture(t)
	resolver := &fakeResolver{clock: f.clock, error: &fault.Error{Code: "RATE_LIMITED", RetryAt: f.clock.Now().Add(time.Hour)}}
	checker := checkerFixture(t, f, resolver, 5)
	_, err := checker.Wait(context.Background(), propagationRequest(f, Record{Type: A, Name: "proxy.example.com", Value: "192.0.2.10", TTL: 300}))
	requireCode(t, err, "DNS_TIMEOUT")
	if resolver.count() != 1 || f.clock.Waiters() != 0 {
		t.Fatal("out-of-budget retry was scheduled")
	}
}
