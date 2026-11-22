// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestLoginThrottleCurve(t *testing.T) {
	clk := clock.NewFake(testStart)
	thr := NewLoginThrottle(clk.Now, DefaultThrottleOptions())
	for i := 1; i <= 2; i++ {
		wait, ok := thr.Check("alice", "10.0.0.1")
		if !ok || wait != 0 {
			t.Fatalf("attempt %d unexpectedly delayed: %v %v", i, wait, ok)
		}
		if d := thr.Fail("alice", "10.0.0.1"); d != 0 {
			t.Fatalf("failure %d delayed by %v", i, d)
		}
	}
	// The third failure arms the first delay: 1 s.
	if d := thr.Fail("alice", "10.0.0.1"); d != time.Second {
		t.Fatalf("third failure delay = %v, want 1s", d)
	}
	if wait, ok := thr.Check("alice", "10.0.0.1"); ok || wait < 900*time.Millisecond {
		t.Fatalf("throttled account allowed: wait=%v ok=%v", wait, ok)
	}
	clk.Advance(1100 * time.Millisecond)
	if wait, ok := thr.Check("alice", "10.0.0.1"); !ok || wait != 0 {
		t.Fatalf("still throttled after the delay: wait=%v ok=%v", wait, ok)
	}
	// The next failure doubles the delay.
	if d := thr.Fail("alice", "10.0.0.1"); d != 2*time.Second {
		t.Fatalf("fourth failure delay = %v, want 2s", d)
	}
	// The curve is capped at Max.
	for i := 0; i < 20; i++ {
		thr.Fail("alice", "10.0.0.1")
	}
	clk.Advance(DefaultThrottleOptions().Max + time.Second)
	thr.Fail("alice", "10.0.0.1")
	if wait, ok := thr.Check("alice", "10.0.0.1"); ok || wait > DefaultThrottleOptions().Max {
		t.Fatalf("cap exceeded: wait=%v ok=%v", wait, ok)
	}
}

func TestLoginThrottleIndependentKeys(t *testing.T) {
	clk := clock.NewFake(testStart)
	thr := NewLoginThrottle(clk.Now, DefaultThrottleOptions())
	for i := 0; i < DefaultThrottleOptions().IPThreshold; i++ {
		thr.Fail("alice", "10.0.0.1")
	}
	if _, ok := thr.Check("bob", "10.0.0.2"); !ok {
		t.Fatal("one account's failures blocked another account from another IP")
	}
	// The IP dimension catches spraying across accounts.
	if _, ok := thr.Check("carol", "10.0.0.1"); ok {
		t.Fatal("spraying from one IP was not delayed")
	}
}

func TestLoginThrottleResetAndExpiry(t *testing.T) {
	clk := clock.NewFake(testStart)
	thr := NewLoginThrottle(clk.Now, DefaultThrottleOptions())
	for i := 0; i < 4; i++ {
		thr.Fail("alice", "10.0.0.1")
	}
	thr.Reset("alice", "10.0.0.1")
	if _, ok := thr.Check("alice", "10.0.0.1"); !ok {
		t.Fatal("reset did not clear the delay")
	}
	if _, ok := thr.entries[ipKeyPrefix+"10.0.0.1"]; !ok {
		t.Fatal("reset cleared the source counter; only time may clear it")
	}
	for i := 0; i < 4; i++ {
		thr.Fail("alice", "10.0.0.1")
	}
	clk.Advance(DefaultThrottleOptions().Window + time.Minute)
	if _, ok := thr.Check("alice", "10.0.0.1"); !ok {
		t.Fatal("entry did not expire after the window")
	}
	if n := thr.Len(); n != 0 {
		t.Fatalf("expired entries not removed: %d", n)
	}
}

func TestLoginThrottleBounded(t *testing.T) {
	clk := clock.NewFake(testStart)
	opts := DefaultThrottleOptions()
	opts.MaxEntries = 8
	thr := NewLoginThrottle(clk.Now, opts)
	for i := 0; i < 100; i++ {
		thr.Fail(fmt.Sprintf("user%d", i), "10.0.0.1")
	}
	if n := thr.Len(); n > opts.MaxEntries {
		t.Fatalf("throttle grew to %d entries, cap is %d", n, opts.MaxEntries)
	}
}

// TestAttemptConcurrentChargesEachRequest is the check-then-charge race: with
// the clock frozen, concurrent attempts must see each other's charges, so
// exactly Threshold of them get through.
func TestAttemptConcurrentChargesEachRequest(t *testing.T) {
	opts := DefaultThrottleOptions()
	thr := NewLoginThrottle(clock.NewFake(testStart).Now, opts)
	const workers = 100
	var (
		wg      sync.WaitGroup
		allowed atomic.Int64
	)
	start := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, ok := thr.Attempt("alice", "203.0.113.5"); ok {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := int(allowed.Load()); got != opts.Threshold {
		t.Fatalf("%d of %d concurrent attempts passed, want exactly %d", got, workers, opts.Threshold)
	}
}

// TestEvictionNeverDropsDelayedEntry floods the table with fresh keys while the
// victim serves a delay. The clock creeps forward so the victim's entries are
// the oldest ones, which is exactly what an oldest-first eviction would drop.
// The table is smaller than the default only to keep the scans cheap under -race.
func TestEvictionNeverDropsDelayedEntry(t *testing.T) {
	clk := clock.NewFake(testStart)
	opts := DefaultThrottleOptions()
	opts.MaxEntries = 512
	thr := NewLoginThrottle(clk.Now, opts)
	for i := 0; i < opts.Threshold; i++ {
		if _, ok := thr.Attempt("victim", "198.51.100.1"); !ok {
			t.Fatalf("attempt %d refused before the threshold", i+1)
		}
	}
	for i := 0; i < 5000; i++ {
		clk.Advance(100 * time.Microsecond)
		// Every junk attempt comes from its own address, below the source limit.
		thr.Attempt(fmt.Sprintf("junk%d", i), fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&0xff, i&0xff))
	}
	if n := thr.Len(); n != opts.MaxEntries {
		t.Fatalf("flood left %d entries, want the table full at %d", n, opts.MaxEntries)
	}
	if wait, ok := thr.Attempt("victim", "198.51.100.1"); ok || wait <= 0 {
		t.Fatalf("flood erased the victim's delay: wait=%v ok=%v", wait, ok)
	}
}

// TestEvictionNeverRefusesWhenEveryEntryIsDelayed covers the saturated table:
// a new key is still admitted, at the expense of the weakest delayed entry, and
// the table stays bounded. Refusing would let a flood lock everyone out.
func TestEvictionNeverRefusesWhenEveryEntryIsDelayed(t *testing.T) {
	clk := clock.NewFake(testStart)
	opts := DefaultThrottleOptions()
	opts.MaxEntries, opts.Threshold, opts.IPThreshold, opts.AccountThreshold = 3, 1, 1, 100
	thr := NewLoginThrottle(clk.Now, opts)
	if _, ok := thr.Attempt("alice", "198.51.100.1"); !ok {
		t.Fatal("first attempt refused")
	}
	if _, ok := thr.Attempt("bob", "198.51.100.2"); !ok {
		t.Fatal("full table of delayed entries refused a new client")
	}
	if n := thr.Len(); n > opts.MaxEntries {
		t.Fatalf("throttle grew to %d entries, cap is %d", n, opts.MaxEntries)
	}
}

// TestEvictionKeepsHeavyCounterAfterDelay: once a heavily charged counter has
// served its delay it is no longer protected by the delay, yet a flood of
// single-failure junk keys still must not displace it.
func TestEvictionKeepsHeavyCounterAfterDelay(t *testing.T) {
	clk := clock.NewFake(testStart)
	opts := DefaultThrottleOptions()
	opts.MaxEntries = 512
	thr := NewLoginThrottle(clk.Now, opts)
	for i := 0; i < 20; i++ {
		thr.Attempt("victim", fmt.Sprintf("203.0.113.%d", i))
	}
	clk.Advance(opts.AccountMax + time.Second) // every delay of the victim is served
	for i := 0; i < 5000; i++ {
		thr.Attempt(fmt.Sprintf("junk%d", i), fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&0xff, i&0xff))
	}
	if e, ok := thr.entries[accountKeyPrefix+"victim"]; !ok || e.failures != 20 {
		t.Fatalf("junk flood displaced the account counter: %+v ok=%v", e, ok)
	}
}

// TestIPv6Aggregated64 changes the address inside one /64 on every attempt, the
// way an attacker holding the prefix would. Each attempt names its own account,
// so only the source counter can connect them.
func TestIPv6Aggregated64(t *testing.T) {
	opts := DefaultThrottleOptions()
	thr := NewLoginThrottle(clock.NewFake(testStart).Now, opts)
	for i := 0; i < opts.IPThreshold; i++ {
		ip := fmt.Sprintf("2001:db8:1:2::%x", i+1)
		if _, ok := thr.Attempt(fmt.Sprintf("user%d", i), ip); !ok {
			t.Fatalf("attempt %d from %s refused before the threshold", i+1, ip)
		}
	}
	if _, ok := thr.Attempt("fresh", "2001:db8:1:2:aaaa:bbbb:cccc:dddd"); ok {
		t.Fatal("another address of the same /64 escaped the source counter")
	}
	if _, ok := thr.Attempt("fresh", "2001:db8:1:3::1"); !ok {
		t.Fatal("the neighbouring /64 was throttled")
	}

	// The account+source pair aggregates the same way, whatever the spelling.
	for i := 0; i < opts.Threshold; i++ {
		if _, ok := thr.Attempt("bob", fmt.Sprintf("2001:db8:5:6::%x", i+1)); !ok {
			t.Fatalf("pair attempt %d refused before the threshold", i+1)
		}
	}
	if _, ok := thr.Attempt("bob", "2001:DB8:5:6:0:0:0:ffff"); ok {
		t.Fatal("another address of the same /64 escaped the pair counter")
	}
}

// TestIPv6AggregatedKeepsIPv4Addresses pins the other side of the aggregation:
// IPv4 stays per address, and an IPv4-mapped address is that IPv4 address.
func TestIPv6AggregatedKeepsIPv4Addresses(t *testing.T) {
	opts := DefaultThrottleOptions()
	thr := NewLoginThrottle(clock.NewFake(testStart).Now, opts)
	for i := 0; i < opts.Threshold; i++ {
		if _, ok := thr.Attempt("alice", "198.51.100.7"); !ok {
			t.Fatalf("attempt %d refused before the threshold", i+1)
		}
	}
	if _, ok := thr.Attempt("alice", "::ffff:198.51.100.7"); ok {
		t.Fatal("the IPv4-mapped form escaped the IPv4 counter")
	}
	if _, ok := thr.Attempt("alice", "198.51.100.8"); !ok {
		t.Fatal("IPv4 neighbours were aggregated")
	}
}

// TestAccountKeyDoesNotLockOtherIPs is the lockout attack: ten real failures
// from one source must not stop the owner signing in from somewhere else.
func TestAccountKeyDoesNotLockOtherIPs(t *testing.T) {
	clk := clock.NewFake(testStart)
	opts := DefaultThrottleOptions()
	thr := NewLoginThrottle(clk.Now, opts)
	for i := 0; i < 10; i++ {
		clk.Advance(opts.Max + time.Second) // serve the delay of the previous failure
		if _, ok := thr.Attempt("admin", "198.51.100.1"); !ok {
			t.Fatalf("attempt %d refused after its delay was served", i+1)
		}
	}
	if _, ok := thr.Attempt("admin", "198.51.100.1"); ok {
		t.Fatal("the attacking source was not delayed")
	}
	if wait, ok := thr.Attempt("admin", "198.51.100.2"); !ok {
		t.Fatalf("another source was locked out of the account: wait=%v", wait)
	}
}

// TestAccountKeyEngagesLateAndStaysShort drives the account-wide counter from
// a different source each time: it stays silent up to AccountThreshold, then
// slows the account down, but never for longer than AccountMax.
func TestAccountKeyEngagesLateAndStaysShort(t *testing.T) {
	clk := clock.NewFake(testStart)
	opts := DefaultThrottleOptions()
	thr := NewLoginThrottle(clk.Now, opts)
	source := func(i int) string { return fmt.Sprintf("10.1.%d.%d", i>>8, i&0xff) }
	for i := 0; i < opts.AccountThreshold; i++ {
		if _, ok := thr.Attempt("admin", source(i)); !ok {
			t.Fatalf("attempt %d refused before the account threshold", i+1)
		}
	}
	if wait, ok := thr.Attempt("admin", source(1000)); ok || wait != opts.Base {
		t.Fatalf("account counter did not engage: wait=%v ok=%v", wait, ok)
	}
	for i := 0; i < 20; i++ {
		clk.Advance(opts.AccountMax + time.Second)
		if _, ok := thr.Attempt("admin", source(2000+i)); !ok {
			t.Fatalf("attempt %d refused after the account delay was served", i+1)
		}
	}
	if wait, ok := thr.Attempt("admin", source(3000)); ok || wait != opts.AccountMax {
		t.Fatalf("account delay = %v (ok=%v), want the %v cap", wait, ok, opts.AccountMax)
	}
}

// TestLoginBackoffIntegration exercises the service-level behaviour: a wrong
// password is UNAUTHENTICATED, repeated failures answer RATE_LIMITED with a
// Retry-After, waiting unlocks, and a success clears every counter.
func TestLoginBackoffIntegration(t *testing.T) {
	f := newFixture(t)
	f.createUser("alice", testPassword, RoleOperator)
	wrong := LoginInput{Username: "alice", Password: "definitely-not-it", ClientIP: "198.51.100.9"}
	for i := 0; i < 3; i++ {
		if _, err := f.svc.Login(f.ctx, wrong); !problem.HasCode(err, problem.Unauthenticated) {
			t.Fatalf("failure %d: %v", i+1, err)
		}
	}
	_, err := f.svc.Login(f.ctx, wrong)
	if !problem.HasCode(err, problem.RateLimited) {
		t.Fatalf("expected RATE_LIMITED, got %v", err)
	}
	var pe *problem.Error
	if !asProblem(err, &pe) || pe.RetryAfterSec < 1 {
		t.Fatalf("rate limit without retry_after: %v", err)
	}
	// The right password is also throttled until the delay passes.
	if _, err := f.svc.Login(f.ctx, LoginInput{Username: "alice", Password: testPassword, ClientIP: "198.51.100.9"}); !problem.HasCode(err, problem.RateLimited) {
		t.Fatalf("correct password bypassed the throttle: %v", err)
	}
	f.clk.Advance(2 * time.Second)
	res, err := f.svc.Login(f.ctx, LoginInput{Username: "alice", Password: testPassword, ClientIP: "198.51.100.9"})
	if err != nil {
		t.Fatalf("login after the delay: %v", err)
	}
	if !res.Authenticated() {
		t.Fatal("login did not complete")
	}
	if _, ok := f.svc.thr.entries[pairKeyPrefix+"alice|198.51.100.9"]; ok {
		t.Fatal("success did not clear the account+source counter")
	}
	if f.audit.count(ActionLoginFailed) < 3 {
		t.Fatal("failed logins were not audited")
	}
	if f.audit.count(ActionLogin) != 1 {
		t.Fatalf("successful login audits = %d, want 1", f.audit.count(ActionLogin))
	}
}

// TestResetKeepsSourceCounter: an attacker who logs in to an account of their
// own must not wipe the spraying counter of their source.
func TestResetKeepsSourceCounter(t *testing.T) {
	opts := DefaultThrottleOptions()
	thr := NewLoginThrottle(clock.NewFake(testStart).Now, opts)
	for i := 0; i < opts.IPThreshold-1; i++ {
		thr.Attempt(fmt.Sprintf("victim%d", i), "198.51.100.5")
	}
	thr.Attempt("mallory", "198.51.100.5")
	thr.Reset("mallory", "198.51.100.5")
	if _, ok := thr.Attempt("victim-next", "198.51.100.5"); ok {
		t.Fatal("own successful login cleared the source counter")
	}
}
