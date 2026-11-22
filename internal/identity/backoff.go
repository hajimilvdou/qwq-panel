// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Key prefixes of the throttle entries. The prefix selects the backoff curve.
const (
	pairKeyPrefix    = "p:" // one account from one client
	ipKeyPrefix      = "i:" // one client, any account
	accountKeyPrefix = "u:" // one account, any client
)

// ThrottleOptions configure the progressive login backoff. An attempt counts
// against three key classes, each on its own curve (see throttleKeys).
type ThrottleOptions struct {
	// MaxEntries bounds the memory used by the throttle (up to three entries
	// per account and client). 4096 entries cost roughly 0.5 MiB.
	MaxEntries int
	// Window forgets an entry after this long without a failure.
	Window time.Duration
	// Threshold is the number of failures of one account from one client within
	// the window before any delay applies: typos stay cheap.
	Threshold int
	// Base is the delay when a class reaches its threshold; it doubles for every
	// further failure.
	Base time.Duration
	// Max caps the delay of one account from one client. There is no hard
	// lockout: waiting long enough always unlocks the account (ARCH §4.1.1).
	Max time.Duration
	// IPThreshold and IPMax are the curve of one client across all accounts,
	// which catches password spraying.
	IPThreshold int
	IPMax       time.Duration
	// AccountThreshold and AccountMax are the curve of one account across all
	// clients. It only has to slow distributed guessing of a short TOTP code, so
	// it starts late and stays short; the long delays belong to the pair curve,
	// which a stranger cannot trigger for another client.
	AccountThreshold int
	AccountMax       time.Duration
}

// DefaultThrottleOptions returns the host's backoff curves. One account from
// one client gets no delay for the first two failures, then 1 s, 2 s, 4 s, ...
// capped at 5 minutes; one client starts the same curve after 10 failures
// across accounts; one account, from anywhere, after 30 failures and capped at
// 30 seconds. With the 15 minute window this stops online guessing while a user
// who mistypes twice never notices.
func DefaultThrottleOptions() ThrottleOptions {
	return ThrottleOptions{
		MaxEntries:       4096,
		Window:           15 * time.Minute,
		Threshold:        3,
		Base:             time.Second,
		Max:              5 * time.Minute,
		IPThreshold:      10,
		IPMax:            5 * time.Minute,
		AccountThreshold: 30,
		AccountMax:       30 * time.Second,
	}
}

// LoginThrottle is the progressive login backoff, keyed by account and client
// together, by client and by account (ARCH §4.1.1). It is an in-memory cache
// bound to one host process: restarting the host clears it, which is acceptable
// because a restart also makes guesses no cheaper for the attacker. Entries are
// evicted by expiry and, when the map is full, least valuable first (see
// evictLocked); a full table never refuses an attempt.
type LoginThrottle struct {
	mu   sync.Mutex
	now  func() time.Time
	opts ThrottleOptions
	// entries maps the keys built by throttleKeys to the failure state.
	entries map[string]*throttleEntry
}

type throttleEntry struct {
	failures int
	last     time.Time
	// waitUntil is when the current delay expires; zero when no delay applies.
	waitUntil time.Time
}

// NewLoginThrottle returns a throttle. A zero-value option set is replaced by
// DefaultThrottleOptions; individual zero fields are filled from the defaults.
func NewLoginThrottle(now func() time.Time, opts ThrottleOptions) *LoginThrottle {
	if now == nil {
		now = time.Now
	}
	def := DefaultThrottleOptions()
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = def.MaxEntries
	}
	if opts.Window <= 0 {
		opts.Window = def.Window
	}
	if opts.Threshold <= 0 {
		opts.Threshold = def.Threshold
	}
	if opts.Base <= 0 {
		opts.Base = def.Base
	}
	if opts.Max <= 0 {
		opts.Max = def.Max
	}
	if opts.IPThreshold <= 0 {
		opts.IPThreshold = def.IPThreshold
	}
	if opts.IPMax <= 0 {
		opts.IPMax = def.IPMax
	}
	if opts.AccountThreshold <= 0 {
		opts.AccountThreshold = def.AccountThreshold
	}
	if opts.AccountMax <= 0 {
		opts.AccountMax = def.AccountMax
	}
	return &LoginThrottle{now: now, opts: opts, entries: make(map[string]*throttleEntry)}
}

// Check reports how long the caller must wait before this account/IP pair may
// try again, and false when the attempt must be refused now. It also expires
// old entries. It charges nothing; the login paths use Attempt.
func (t *LoginThrottle) Check(account, clientIP string) (time.Duration, bool) {
	if t == nil {
		return 0, true
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	wait := t.waitLocked(throttleKeys(account, clientIP), now)
	return wait, wait == 0
}

// Attempt atomically checks the backoff and charges one failure up front, so
// concurrent guesses see each other's charges. Only a complete authentication
// refunds it, through Reset. It returns how long to wait and whether the
// attempt may proceed; a refused attempt charges nothing. Every delay is
// bounded by its class cap: no attacker can lock an account out for good.
func (t *LoginThrottle) Attempt(account, clientIP string) (time.Duration, bool) {
	if t == nil {
		return 0, true
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	keys := throttleKeys(account, clientIP)
	if wait := t.waitLocked(keys, now); wait > 0 {
		return wait, false
	}
	t.failLocked(keys, now)
	return 0, true
}

// Fail records one failed attempt for the account and the client IP. It returns
// the delay that now applies (zero when still below the thresholds).
func (t *LoginThrottle) Fail(account, clientIP string) time.Duration {
	if t == nil {
		return 0
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	keys := throttleKeys(account, clientIP)
	t.failLocked(keys, now)
	return t.waitLocked(keys, now)
}

// Reset clears the account+client entry. It is called only after a complete
// authentication, so a user who finally gets the password or code right is not
// penalised for earlier typos. The client and account entries only decay with
// time: otherwise an attacker could log in to an account of their own now and
// then to wipe the spraying counter of their source.
func (t *LoginThrottle) Reset(account, clientIP string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, key := range throttleKeys(account, clientIP) {
		if strings.HasPrefix(key, pairKeyPrefix) {
			delete(t.entries, key)
		}
	}
}

// Len reports the number of tracked entries (tests and metrics).
func (t *LoginThrottle) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// delay returns the wait after n consecutive failures of key: below the class
// threshold there is none, then Base doubling per failure up to the class cap.
func (t *LoginThrottle) delay(key string, failures int) time.Duration {
	threshold, limit := t.curve(key)
	if failures < threshold {
		return 0
	}
	d := t.opts.Base
	for i := threshold; i < failures && d < limit; i++ {
		d *= 2
	}
	if d > limit {
		d = limit
	}
	return d
}

// curve returns the threshold and the cap of the class key belongs to.
func (t *LoginThrottle) curve(key string) (int, time.Duration) {
	switch {
	case strings.HasPrefix(key, ipKeyPrefix):
		return t.opts.IPThreshold, t.opts.IPMax
	case strings.HasPrefix(key, accountKeyPrefix):
		return t.opts.AccountThreshold, t.opts.AccountMax
	default:
		return t.opts.Threshold, t.opts.Max
	}
}

// waitLocked returns the longest delay the keys are serving and forgets the
// ones past the window. Callers hold t.mu.
func (t *LoginThrottle) waitLocked(keys []string, now time.Time) time.Duration {
	var wait time.Duration
	for _, key := range keys {
		e, ok := t.entries[key]
		if !ok {
			continue
		}
		if now.Sub(e.last) > t.opts.Window {
			delete(t.entries, key)
			continue
		}
		if d := e.waitUntil.Sub(now); d > wait {
			wait = d
		}
	}
	return wait
}

// failLocked charges one failure to every key. A full table makes room through
// evictLocked first; it never refuses, so a flood of junk keys can neither lock
// legitimate users out nor grow the table past MaxEntries (plus the keys of one
// attempt when MaxEntries is smaller than that). Callers hold t.mu.
func (t *LoginThrottle) failLocked(keys []string, now time.Time) {
	missing := 0
	for _, key := range keys {
		if _, ok := t.entries[key]; !ok {
			missing++
		}
	}
	for len(t.entries)+missing > t.opts.MaxEntries {
		if !t.evictLocked(now, keys) {
			break
		}
	}
	for _, key := range keys {
		e, ok := t.entries[key]
		if !ok || now.Sub(e.last) > t.opts.Window {
			e = &throttleEntry{}
			t.entries[key] = e
		}
		e.failures++
		e.last = now
		e.waitUntil = now.Add(t.delay(key, e.failures))
	}
}

// evictLocked frees room in a full table. Expired entries go first; otherwise
// the least valuable entry goes: one not serving a delay before one that is,
// then the fewest failures, then the oldest last failure (LRU). Junk keys carry
// a single failure and no delay, so they always go before a counter that is
// actually slowing an attacker down; displacing such a counter would require
// filling the table with even heavier ones. keep, the counters of the attempt
// being charged, is never a candidate. It returns false when nothing could be
// freed. Callers hold t.mu.
func (t *LoginThrottle) evictLocked(now time.Time, keep []string) bool {
	victimKey, purged := "", false
	var victim *throttleEntry
	for k, e := range t.entries {
		if slices.Contains(keep, k) {
			continue
		}
		if now.Sub(e.last) > t.opts.Window {
			delete(t.entries, k)
			purged = true
			continue
		}
		if victim == nil || lessValuable(e, victim, now) {
			victimKey, victim = k, e
		}
	}
	if purged {
		return true
	}
	if victim == nil {
		return false
	}
	delete(t.entries, victimKey)
	return true
}

// lessValuable orders eviction candidates: idle before delayed, then fewer
// failures, then older last failure.
func lessValuable(a, b *throttleEntry, now time.Time) bool {
	if da, db := a.waitUntil.After(now), b.waitUntil.After(now); da != db {
		return !da
	}
	if a.failures != b.failures {
		return a.failures < b.failures
	}
	return a.last.Before(b.last)
}

// throttleKeys returns the counters one attempt charges:
//
//	p:<account>|<client>  guessing one account from one client (the main defence)
//	i:<client>            spraying many accounts from one client
//	u:<account>           guessing one account from many clients
//
// <client> is the aggregated address (see aggregateClient). Without a client
// address the pair key is still used, shared by all such attempts, so that the
// main defence does not switch off.
func throttleKeys(account, clientIP string) []string {
	acct := strings.ToLower(strings.TrimSpace(account))
	client := aggregateClient(strings.TrimSpace(clientIP))
	keys := make([]string, 0, 3)
	if acct != "" {
		keys = append(keys, pairKeyPrefix+acct+"|"+client, accountKeyPrefix+acct)
	}
	if client != "" {
		keys = append(keys, ipKeyPrefix+client)
	}
	return keys
}

// aggregateClient maps an address to the unit an attacker has to pay for: one
// IPv4 address or one IPv6 /64, the smallest network a customer is assigned. An
// IPv4-mapped address counts as that IPv4 address; a value that does not parse
// is used as given.
func aggregateClient(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64) // cannot fail: 64 is within an IPv6 address
	return p.String()
}
