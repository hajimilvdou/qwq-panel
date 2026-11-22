// SPDX-License-Identifier: AGPL-3.0-only

package ids

import (
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEncodeSpecVector(t *testing.T) {
	// Test vector from the TypeID specification.
	raw, _ := hex.DecodeString("01890a5dac96774bbcceb302099a8057")
	var u [16]byte
	copy(u[:], raw)
	if got, want := encode(u), "01h455vb4pex5vsknk084sn02q"; got != want {
		t.Fatalf("encode = %s, want %s", got, want)
	}
	var max [16]byte
	for i := range max {
		max[i] = 0xff
	}
	if got := encode(max); got != "7zzzzzzzzzzzzzzzzzzzzzzzzz" {
		t.Fatalf("encode(max) = %s", got)
	}
}

func TestNewFormatAndVersion(t *testing.T) {
	g := New(nil)
	id := g.New(Operation)
	if !strings.HasPrefix(id, "op_") || len(id) != 3+26 {
		t.Fatalf("id %q", id)
	}
	if err := Check(id, Operation); err != nil {
		t.Fatal(err)
	}
	u := g.uuid()
	if u[6]>>4 != 7 || u[8]>>6 != 2 {
		t.Fatalf("version/variant bits wrong: %x", u)
	}
}

func TestMonotonicWithinMillisecond(t *testing.T) {
	fixed := time.UnixMilli(1_700_000_000_000)
	g := New(func() time.Time { return fixed })
	prev := ""
	for i := 0; i < 10000; i++ { // crosses several counter overflows
		id := g.New(Event)
		if id <= prev {
			t.Fatalf("not increasing at %d: %s <= %s", i, id, prev)
		}
		prev = id
	}
}

func TestClockGoingBackwardsStaysMonotonic(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	g := New(func() time.Time { return now })
	a := g.New(Event)
	now = now.Add(-time.Hour)
	b := g.New(Event)
	if b <= a {
		t.Fatalf("%s <= %s after clock step back", b, a)
	}
}

func TestConcurrentUnique(t *testing.T) {
	g := New(nil)
	const workers, per = 8, 2000
	out := make([][]string, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				out[w] = append(out[w], g.New(Request))
			}
		}(w)
	}
	wg.Wait()
	var all []string
	for _, s := range out {
		all = append(all, s...)
	}
	sort.Strings(all)
	for i := 1; i < len(all); i++ {
		if all[i] == all[i-1] {
			t.Fatalf("duplicate id %s", all[i])
		}
	}
}

func TestCheck(t *testing.T) {
	good := New(nil).New(User)
	bad := []string{
		"", "usr", "usr_", "op_" + good[4:], "USR_" + good[4:], good + "0",
		"usr_8" + good[5:],                 // overflows 128 bits
		"usr_" + good[4:29] + "u",          // 'u' is not in the alphabet
		"usr-" + good[4:],                  // wrong separator
		"usr_" + strings.ToUpper(good[4:]), // upper case
	}
	for _, s := range bad {
		if Valid(s, User) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
	if !Valid(good, User) {
		t.Errorf("Valid(%q) = false", good)
	}
}

func TestInvalidPrefixPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	New(nil).New("Op")
}

func TestTraceID(t *testing.T) {
	id := TraceID()
	if !ValidTraceID(id) {
		t.Fatalf("TraceID() = %q", id)
	}
	for _, s := range []string{"", strings.Repeat("0", 32), strings.Repeat("g", 32), strings.Repeat("A", 32)} {
		if ValidTraceID(s) {
			t.Errorf("ValidTraceID(%q) = true", s)
		}
	}
}

func BenchmarkNew(b *testing.B) {
	g := New(nil)
	for i := 0; i < b.N; i++ {
		_ = g.New(Event)
	}
}
