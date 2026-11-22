// SPDX-License-Identifier: AGPL-3.0-only

// Package ids generates resource identifiers.
//
// An ID is "<prefix>_<suffix>": a short lower-case prefix naming the resource
// kind and a UUIDv7 encoded as 26 characters of lower-case Crockford base32
// (the TypeID format). IDs sort by creation time, which keeps SQLite primary
// keys append-friendly and cursors stable; the prefix tells a human or an AI
// client what kind of object an ID refers to. IDs carry no authority: knowing
// one never grants access.
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Prefixes of host resources.
const (
	User        = "usr"
	Session     = "ses"
	Role        = "rol"
	Operation   = "op"
	Plan        = "pln"
	Approval    = "apv"
	Delegation  = "dlg"
	Service     = "svc"
	Event       = "evt"
	Request     = "req"
	Secret      = "sec"
	Install     = "ins"
	SetupToken  = "stk"
	Idempotency = "idk"
	// Generation 标识宿主私有的固定停止目标；不授予任何调用权限。
	Generation = "gen"
)

const (
	suffixLen = 26
	maxPrefix = 63
	alphabet  = "0123456789abcdefghjkmnpqrstvwxyz"
)

// Generator produces monotonic UUIDv7-based IDs. The zero value is not usable;
// use New.
type Generator struct {
	mu     sync.Mutex
	now    func() time.Time
	lastMS uint64
	seq    uint16 // the 12-bit rand_a field, used as a counter within one millisecond
}

// New returns a generator that reads time from now (time.Now when nil).
func New(now func() time.Time) *Generator {
	if now == nil {
		now = time.Now
	}
	return &Generator{now: now}
}

// New returns a new ID with the given prefix. It panics if the prefix is
// invalid, because prefixes are compile-time constants.
func (g *Generator) New(prefix string) string {
	if err := checkPrefix(prefix); err != nil {
		panic(err)
	}
	u := g.uuid()
	return prefix + "_" + encode(u)
}

// uuid returns a UUIDv7 (RFC 9562 §5.7). Within one millisecond rand_a is a
// counter, so IDs from one generator are strictly increasing; on counter
// overflow the timestamp is advanced by one millisecond (§6.2, method 1).
func (g *Generator) uuid() [16]byte {
	var u [16]byte
	if _, err := rand.Read(u[8:]); err != nil {
		panic(fmt.Errorf("ids: crypto/rand: %w", err))
	}

	g.mu.Lock()
	ms := uint64(g.now().UnixMilli())
	if ms > g.lastMS {
		var r [2]byte
		if _, err := rand.Read(r[:]); err != nil {
			g.mu.Unlock()
			panic(fmt.Errorf("ids: crypto/rand: %w", err))
		}
		// Start below the midpoint so that many IDs fit in one millisecond.
		g.lastMS, g.seq = ms, binary.BigEndian.Uint16(r[:])&0x07ff
	} else {
		g.seq++
		if g.seq > 0x0fff {
			g.lastMS++
			g.seq = 0
		}
	}
	ms, seq := g.lastMS, g.seq
	g.mu.Unlock()

	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	u[6] = 0x70 | byte(seq>>8) // version 7
	u[7] = byte(seq)
	u[8] = 0x80 | u[8]&0x3f // variant 10
	return u
}

// encode writes the 128-bit value as 26 base32 digits, most significant first;
// the first digit holds only 3 bits.
func encode(u [16]byte) string {
	hi := binary.BigEndian.Uint64(u[:8])
	lo := binary.BigEndian.Uint64(u[8:])
	var b [suffixLen]byte
	for i := range b {
		shift := uint(125 - 5*i)
		var v uint64
		switch {
		case shift >= 64:
			v = hi >> (shift - 64)
		case shift > 59:
			v = hi<<(64-shift) | lo>>shift
		default:
			v = lo >> shift
		}
		b[i] = alphabet[v&31]
	}
	return string(b[:])
}

// Valid reports whether id has the given prefix and a well-formed suffix.
func Valid(id, prefix string) bool {
	return Check(id, prefix) == nil
}

// Check returns an error describing why id is not a valid ID with the given
// prefix. Messages never echo the input.
func Check(id, prefix string) error {
	if len(id) != len(prefix)+1+suffixLen || id[:len(prefix)] != prefix || id[len(prefix)] != '_' {
		return errors.New("id: wrong prefix or length")
	}
	s := id[len(prefix)+1:]
	if s[0] > '7' {
		return errors.New("id: suffix overflows 128 bits")
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return errors.New("id: invalid character in suffix")
		}
	}
	return nil
}

func isDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z' && c != 'i' && c != 'l' && c != 'o' && c != 'u')
}

func checkPrefix(p string) error {
	if p == "" || len(p) > maxPrefix {
		return fmt.Errorf("ids: invalid prefix %q", p)
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 'a' || p[i] > 'z' {
			return fmt.Errorf("ids: invalid prefix %q", p)
		}
	}
	return nil
}

// TraceID returns a random W3C Trace Context trace-id: 32 lower-case hex
// characters, not all zero.
func TraceID() string {
	var b [16]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(fmt.Errorf("ids: crypto/rand: %w", err))
		}
		if b != [16]byte{} {
			return hex.EncodeToString(b[:])
		}
	}
}

// ValidTraceID reports whether s is a W3C trace-id.
func ValidTraceID(s string) bool {
	if len(s) != 32 || s == "00000000000000000000000000000000" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
