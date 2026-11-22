// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"fmt"
	"math"
	"os"
	"strconv"
)

// EnvMemoryLimit is the environment variable the Go runtime and the SDK read.
// The systemd unit sets it to about 0.85 x resources.memory_max_mb (ARCH §6.3).
const EnvMemoryLimit = "GOMEMLIMIT"

// MemoryLimit is the process memory limit from GOMEMLIMIT.
//
// The Go runtime reads GOMEMLIMIT itself at startup; the SDK only validates the
// value (so a typo in a unit fails the plugin at startup instead of a runtime
// warning) and exposes it in CheckHealth details.
type MemoryLimit struct {
	// Bytes is the parsed limit; meaningful only when Set is true.
	Bytes int64
	// Set is false when GOMEMLIMIT is unset or "off".
	Set bool
	// Raw is the unmodified environment value.
	Raw string
}

// MemoryLimitFromEnv reads GOMEMLIMIT from the process environment.
func MemoryLimitFromEnv() (MemoryLimit, error) {
	return ReadMemoryLimit(os.Getenv)
}

// ReadMemoryLimit parses GOMEMLIMIT using the same grammar as the Go runtime
// (runtime.parseByteCount): an optional "off", or an unsigned integer byte
// count with an optional B, KiB, MiB, GiB or TiB suffix. Decimal units such as
// "MB" and fractional values are rejected because the runtime rejects them too
// (the runtime terminates the process on a malformed value).
func ReadMemoryLimit(getenv func(string) string) (MemoryLimit, error) {
	raw := getenv(EnvMemoryLimit)
	if raw == "" || raw == "off" {
		return MemoryLimit{Raw: raw}, nil
	}
	n, ok := parseByteCount(raw)
	if !ok {
		return MemoryLimit{Raw: raw}, fmt.Errorf("%s=%q is not a byte count with an optional B, KiB, MiB, GiB or TiB suffix", EnvMemoryLimit, raw)
	}
	return MemoryLimit{Bytes: n, Set: true, Raw: raw}, nil
}

// parseByteCount is the runtime's grammar: ^[0-9]+(([KMGT]i)?B)?$.
func parseByteCount(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	last := s[len(s)-1]
	if last >= '0' && last <= '9' {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	}
	if last != 'B' || len(s) < 2 {
		return 0, false
	}
	if c := s[len(s)-2]; c >= '0' && c <= '9' {
		n, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	} else if c != 'i' {
		return 0, false
	}
	if len(s) < 4 {
		return 0, false
	}
	var power int
	switch s[len(s)-3] {
	case 'K':
		power = 1
	case 'M':
		power = 2
	case 'G':
		power = 3
	case 'T':
		power = 4
	default:
		return 0, false
	}
	m := uint64(1)
	for i := 0; i < power; i++ {
		m *= 1024
	}
	n, err := strconv.ParseInt(s[:len(s)-3], 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	un := uint64(n)
	if un > math.MaxUint64/m {
		return 0, false
	}
	un *= m
	if un > uint64(math.MaxInt64) {
		return 0, false
	}
	return int64(un), true
}
