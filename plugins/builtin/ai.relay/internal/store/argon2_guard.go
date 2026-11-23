// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// Tuned for plugin cgroup MemoryMax bounds (OWASP baseline: 16 MiB, t=2, p=1).
	safeArgonTime       uint32 = 2
	safeArgonMemoryKiB  uint32 = 16 * 1024
	safeArgonThreads    uint8  = 1
	safeArgonKeyLen     uint32 = 32
	maxAcceptedMemKiB   uint32 = 32 * 1024
	maxAcceptedIter     uint32 = 6
	maxAcceptedThreads  uint8  = 4
	argonAcquireTimeout        = 2 * time.Second
)

// portalArgonSem serializes Argon2id allocations to a single concurrent slot so
// concurrent logins cannot spike heap memory past the plugin cgroup limit.
var portalArgonSem = make(chan struct{}, 1)

func acquireArgonSlot(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(argonAcquireTimeout)
	defer timer.Stop()
	select {
	case portalArgonSem <- struct{}{}:
		return nil
	case <-timer.C:
		return errors.New("RATE_LIMITED: 登录认证繁忙，请稍后重试")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseArgonSlot() {
	<-portalArgonSem
}

// HashPasswordBounded hashes a password with bounded 16 MiB Argon2id behind the
// global single-slot semaphore.
func HashPasswordBounded(ctx context.Context, password string) (string, error) {
	if len(password) < 8 || len(password) > 128 {
		return "", errors.New("VALIDATION_FAILED: 密码长度需在 8..128 字符之间")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if err := acquireArgonSlot(ctx); err != nil {
		return "", err
	}
	defer releaseArgonSlot()

	hash := argon2.IDKey([]byte(password), salt, safeArgonTime, safeArgonMemoryKiB, safeArgonThreads, safeArgonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, safeArgonMemoryKiB, safeArgonTime, safeArgonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPasswordBounded verifies an Argon2id PHC hash in constant time while
// capping memory/iteration/thread parameters and serializing through the semaphore.
func VerifyPasswordBounded(ctx context.Context, password, encoded string) (bool, error) {
	if len(password) > 128 {
		return false, nil
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, nil
	}
	var mem, iter uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &par); err != nil {
		return false, nil
	}
	if mem < 4096 || mem > maxAcceptedMemKiB || iter < 1 || iter > maxAcceptedIter || par < 1 || par > maxAcceptedThreads {
		return false, errors.New("STATE_INVALID: argon2 parameters exceed sandbox safety bounds")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false, nil
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return false, nil
	}

	if err := acquireArgonSlot(ctx); err != nil {
		return false, err
	}
	defer releaseArgonSlot()

	actual := argon2.IDKey([]byte(password), salt, iter, mem, par, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

// ApplyAtomicBalanceDelta atomically adjusts an in-memory balance by deltaMicros
// using CAS, clamping at zero so concurrent in-flight reservations are never clobbered.
func ApplyAtomicBalanceDelta(balanceMicros *atomic.Int64, deltaMicros int64) int64 {
	for {
		cur := balanceMicros.Load()
		next := cur + deltaMicros
		if next < 0 {
			next = 0
		}
		if balanceMicros.CompareAndSwap(cur, next) {
			return next
		}
	}
}
