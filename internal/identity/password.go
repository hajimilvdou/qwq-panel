// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/platform/problem"

	"golang.org/x/crypto/argon2"
)

// Params are the argon2id cost parameters of a password hash. They are embedded
// in the stored PHC string, so raising them never invalidates existing
// passwords: the next successful login re-hashes with the current parameters.
type Params struct {
	// Memory is m, in KiB.
	Memory uint32
	// Iterations is t.
	Iterations uint32
	// Parallelism is p.
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams 返回新密码使用的 argon2id 成本，不随 CPU 预算降低强度。
// 19 MiB / t=2 / p=1 对齐内存受限场景的既定安全参数；单 CPU 默认一个槽，
// 多 CPU 至多两个槽，工作区峰值分别约为 19 MiB / 38 MiB。
// 单次哈希在一 vCPU 上约 40-60ms；p=1 避免最低配置机器的无益调度。
func DefaultParams() Params {
	return Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

// minParams/maxParams bound what parsePHC accepts, so a corrupted or hostile
// database row cannot make the host allocate an unbounded amount of memory.
var (
	minMemory = uint32(8 * 1024)
	maxMemory = uint32(1024 * 1024)
)

func (p Params) valid() error {
	switch {
	case p.Memory < minMemory || p.Memory > maxMemory:
		return fmt.Errorf("identity: argon2 memory %d KiB out of range", p.Memory)
	case p.Iterations < 1 || p.Iterations > 10:
		return fmt.Errorf("identity: argon2 iterations %d out of range", p.Iterations)
	case p.Parallelism < 1 || p.Parallelism > 16:
		return fmt.Errorf("identity: argon2 parallelism %d out of range", p.Parallelism)
	case p.SaltLength < 8 || p.SaltLength > 64:
		return fmt.Errorf("identity: argon2 salt length %d out of range", p.SaltLength)
	case p.KeyLength < 16 || p.KeyLength > 64:
		return fmt.Errorf("identity: argon2 key length %d out of range", p.KeyLength)
	}
	return nil
}

// String renders the PHC parameter section (m=…,t=…,p=…).
func (p Params) String() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory, p.Iterations, p.Parallelism)
}

// DefaultHashConcurrency 是自动哈希预算的上限，保留显式配置的原调用契约。
// 单 CPU 默认只分配一个槽，多 CPU 至多两个；各槽共用原 argon2 参数。
const DefaultHashConcurrency = 2

// hashQueueWait bounds how long a request waits for a hashing slot. Under a
// flood of logins the excess fails fast with a retryable UNAVAILABLE instead of
// queueing a real administrator behind thousands of hashes; the gateway's
// pre-authentication limits keep such floods rare in the first place.
const hashQueueWait = 2 * time.Second

// Hasher computes and verifies argon2id password hashes. A single Hasher is
// shared by the whole process; its semaphore limits how many hashes run at once
// so that a burst of logins cannot exhaust the memory of a small host.
type Hasher struct {
	params Params
	sem    chan struct{}
	// dummyHash is a PHC string of params that DummyVerify checks against. It
	// is fixed at construction: nothing can fail, nothing is cached later.
	dummyHash string
}

// NewHasher 创建共享哈希器；concurrency <= 0 时按当前 CPU 预算选择默认槽数。
// 显式正数不改写，槽数在创建时固定；非法编译期参数仍按原契约 panic。
func NewHasher(p Params, concurrency int) *Hasher {
	if err := p.valid(); err != nil {
		panic(err)
	}
	if concurrency <= 0 {
		concurrency = min(DefaultHashConcurrency, runtime.GOMAXPROCS(0))
	}
	return &Hasher{params: p, sem: make(chan struct{}, concurrency), dummyHash: dummyPHC(p)}
}

// dummyPHC encodes an all-zero salt and key with the cost parameters p. Argon2
// costs the same whatever the salt, and no password derives an all-zero key, so
// checking against it is a full-price hash that never matches.
func dummyPHC(p Params) string {
	return encodePHC(p, make([]byte, p.SaltLength), make([]byte, p.KeyLength))
}

// encodePHC formats an argon2id salt and key as a PHC string (the inverse of
// parsePHC).
func encodePHC(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// Params returns the cost parameters used for new hashes.
func (h *Hasher) Params() Params { return h.params }

// Hash returns the PHC string of password with a fresh random salt.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("identity: read salt: %w", err)
	}
	return h.hashWith(ctx, h.params, password, salt)
}

func (h *Hasher) hashWith(ctx context.Context, p Params, password string, salt []byte) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return encodePHC(p, salt, key), nil
}

// VerifyResult reports the outcome of a password check.
type VerifyResult struct {
	OK bool
	// NeedsRehash is true when the hash was produced with older parameters and
	// should be replaced after this successful verification.
	NeedsRehash bool
}

// Verify checks password against a PHC string in constant time with respect to
// the hash contents. A malformed hash is an error, never a successful match.
func (h *Hasher) Verify(ctx context.Context, encoded, password string) (VerifyResult, error) {
	p, salt, want, err := parsePHC(encoded)
	if err != nil {
		return VerifyResult{}, err
	}
	key, err := h.derive(ctx, p, password, salt)
	if err != nil {
		return VerifyResult{}, err
	}
	ok := subtle.ConstantTimeCompare(key, want) == 1
	return VerifyResult{OK: ok, NeedsRehash: ok && p != h.params}, nil
}

func (h *Hasher) derive(ctx context.Context, p Params, password string, salt []byte) ([]byte, error) {
	if err := h.acquire(ctx); err != nil {
		return nil, err
	}
	defer h.release()
	return argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength), nil
}

// DummyVerify burns one hash of the configured cost. Login calls it when the
// account does not exist so that the response time does not reveal whether a
// username is registered. Every call runs a real Verify through the same
// semaphore as a known user, so a saturated hasher fails both alike, and a
// failure is never remembered past the call that hit it.
func (h *Hasher) DummyVerify(ctx context.Context) error {
	_, err := h.Verify(ctx, h.dummyHash, "qwq-password-timing-equaliser")
	return err
}

// acquire takes a hashing slot. It gives up when ctx ends or, at the latest,
// after hashQueueWait, so no request waits behind an unbounded queue.
func (h *Hasher) acquire(ctx context.Context) error {
	t := time.NewTimer(hashQueueWait)
	defer t.Stop()
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-t.C:
		return problem.New(problem.Unavailable, "The server is busy verifying passwords; retry shortly.")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

func parsePHC(encoded string) (Params, []byte, []byte, error) {
	var p Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, errors.New("identity: not an argon2id PHC string")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, errors.New("identity: unsupported argon2 version")
	}
	mem, iter, par, err := parseParams(parts[3])
	if err != nil {
		return p, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, fmt.Errorf("identity: decode salt: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, fmt.Errorf("identity: decode key: %w", err)
	}
	p = Params{Memory: mem, Iterations: iter, Parallelism: par,
		SaltLength: uint32(len(salt)), KeyLength: uint32(len(key))}
	if err := p.valid(); err != nil {
		return p, nil, nil, err
	}
	return p, salt, key, nil
}

// parseParams reads the "m=...,t=...,p=..." PHC section. The order is fixed by
// RFC 9106 / the reference implementation.
func parseParams(s string) (memory, iterations uint32, parallelism uint8, err error) {
	var m, t, p uint64
	if _, err = fmt.Sscanf(s, "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return 0, 0, 0, fmt.Errorf("identity: parse argon2 params: %w", err)
	}
	if m > 1<<32-1 || t > 1<<32-1 || p > 255 {
		return 0, 0, 0, errors.New("identity: argon2 params out of range")
	}
	return uint32(m), uint32(t), uint8(p), nil
}

// PasswordPolicy is the password strength rule for new passwords. The public
// API schema requires 12 to 256 characters (Password in openapi.yaml).
type PasswordPolicy struct {
	MinLength int
	MaxLength int
	// PassphraseLength waives the character-class rule: a long passphrase is
	// stronger than a short string that satisfies a class counter.
	PassphraseLength int
	// MaxUsernameOverlap rejects passwords that contain the login name.
	MaxUsernameOverlap bool
}

// DefaultPasswordPolicy returns the policy used by the host.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{MinLength: 12, MaxLength: 256, PassphraseLength: 20, MaxUsernameOverlap: true}
}

// commonPasswords is a short denylist of passwords that pass the length rule
// but are the first guesses of any attacker. It is not a substitute for a full
// leaked-password corpus (P3 work); it catches the obvious choices.
var commonPasswords = map[string]struct{}{
	"password1234":     {},
	"passwordpassword": {},
	"123456789012":     {},
	"1234567890123":    {},
	"qwertyuiop12":     {},
	"qwertyuiop123":    {},
	"administrator1":   {},
	"changeme1234":     {},
	"letmein12345":     {},
	"iloveyou1234":     {},
	"welcome12345":     {},
	"qwqpanel1234":     {},
}

// Validate returns the field violations of a candidate password. An empty slice
// means the password is acceptable.
func (p PasswordPolicy) Validate(username, password string) []problem.Violation {
	var vs []problem.Violation
	add := func(code, msg string) {
		vs = append(vs, problem.Violation{Pointer: "/password", Code: code, Message: msg})
	}
	n := utf8.RuneCountInString(password)
	if n < p.MinLength {
		add("too_short", fmt.Sprintf("The password must be at least %d characters.", p.MinLength))
	}
	if n > p.MaxLength {
		add("too_long", fmt.Sprintf("The password must be at most %d characters.", p.MaxLength))
	}
	if strings.TrimSpace(password) == "" {
		add("empty", "The password must not be empty or whitespace.")
		return vs
	}
	if n < p.PassphraseLength && charClasses(password) < 3 {
		add("too_weak", "Use at least three of: lower case, upper case, digits, symbols, or a passphrase of 20+ characters.")
	}
	if _, ok := commonPasswords[strings.ToLower(password)]; ok {
		add("common", "This password is one of the most common choices.")
	}
	if p.MaxUsernameOverlap && len(username) >= 3 &&
		strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		add("contains_username", "The password must not contain the user name.")
	}
	if allSameRune(password) {
		add("repeated", "The password must not repeat one character.")
	}
	return vs
}

func charClasses(s string) int {
	var lower, upper, digit, other bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

func allSameRune(s string) bool {
	var first rune
	for i, r := range s {
		if i == 0 {
			first = r
			continue
		}
		if r != first {
			return false
		}
	}
	return true
}

// preparePassword validates and hashes a password outside any write
// transaction, so that a 40-60 ms argon2 hash never extends a write lock.
func (s *Service) preparePassword(ctx context.Context, username, password string) (string, error) {
	if vs := s.passwordPolicy.Validate(username, password); len(vs) > 0 {
		return "", problem.Validation(vs...)
	}
	return s.hasher.Hash(ctx, password)
}

// PreparePassword validates a password against the policy and returns its
// argon2id PHC string. Callers that hold a *storage.Tx must hash before opening
// it and pass the result to the write functions (CreateUser, ResetPassword).
func (s *Service) PreparePassword(ctx context.Context, username, password string) (string, error) {
	return s.preparePassword(ctx, username, password)
}
