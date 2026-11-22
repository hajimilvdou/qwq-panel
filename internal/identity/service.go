// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Defaults of the identity configuration. They are tuned for a small VPS
// (1 vCPU / 1 GiB) and for a browser panel with a second factor; see REPORT.md
// for the reasoning behind each value.
const (
	// DefaultIdleTimeout ends an inactive session. The Shell touches the
	// session with every request, so 30 minutes is a real inactivity window.
	DefaultIdleTimeout = 30 * time.Minute
	// DefaultAbsoluteTimeout caps a session's total life regardless of activity;
	// the session ID is rotated on login and on privilege change, and the new
	// session inherits this deadline.
	DefaultAbsoluteTimeout = 12 * time.Hour
	// DefaultTouchInterval throttles the last_seen_at write: at most one write
	// per session per minute keeps the single write connection free on a busy UI.
	DefaultTouchInterval = time.Minute
	// DefaultSetupTokenTTL bounds the one-time installation token.
	DefaultSetupTokenTTL = 24 * time.Hour
	// DefaultEnrollmentTokenTTL bounds the link an administrator hands to a new
	// user so the user can choose their own password.
	DefaultEnrollmentTokenTTL = 24 * time.Hour
	// DefaultMFAChallengeTTL bounds the half-authenticated login challenge.
	DefaultMFAChallengeTTL = 5 * time.Minute
	// DefaultTOTPEnrollmentTTL bounds how long an unconfirmed TOTP secret lives.
	DefaultTOTPEnrollmentTTL = 15 * time.Minute
	// DefaultMFAFreshness is how long a second factor is considered recent
	// enough for destructive approvals (ADR-0004 D6).
	DefaultMFAFreshness = 15 * time.Minute
	// DefaultMaxMFAChallengeAttempts invalidates a challenge after this many
	// wrong codes; the next login starts a new challenge.
	DefaultMaxMFAChallengeAttempts = 5
	// DefaultSessionRetention is how long a session row is kept after it expired
	// or was revoked (OPS-05). It is evidence for "who was signed in", not a
	// usable credential: the token hash is gone from the client long before.
	DefaultSessionRetention = 30 * 24 * time.Hour
)

// Options configure a Service.
type Options struct {
	// DB is the host database. Required.
	DB *storage.DB
	// Clock supplies the current time; it must match the clock used by DB so
	// that tx.Now() and service timestamps agree.
	Clock clock.Clock
	// IDs generates resource IDs. Defaults to a generator over Clock.
	IDs *ids.Generator
	// Logger receives operational warnings. Optional.
	Logger *slog.Logger
	// Sealer seals TOTP secrets. Required for MFA; without it TOTP enrolment
	// and verification return UNAVAILABLE and password-only login works.
	Sealer SecretSealer
	// Auditor receives audit records. Optional (tests use a fake; the host wires
	// the operations package implementation).
	Auditor Auditor
	// Hasher 使用共享 argon2id 哈希器；默认参数不变，槽数按当前 CPU 预算选择。
	Hasher *Hasher
	// Throttle implements progressive login backoff. Defaults to DefaultThrottle.
	Throttle *LoginThrottle
	// PasswordPolicy overrides the default strength rule.
	PasswordPolicy *PasswordPolicy

	IdleTimeout        time.Duration
	AbsoluteTimeout    time.Duration
	TouchInterval      time.Duration
	SetupTokenTTL      time.Duration
	EnrollmentTokenTTL time.Duration
	MFAChallengeTTL    time.Duration
	TOTPEnrollmentTTL  time.Duration
	MFAFreshness       time.Duration
	// SessionRetention is how long an expired or revoked session row is kept
	// (OPS-05). Prune uses it; the operations sweeper calls Prune.
	SessionRetention time.Duration

	MaxMFAChallengeAttempts int
}

// Service is the identity domain service. It is safe for concurrent use; all
// mutable state lives in the database or in the bounded login throttle.
type Service struct {
	db     *storage.DB
	clock  clock.Clock
	ids    *ids.Generator
	log    *slog.Logger
	sealer SecretSealer
	audit  Auditor
	hasher *Hasher
	thr    *LoginThrottle

	idleTimeout        time.Duration
	absoluteTimeout    time.Duration
	touchInterval      time.Duration
	setupTokenTTL      time.Duration
	enrollmentTokenTTL time.Duration
	mfaChallengeTTL    time.Duration
	totpEnrollTTL      time.Duration
	mfaFreshness       time.Duration
	sessionRetention   time.Duration
	maxMFAAttempts     int
	passwordPolicy     PasswordPolicy
}

// New validates opts and returns a Service.
func New(opts Options) (*Service, error) {
	if opts.DB == nil {
		return nil, errors.New("identity: Options.DB is required")
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.IDs == nil {
		opts.IDs = ids.New(opts.Clock.Now)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Hasher == nil {
		opts.Hasher = NewHasher(DefaultParams(), 0)
	}
	if opts.Throttle == nil {
		opts.Throttle = NewLoginThrottle(opts.Clock.Now, DefaultThrottleOptions())
	}
	if opts.PasswordPolicy == nil {
		p := DefaultPasswordPolicy()
		opts.PasswordPolicy = &p
	}
	s := &Service{
		db:                 opts.DB,
		clock:              opts.Clock,
		ids:                opts.IDs,
		log:                opts.Logger,
		sealer:             opts.Sealer,
		audit:              opts.Auditor,
		hasher:             opts.Hasher,
		thr:                opts.Throttle,
		idleTimeout:        orDefault(opts.IdleTimeout, DefaultIdleTimeout),
		absoluteTimeout:    orDefault(opts.AbsoluteTimeout, DefaultAbsoluteTimeout),
		touchInterval:      orDefault(opts.TouchInterval, DefaultTouchInterval),
		setupTokenTTL:      orDefault(opts.SetupTokenTTL, DefaultSetupTokenTTL),
		enrollmentTokenTTL: orDefault(opts.EnrollmentTokenTTL, DefaultEnrollmentTokenTTL),
		mfaChallengeTTL:    orDefault(opts.MFAChallengeTTL, DefaultMFAChallengeTTL),
		totpEnrollTTL:      orDefault(opts.TOTPEnrollmentTTL, DefaultTOTPEnrollmentTTL),
		mfaFreshness:       orDefault(opts.MFAFreshness, DefaultMFAFreshness),
		sessionRetention:   orDefault(opts.SessionRetention, DefaultSessionRetention),
		maxMFAAttempts:     opts.MaxMFAChallengeAttempts,
		passwordPolicy:     *opts.PasswordPolicy,
	}
	if s.maxMFAAttempts <= 0 {
		s.maxMFAAttempts = DefaultMaxMFAChallengeAttempts
	}
	return s, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// Clock returns the clock the service uses (tests and the gateway share it).
func (s *Service) Clock() clock.Clock { return s.clock }

func (s *Service) now() time.Time { return s.clock.Now().UTC() }

// update runs fn in one write transaction. Authentication flows use it; the
// resource write functions receive the caller's transaction instead.
func (s *Service) update(ctx context.Context, fn func(*storage.Tx) error) error {
	return s.db.Update(ctx, fn)
}

// newSecret returns a 32-byte random token in unpadded base64url and the
// SHA-256 digest of the token *string*, which is the form stored in the
// database and the form hashToken produces for lookups.
func newSecret() (string, []byte, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, fmt.Errorf("identity: crypto/rand: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	return token, hashToken(token), nil
}

// hashToken hashes a token string as newSecret does.
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// unauthenticated is the single response for every failed credential check: it
// must not say which part was wrong (OpenAPI /sessions description).
func unauthenticated() error {
	return problem.New(problem.Unauthenticated, "Authentication required.")
}

// rateLimited renders a throttled attempt with the retry delay.
func rateLimited(wait time.Duration) error {
	sec := int((wait + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	return &problem.Error{
		Code:          problem.RateLimited,
		Detail:        "Too many attempts. Wait before trying again.",
		RetryAfterSec: sec,
	}
}

// auditRecord writes one audit record in its own transaction. Failures are
// logged, never returned: an audit store outage must not turn a login into a
// 500 response.
func (s *Service) auditRecord(ctx context.Context, rec AuditRecord) {
	if s.audit == nil {
		return
	}
	if rec.At.IsZero() {
		rec.At = s.now()
	}
	err := s.update(ctx, func(tx *storage.Tx) error {
		return s.audit.Audit(ctx, tx, rec)
	})
	if err != nil {
		s.log.WarnContext(ctx, "audit write failed", "action", rec.Action, "error", err)
	}
}

// errNotFound reports a missing row as NOT_FOUND without echoing the ID.
func errNotFound(what string) error {
	return problem.New(problem.NotFound, "The %s does not exist.", what)
}

// isNoRows reports whether err is sql.ErrNoRows.
func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// auditActor prefers the transaction origin (set by operations.Run) and falls
// back to the actor passed by the caller.
func auditActor(tx *storage.Tx, fallback actor.Actor) actor.Actor {
	if o := tx.Origin().Actor; o.Kind != "" {
		return o
	}
	if fallback.Kind != "" && fallback.ID != "" {
		return fallback
	}
	return actor.SystemActor("identity")
}

// formatTime stores t with the storage layout; the zero time becomes ”.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return storage.FormatTime(t)
}

// parseTime is the inverse of formatTime.
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return storage.ParseTime(s)
}
