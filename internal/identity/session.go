// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// SessionCookieName is the cookie the gateway sets; identity only issues the
// token and its expiry. The __Secure- prefix and Path=/api/ are part of the
// public contract (ARCH §4.1.1, openapi.yaml securitySchemes).
const SessionCookieName = "__Secure-qwq_session"

// Session is a signed-in browser session. The token itself exists only in the
// cookie: the database stores its SHA-256.
type Session struct {
	ID   string
	User User
	// CSRF is the synchroniser token returned in Session.csrf_token.
	CSRF string
	// MFAVerifiedAt is zero when the session never passed a second factor.
	MFAVerifiedAt time.Time
	CreatedAt     time.Time
	LastSeenAt    time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
	ClientIP      string
	UserAgent     string
}

// Expired reports whether the session is past its idle or absolute deadline.
func (sess Session) Expired(now time.Time) bool {
	return !now.Before(sess.IdleExpiresAt) || !now.Before(sess.ExpiresAt)
}

// MFAFresh reports whether the second factor is recent enough for destructive
// approvals (ADR-0004 D6).
func (sess Session) MFAFresh(now time.Time, window time.Duration) bool {
	return !sess.MFAVerifiedAt.IsZero() && !sess.MFAVerifiedAt.After(now) && now.Sub(sess.MFAVerifiedAt) < window
}

// sessionSpec are the varying parts of a new session row.
type sessionSpec struct {
	Created       time.Time
	Expires       time.Time
	MFAVerifiedAt time.Time
	ClientIP      string
	UserAgent     string
	// MFAFreshness is copied from the service; it is not stored.
}

// sessionColumns selects a session joined with its user, so one query
// authenticates a request.
const sessionColumns = `s.session_id, s.csrf_token, s.mfa_verified_at, s.created_at, s.last_seen_at,
	s.idle_expires_at, s.expires_at, s.revoked_at, s.client_ip, s.user_agent, ` + userColumns

func scanSession(row scanner) (Session, error) {
	var sess Session
	var mfaAt, created, lastSeen, idle, expires, revoked, ip, ua string
	var role string
	var disabled, mfa int
	var uCreated, uUpdated string
	if err := row.Scan(&sess.ID, &sess.CSRF, &mfaAt, &created, &lastSeen, &idle, &expires, &revoked,
		&ip, &ua, &sess.User.ID, &sess.User.Username, &sess.User.DisplayName, &role,
		&disabled, &mfa, &uCreated, &uUpdated, &sess.User.Revision); err != nil {
		return Session{}, err
	}
	sess.User.Role = Role(role)
	sess.User.Disabled = disabled != 0
	sess.User.MFAEnabled = mfa != 0
	var err error
	for _, f := range []struct {
		dst *time.Time
		src string
	}{
		{&sess.MFAVerifiedAt, mfaAt},
		{&sess.CreatedAt, created},
		{&sess.LastSeenAt, lastSeen},
		{&sess.IdleExpiresAt, idle},
		{&sess.ExpiresAt, expires},
		{&sess.User.CreatedAt, uCreated},
		{&sess.User.UpdatedAt, uUpdated},
	} {
		if *f.dst, err = parseTime(f.src); err != nil {
			return Session{}, fmt.Errorf("identity: session timestamp: %w", err)
		}
	}
	if revoked != "" {
		// A revoked session is reported as absent; callers map it to
		// UNAUTHENTICATED and the timestamps are irrelevant.
		return Session{}, problem.New(problem.Unauthenticated, "Authentication required.")
	}
	sess.ClientIP, sess.UserAgent = ip, ua
	return sess, nil
}

// insertSessionTx writes a session row and returns it with the raw token that
// belongs in the cookie.
func (s *Service) insertSessionTx(ctx context.Context, tx *storage.Tx, u User, spec sessionSpec) (Session, string, error) {
	token, tokenHash, err := newSecret()
	if err != nil {
		return Session{}, "", err
	}
	csrf, _, err := newSecret()
	if err != nil {
		return Session{}, "", err
	}
	if spec.Created.IsZero() {
		spec.Created = tx.Now()
	}
	if spec.Expires.IsZero() {
		spec.Expires = spec.Created.Add(s.absoluteTimeout)
	}
	idle := spec.Created.Add(s.idleTimeout)
	if idle.After(spec.Expires) {
		idle = spec.Expires
	}
	id := tx.NewID(ids.Session)
	now := tx.Now()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sessions (session_id, user_id, token_hash, csrf_token, mfa_verified_at,
			created_at, last_seen_at, idle_expires_at, expires_at, revoked_at, client_ip, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)`,
		id, u.ID, tokenHash, csrf, formatTime(spec.MFAVerifiedAt), formatTime(spec.Created),
		formatTime(now), formatTime(idle), formatTime(spec.Expires), spec.ClientIP, spec.UserAgent); err != nil {
		return Session{}, "", fmt.Errorf("identity: insert session: %w", err)
	}
	return Session{
		ID: id, User: u, CSRF: csrf, MFAVerifiedAt: spec.MFAVerifiedAt,
		CreatedAt: spec.Created, LastSeenAt: now, IdleExpiresAt: idle, ExpiresAt: spec.Expires,
		ClientIP: spec.ClientIP, UserAgent: spec.UserAgent,
	}, token, nil
}

// sessionByToken loads a live or revoked session by its raw token.
func (s *Service) sessionByToken(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, unauthenticated()
	}
	sess, err := scanSession(s.db.Reader().QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions s JOIN users u ON u.user_id = s.user_id
		 WHERE s.token_hash = ?`, hashToken(token)))
	if isNoRows(err) {
		return Session{}, unauthenticated()
	}
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}

// AuthenticateSession resolves the cookie token to an actor and its session. A
// missing, revoked, idle-expired or absolute-expired session is
// UNAUTHENTICATED. The last-seen write is throttled to one per TouchInterval.
func (s *Service) AuthenticateSession(ctx context.Context, token string) (actor.Actor, Session, error) {
	sess, err := s.sessionByToken(ctx, token)
	if err != nil {
		return actor.Actor{}, Session{}, err
	}
	now := s.now()
	a, err := s.humanSessionActor(sess, now)
	if err != nil {
		return actor.Actor{}, Session{}, unauthenticated()
	}
	s.touchSession(ctx, sess, now)
	return a, sess, nil
}

// touchSession moves the idle deadline forward, writing at most once per
// TouchInterval so that a busy UI does not monopolise the write connection.
func (s *Service) touchSession(ctx context.Context, sess Session, now time.Time) {
	if now.Sub(sess.LastSeenAt) < s.touchInterval {
		return
	}
	idle := now.Add(s.idleTimeout)
	if idle.After(sess.ExpiresAt) {
		idle = sess.ExpiresAt
	}
	err := s.update(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE session_id = ? AND revoked_at = ''`,
			formatTime(now), formatTime(idle), sess.ID)
		return err
	})
	if err != nil {
		// A lost touch only shortens the idle window slightly; it must not fail
		// the request.
		s.log.WarnContext(ctx, "session touch failed", "session_id", sess.ID, "error", err)
	}
}

// LoginInput is one password login attempt.
type LoginInput struct {
	Username  string
	Password  string
	ClientIP  string
	UserAgent string
}

// LoginResult is either an authenticated session or a second-factor challenge.
type LoginResult struct {
	Session Session
	// Token is the raw session token for the cookie; empty when MFA is pending.
	Token string
	// MFA is set when the password was correct but a second factor is required.
	MFA *MFAChallenge
}

// Authenticated reports whether the login completed.
func (r LoginResult) Authenticated() bool { return r.Token != "" }

// MFAChallenge is the response to a login that needs a second factor.
type MFAChallenge struct {
	ID        string
	Methods   []string
	ExpiresAt time.Time
}

// Login authenticates a user name and password with progressive backoff. A
// user with TOTP enabled gets a challenge instead of a session (OpenAPI
// POST /api/v1/sessions, 200 vs 201). The attempt is charged before the
// password is checked and only a complete authentication refunds it, so a
// pending second factor keeps its charge until VerifyMFA succeeds.
func (s *Service) Login(ctx context.Context, in LoginInput) (LoginResult, error) {
	rawName := strings.ToLower(strings.TrimSpace(in.Username))
	username, nameErr := NormalizeUsername(in.Username)
	key := username
	if nameErr != nil {
		// A label no valid username or other throttle label can produce, so an
		// invalid name cannot spend someone else's budget.
		key = invalidNameThrottlePrefix + clipName(rawName)
	}
	if wait, ok := s.thr.Attempt(key, in.ClientIP); !ok {
		return LoginResult{}, rateLimited(wait)
	}
	if nameErr != nil {
		// A malformed name is still a failed login; never reveal which rule was
		// broken through a different status code.
		s.recordLoginFailure(ctx, User{}, key, in, "invalid_username")
		return LoginResult{}, unauthenticated()
	}
	u, err := s.UserByUsername(ctx, username)
	if err != nil {
		if problem.HasCode(err, problem.NotFound) {
			if herr := s.hasher.DummyVerify(ctx); herr != nil {
				return LoginResult{}, herr
			}
			s.recordLoginFailure(ctx, User{}, username, in, "unknown_user")
			return LoginResult{}, unauthenticated()
		}
		return LoginResult{}, err
	}
	encoded, err := s.passwordHash(ctx, u.ID)
	if err != nil {
		if problem.HasCode(err, problem.NotFound) {
			if herr := s.hasher.DummyVerify(ctx); herr != nil {
				return LoginResult{}, herr
			}
			s.recordLoginFailure(ctx, u, username, in, "no_password")
			return LoginResult{}, unauthenticated()
		}
		return LoginResult{}, err
	}
	verify, err := s.hasher.Verify(ctx, encoded, in.Password)
	if err != nil {
		return LoginResult{}, fmt.Errorf("identity: verify password: %w", err)
	}
	if !verify.OK {
		s.recordLoginFailure(ctx, u, username, in, "bad_password")
		return LoginResult{}, unauthenticated()
	}
	if u.Disabled {
		s.recordLoginFailure(ctx, u, username, in, "disabled")
		return LoginResult{}, unauthenticated()
	}
	var newHash string
	if verify.NeedsRehash {
		if newHash, err = s.hasher.Hash(ctx, in.Password); err != nil {
			return LoginResult{}, err
		}
	}
	if u.MFAEnabled {
		ch, err := s.startMFAChallenge(ctx, u, in, newHash)
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{MFA: &ch}, nil
	}
	sess, token, err := s.completeLogin(ctx, u, in, newHash, time.Time{})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Session: sess, Token: token}, nil
}

// passwordHash returns the stored PHC string, or NOT_FOUND when the user has no
// password yet.
func (s *Service) passwordHash(ctx context.Context, userID string) (string, error) {
	c, err := s.credentialByType(ctx, userID, credPassword)
	if err != nil {
		return "", err
	}
	if c.Secret == "" {
		return "", errNotFound("password")
	}
	return c.Secret, nil
}

// recordLoginFailure writes the audit record of a failed login; Attempt has
// already charged the backoff.
func (s *Service) recordLoginFailure(ctx context.Context, u User, username string, in LoginInput, reason string) {
	rec := AuditRecord{
		Action:    ActionLoginFailed,
		Actor:     actor.SystemActor("identity"),
		Outcome:   OutcomeFailure,
		Reason:    reason,
		ClientIP:  in.ClientIP,
		UserAgent: in.UserAgent,
		Detail:    map[string]string{"username": username},
	}
	if u.ID != "" {
		rec.Subject = u.Subject()
	}
	s.auditRecord(ctx, rec)
}

// clipName bounds a raw login name used as a throttle key or audit detail.
func clipName(s string) string {
	r := []rune(s)
	if len(r) <= MaxUsernameLen {
		return s
	}
	return string(r[:MaxUsernameLen])
}

// startMFAChallenge stores a single-use challenge and returns its token.
func (s *Service) startMFAChallenge(ctx context.Context, u User, in LoginInput, newHash string) (MFAChallenge, error) {
	methods := []string{"totp"}
	if ok, err := s.hasCredential(ctx, u.ID, credRecovery); err != nil {
		return MFAChallenge{}, err
	} else if ok {
		methods = append(methods, "recovery_code")
	}
	raw, digest, err := newSecret()
	if err != nil {
		return MFAChallenge{}, err
	}
	var expires time.Time
	err = s.update(ctx, func(tx *storage.Tx) error {
		now := tx.Now()
		expires = now.Add(s.mfaChallengeTTL)
		if newHash != "" {
			if err := upsertPasswordTx(ctx, tx, u.ID, newHash, now); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM mfa_challenges WHERE user_id = ? AND (expires_at < ? OR used_at <> '')`,
			u.ID, formatTime(now)); err != nil {
			return fmt.Errorf("identity: clear challenges: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO mfa_challenges (id_hash, user_id, created_at, expires_at, used_at, attempts, client_ip)
			 VALUES (?, ?, ?, ?, '', 0, ?)`,
			digest, u.ID, formatTime(now), formatTime(expires), in.ClientIP); err != nil {
			return fmt.Errorf("identity: insert challenge: %w", err)
		}
		return nil
	})
	if err != nil {
		return MFAChallenge{}, err
	}
	return MFAChallenge{ID: raw, Methods: methods, ExpiresAt: expires}, nil
}

// VerifyMFAInput answers an MFAChallenge. SessionToken is optional: when set,
// the answered challenge elevates that session, which is rotated (a new token
// and session ID, same absolute deadline).
type VerifyMFAInput struct {
	ChallengeID  string
	Method       string
	Code         string
	ClientIP     string
	UserAgent    string
	SessionToken string
}

// VerifyMFA completes a login or an elevation with a TOTP or recovery code.
func (s *Service) VerifyMFA(ctx context.Context, in VerifyMFAInput) (LoginResult, error) {
	if in.Method != "totp" && in.Method != "recovery_code" {
		return LoginResult{}, problem.Validation(problem.Violation{
			Pointer: "/method", Code: "invalid", Message: "The method must be totp or recovery_code.",
		})
	}
	ch, err := s.challenge(ctx, in.ChallengeID)
	if err != nil {
		return LoginResult{}, err
	}
	u, err := s.User(ctx, ch.UserID)
	if err != nil {
		return LoginResult{}, err
	}
	if u.Disabled {
		s.recordMFAFailure(ctx, u, in, "disabled")
		return LoginResult{}, unauthenticated()
	}
	if wait, ok := s.thr.Attempt(u.Username, in.ClientIP); !ok {
		return LoginResult{}, rateLimited(wait)
	}
	var elevation *Session
	if in.SessionToken != "" {
		// The challenge already proves the password and the second factor, so
		// an expired, revoked or foreign cookie left in the browser is ignored
		// and a fresh session is issued; only a live session of u is elevated.
		cur, err := s.sessionByToken(ctx, in.SessionToken)
		switch {
		case err == nil && cur.User.ID == u.ID && !cur.Expired(s.now()):
			elevation = &cur
		case err != nil && !problem.HasCode(err, problem.Unauthenticated):
			return LoginResult{}, err
		}
	}
	var (
		result  LoginResult
		failure string
	)
	err = s.update(ctx, func(tx *storage.Tx) error {
		now := tx.Now()
		ch, err := s.challengeTx(ctx, tx, in.ChallengeID)
		if err != nil {
			return err
		}
		if ch.Used || !now.Before(ch.ExpiresAt) || ch.Attempts >= s.maxMFAAttempts {
			failure = "bad_challenge"
			return nil
		}
		fresh, recoverUsed, err := s.verifySecondFactorTx(ctx, tx, u, in.Method, in.Code, now)
		if err != nil {
			return err
		}
		if !fresh {
			failure = "bad_code"
			if _, err := tx.ExecContext(ctx,
				`UPDATE mfa_challenges SET attempts = attempts + 1 WHERE id_hash = ?`, ch.IDHash); err != nil {
				return fmt.Errorf("identity: count challenge attempt: %w", err)
			}
			return nil
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE mfa_challenges SET used_at = ? WHERE id_hash = ?`, formatTime(now), ch.IDHash); err != nil {
			return fmt.Errorf("identity: consume challenge: %w", err)
		}
		spec := sessionSpec{Created: now, Expires: now.Add(s.absoluteTimeout),
			MFAVerifiedAt: now, ClientIP: in.ClientIP, UserAgent: in.UserAgent}
		if elevation != nil {
			// Privilege change: keep the original absolute deadline, end the old
			// session and issue a new token (rotation, ARCH §4.1.1).
			spec.Created, spec.Expires = elevation.CreatedAt, elevation.ExpiresAt
			if _, err := tx.ExecContext(ctx,
				`UPDATE sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at = ''`,
				formatTime(now), elevation.ID); err != nil {
				return fmt.Errorf("identity: rotate session: %w", err)
			}
		}
		var token string
		result.Session, token, err = s.insertSessionTx(ctx, tx, u, spec)
		if err != nil {
			return err
		}
		result.Token = token
		action := ActionMFAVerified
		if recoverUsed {
			action = ActionRecoveryUsed
		}
		if err := s.auditTx(ctx, tx, AuditRecord{
			Action:    action,
			Actor:     actor.Actor{Kind: actor.Human, ID: u.ID, SessionID: result.Session.ID},
			Subject:   u.Subject(),
			Outcome:   OutcomeSuccess,
			ClientIP:  in.ClientIP,
			UserAgent: in.UserAgent,
		}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	if failure != "" {
		s.recordMFAFailure(ctx, u, in, failure)
		return LoginResult{}, unauthenticated()
	}
	s.thr.Reset(u.Username, in.ClientIP)
	return result, nil
}

// recordMFAFailure writes the audit record for a failed second factor.
func (s *Service) recordMFAFailure(ctx context.Context, u User, in VerifyMFAInput, reason string) {
	s.auditRecord(ctx, AuditRecord{
		Action:    ActionMFAFailed,
		Actor:     actor.SystemActor("identity"),
		Subject:   u.Subject(),
		Outcome:   OutcomeFailure,
		Reason:    reason,
		ClientIP:  in.ClientIP,
		UserAgent: in.UserAgent,
	})
}

// completeLogin creates the session and resets the backoff after a successful
// password-only login.
func (s *Service) completeLogin(ctx context.Context, u User, in LoginInput, newHash string, mfaAt time.Time) (Session, string, error) {
	var (
		sess  Session
		token string
	)
	err := s.update(ctx, func(tx *storage.Tx) error {
		now := tx.Now()
		if newHash != "" {
			if err := upsertPasswordTx(ctx, tx, u.ID, newHash, now); err != nil {
				return err
			}
		}
		var err error
		sess, token, err = s.insertSessionTx(ctx, tx, u, sessionSpec{
			Created: now, Expires: now.Add(s.absoluteTimeout), MFAVerifiedAt: mfaAt,
			ClientIP: in.ClientIP, UserAgent: in.UserAgent,
		})
		if err != nil {
			return err
		}
		return s.auditTx(ctx, tx, AuditRecord{
			Action:    ActionLogin,
			Actor:     actor.Actor{Kind: actor.Human, ID: u.ID, SessionID: sess.ID},
			Subject:   u.Subject(),
			Outcome:   OutcomeSuccess,
			ClientIP:  in.ClientIP,
			UserAgent: in.UserAgent,
		})
	})
	if err != nil {
		return Session{}, "", err
	}
	s.thr.Reset(u.Username, in.ClientIP)
	return sess, token, nil
}

// Logout revokes the session. Repeating it is harmless; an unknown token is not
// an error because the caller usually resolved the session first.
func (s *Service) Logout(ctx context.Context, token string) error {
	sess, err := s.sessionByToken(ctx, token)
	if err != nil {
		if problem.HasCode(err, problem.Unauthenticated) {
			return nil
		}
		return err
	}
	return s.update(ctx, func(tx *storage.Tx) error {
		now := tx.Now()
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at = ''`,
			formatTime(now), sess.ID); err != nil {
			return fmt.Errorf("identity: revoke session: %w", err)
		}
		return s.auditTx(ctx, tx, AuditRecord{
			Action:   ActionLogout,
			Actor:    actor.Actor{Kind: actor.Human, ID: sess.User.ID, SessionID: sess.ID},
			Subject:  sess.User.Subject(),
			Outcome:  OutcomeSuccess,
			ClientIP: sess.ClientIP,
		})
	})
}

// challenge is one pending second-factor answer.
type challengeRow struct {
	IDHash    []byte
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
	Attempts  int
	ClientIP  string
}

const challengeColumns = `id_hash, user_id, created_at, expires_at, used_at, attempts, client_ip`

func scanChallenge(row scanner) (challengeRow, error) {
	var ch challengeRow
	var created, expires, used string
	if err := row.Scan(&ch.IDHash, &ch.UserID, &created, &expires, &used, &ch.Attempts, &ch.ClientIP); err != nil {
		return challengeRow{}, err
	}
	var err error
	if ch.CreatedAt, err = parseTime(created); err != nil {
		return challengeRow{}, err
	}
	if ch.ExpiresAt, err = parseTime(expires); err != nil {
		return challengeRow{}, err
	}
	ch.Used = used != ""
	return ch, nil
}

func (s *Service) challenge(ctx context.Context, id string) (challengeRow, error) {
	if id == "" {
		return challengeRow{}, unauthenticated()
	}
	ch, err := scanChallenge(s.db.Reader().QueryRowContext(ctx,
		`SELECT `+challengeColumns+` FROM mfa_challenges WHERE id_hash = ?`, hashToken(id)))
	if isNoRows(err) {
		return challengeRow{}, unauthenticated()
	}
	if err != nil {
		return challengeRow{}, fmt.Errorf("identity: load challenge: %w", err)
	}
	return ch, nil
}

func (s *Service) challengeTx(ctx context.Context, tx *storage.Tx, id string) (challengeRow, error) {
	ch, err := scanChallenge(tx.QueryRowContext(ctx,
		`SELECT `+challengeColumns+` FROM mfa_challenges WHERE id_hash = ?`, hashToken(id)))
	if isNoRows(err) {
		return challengeRow{}, unauthenticated()
	}
	if err != nil {
		return challengeRow{}, fmt.Errorf("identity: load challenge: %w", err)
	}
	return ch, nil
}
