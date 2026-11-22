// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Purposes of a one-time token.
const (
	purposeSetup               = "setup"
	purposeEnroll              = "enroll"
	oneTimeTokenThrottlePrefix = "token:"
)

// oneTimeToken is a row of the one_time_tokens table.
type oneTimeToken struct {
	ID        string
	Purpose   string
	UserID    string
	Hash      []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
}

const oneTimeTokenColumns = `token_id, purpose, COALESCE(user_id, ''), token_hash, created_at, expires_at, used_at`

type oneTimeTokenReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func scanOneTimeToken(row scanner) (oneTimeToken, error) {
	var t oneTimeToken
	var created, expires, used string
	if err := row.Scan(&t.ID, &t.Purpose, &t.UserID, &t.Hash, &created, &expires, &used); err != nil {
		return oneTimeToken{}, err
	}
	var err error
	if t.CreatedAt, err = parseTime(created); err != nil {
		return oneTimeToken{}, err
	}
	if t.ExpiresAt, err = parseTime(expires); err != nil {
		return oneTimeToken{}, err
	}
	t.Used = used != ""
	return t, nil
}

// insertOneTimeToken mints a token, stores only its SHA-256 and invalidates
// older unused tokens of the same purpose (for enrolment: of the same user).
func (s *Service) insertOneTimeToken(ctx context.Context, tx *storage.Tx, purpose, userID string, now time.Time) (string, time.Time, error) {
	ttl := s.setupTokenTTL
	if purpose == purposeEnroll {
		ttl = s.enrollmentTokenTTL
	}
	raw, digest, err := newSecret()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := now.Add(ttl)
	if err := deleteUnusedOneTimeTokensTx(ctx, tx, purpose, userID); err != nil {
		return "", time.Time{}, err
	}
	var user any
	if userID != "" {
		user = userID
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO one_time_tokens (token_id, purpose, user_id, token_hash, created_at, expires_at, used_at)
		 VALUES (?, ?, ?, ?, ?, ?, '')`,
		tx.NewID(ids.SetupToken), purpose, user, digest, formatTime(now), formatTime(expires)); err != nil {
		return "", time.Time{}, fmt.Errorf("identity: insert one-time token: %w", err)
	}
	return raw, expires, nil
}

// ======================== 同一规则的廉价预检与事务重验 ========================

// deleteUnusedOneTimeTokensTx 同时供发新链接和管理员设密码时撤销旧链接。
// SQLite 的 IS 支持精确 user_id 和安装 token 的 NULL 分组，互不影响其他用户。
func deleteUnusedOneTimeTokensTx(ctx context.Context, tx *storage.Tx, purpose, userID string) error {
	var user any
	if userID != "" {
		user = userID
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM one_time_tokens WHERE purpose = ? AND user_id IS ? AND used_at = ''`, purpose, user); err != nil {
		return fmt.Errorf("identity: clear one-time tokens: %w", err)
	}
	return nil
}

// findOneTimeToken 只执行有界 token 校验和 SHA-256 查询，不占用 Argon2 槽。
// 只读预检和写事务共享用途、恒时比较、已用与到期判断，避免两条规则漂移。
func (s *Service) findOneTimeToken(ctx context.Context, q oneTimeTokenReader, purpose, token string, now time.Time) (oneTimeToken, error) {
	// newSecret 固定生成 32 字节的无填充 base64url；其文本长度为 43。
	if len(token) != 43 {
		return oneTimeToken{}, unauthenticated()
	}
	digest := hashToken(token)
	t, err := scanOneTimeToken(q.QueryRowContext(ctx,
		`SELECT `+oneTimeTokenColumns+` FROM one_time_tokens WHERE purpose = ? AND token_hash = ?`,
		purpose, digest))
	if isNoRows(err) {
		return oneTimeToken{}, unauthenticated()
	}
	if err != nil {
		return oneTimeToken{}, fmt.Errorf("identity: load one-time token: %w", err)
	}
	if subtle.ConstantTimeCompare(t.Hash, digest) != 1 {
		return oneTimeToken{}, unauthenticated()
	}
	if t.Used {
		return oneTimeToken{}, unauthenticated()
	}
	if !now.Before(t.ExpiresAt) {
		return oneTimeToken{}, unauthenticated()
	}
	return t, nil
}

func (s *Service) findOneTimeTokenTx(ctx context.Context, tx *storage.Tx, purpose, token string) (oneTimeToken, error) {
	return s.findOneTimeToken(ctx, tx, purpose, token, tx.Now())
}

// beginOneTimeToken 复用已有有界节流；key 只保存用途和摘要，不保存 token 明文，
// 并与用户名、password/MFA 的计数命名空间分开。当前 IP 的喷洒计数仍然共享。
func (s *Service) beginOneTimeToken(ctx context.Context, purpose, token, clientIP string) (oneTimeToken, string, error) {
	key := fmt.Sprintf("%s%s:%x", oneTimeTokenThrottlePrefix, purpose, hashToken(token))
	if wait, ok := s.thr.Attempt(key, clientIP); !ok {
		return oneTimeToken{}, "", rateLimited(wait)
	}
	t, err := s.findOneTimeToken(ctx, s.db.Reader(), purpose, token, s.now())
	return t, key, err
}

// SetupInitialized reports whether an administrator exists, i.e. whether the
// first-time setup is closed (openapi GET /api/v1/setup).
func (s *Service) SetupInitialized(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&n); err != nil {
		return false, fmt.Errorf("identity: count administrators: %w", err)
	}
	return n > 0, nil
}

// NewSetupToken mints the one-time installation token. The installer calls it
// once and prints a link with the token in the URL fragment (so it never
// reaches access logs). Only the hash is stored; issuing a new token invalidates
// an unused older one.
func (s *Service) NewSetupToken(ctx context.Context) (string, time.Time, error) {
	var (
		token   string
		expires time.Time
	)
	err := s.update(ctx, func(tx *storage.Tx) error {
		var err error
		token, expires, err = s.insertOneTimeToken(ctx, tx, purposeSetup, "", tx.Now())
		if err != nil {
			return err
		}
		return s.auditTx(ctx, tx, AuditRecord{
			Action:  ActionSetupTokenIssued,
			Actor:   actor.SystemActor("installer"),
			Outcome: OutcomeSuccess,
		})
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// CompleteSetupInput is the first administrator and the installation token.
type CompleteSetupInput struct {
	SetupToken  string
	Username    string
	Password    string
	DisplayName string
	ClientIP    string
	UserAgent   string
}

// CompleteSetup creates the first administrator and logs them in (openapi
// POST /api/v1/setup). The administrator check, the token consumption, the user
// and the session are all written in one transaction, so a crash cannot leave
// the installation half-initialised or the token usable twice.
func (s *Service) CompleteSetup(ctx context.Context, in CompleteSetupInput) (LoginResult, error) {
	initialized, err := s.SetupInitialized(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	if initialized {
		return LoginResult{}, &problem.Error{
			Code: problem.StateConflict, Detail: "The installation is already initialized.",
		}
	}
	username, err := NormalizeUsername(in.Username)
	if err != nil {
		return LoginResult{}, err
	}
	display, err := normalizeDisplayName(in.DisplayName)
	if err != nil {
		return LoginResult{}, err
	}
	_, throttleKey, err := s.beginOneTimeToken(ctx, purposeSetup, in.SetupToken, in.ClientIP)
	if err != nil {
		return LoginResult{}, err
	}
	// Hash before opening the transaction: argon2 must not extend the write lock.
	hash, err := s.preparePassword(ctx, username, in.Password)
	if err != nil {
		return LoginResult{}, err
	}
	var (
		sess  Session
		token string
	)
	err = s.update(ctx, func(tx *storage.Tx) error {
		n, err := activeAdmins(ctx, tx)
		if err != nil {
			return fmt.Errorf("identity: count administrators: %w", err)
		}
		if n > 0 {
			return &problem.Error{Code: problem.StateConflict, Detail: "The installation is already initialized."}
		}
		if _, err := s.findOneTimeTokenTx(ctx, tx, purposeSetup, in.SetupToken); err != nil {
			return err
		}
		now := tx.Now()
		userID := tx.NewID(ids.User)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO users (user_id, username, display_name, role, disabled, created_at, updated_at, revision)
			 VALUES (?, ?, ?, 'admin', 0, ?, ?, 0)`,
			userID, username, display, formatTime(now), formatTime(now)); err != nil {
			return fmt.Errorf("identity: insert administrator: %w", err)
		}
		if err := insertCredentialTx(ctx, tx, userID, credPassword, hash, "{}", 0, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE one_time_tokens SET used_at = ? WHERE purpose = ? AND token_hash = ?`,
			formatTime(now), purposeSetup, hashToken(in.SetupToken)); err != nil {
			return fmt.Errorf("identity: consume setup token: %w", err)
		}
		seq, err := tx.Changed(ctx, storage.Change{Subject: "users/" + userID, Kind: storage.Created})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET revision = ? WHERE user_id = ?`, seq, userID); err != nil {
			return fmt.Errorf("identity: set revision: %w", err)
		}
		u, err := s.userTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		sess, token, err = s.insertSessionTx(ctx, tx, u, sessionSpec{
			Created: now, Expires: now.Add(s.absoluteTimeout),
			ClientIP: in.ClientIP, UserAgent: in.UserAgent,
		})
		if err != nil {
			return err
		}
		return s.auditTx(ctx, tx, AuditRecord{
			Action:    ActionSetupCompleted,
			Actor:     actor.SystemActor("setup"),
			Subject:   u.Subject(),
			Outcome:   OutcomeSuccess,
			ClientIP:  in.ClientIP,
			UserAgent: in.UserAgent,
			Detail:    map[string]string{"username": u.Username},
		})
	})
	if err != nil {
		return LoginResult{}, err
	}
	s.thr.Reset(throttleKey, in.ClientIP)
	return LoginResult{Session: sess, Token: token}, nil
}

// NewEnrollmentToken mints the one-time token of an enrolment link: it lets a
// user who has no password yet choose their first one. It runs in the caller's
// transaction, so the caller's audit row commits with the token. Only the hash
// is stored, and minting replaces every unused enrolment token of the user, so
// at most one link works at a time.
//
// A user who already has a password gets STATE_CONFLICT: a link would let
// whoever holds it replace that password and take the account over, and
// changing a password is ResetPassword's job.
func (s *Service) NewEnrollmentToken(ctx context.Context, tx *storage.Tx, userID string) (string, time.Time, error) {
	u, err := s.userTx(ctx, tx, userID)
	if err != nil {
		return "", time.Time{}, err
	}
	if u.Disabled {
		return "", time.Time{}, &problem.Error{Code: problem.StateConflict, Detail: "The user is disabled."}
	}
	switch _, err := findCredentialTx(ctx, tx, u.ID, credPassword); {
	case err == nil:
		return "", time.Time{}, &problem.Error{Code: problem.StateConflict, Detail: "The user already has a password."}
	case !isNoRows(err):
		return "", time.Time{}, fmt.Errorf("identity: load credential: %w", err)
	}
	return s.insertOneTimeToken(ctx, tx, purposeEnroll, u.ID, tx.Now())
}

// RedeemEnrollmentToken sets a user's first password from an enrolment link.
// The token is the only authority: the user has no session yet.
func (s *Service) RedeemEnrollmentToken(ctx context.Context, token, password string) (User, error) {
	return s.redeemEnrollmentToken(ctx, token, password, "")
}

func checkEnrollmentUser(u User, hasPassword bool) error {
	if u.Disabled {
		return problem.New(problem.PermissionDenied, "The user is disabled.")
	}
	if hasPassword {
		return unauthenticated()
	}
	return nil
}

// redeemEnrollmentToken 保留旧公开签名，HTTP 包装层额外传入已验证的 ClientIP。
// token 和首次密码状态先于哈希预检，写事务再次核验，以保护哈希期间的撤权。
func (s *Service) redeemEnrollmentToken(ctx context.Context, token, password, clientIP string) (User, error) {
	t, throttleKey, err := s.beginOneTimeToken(ctx, purposeEnroll, token, clientIP)
	if err != nil {
		return User{}, err
	}
	u, err := s.User(ctx, t.UserID)
	if err != nil {
		return User{}, err
	}
	hasPassword, err := s.hasCredential(ctx, u.ID, credPassword)
	if err != nil {
		return User{}, err
	}
	if err := checkEnrollmentUser(u, hasPassword); err != nil {
		return User{}, err
	}
	hash, err := s.preparePassword(ctx, u.Username, password)
	if err != nil {
		return User{}, err
	}
	err = s.update(ctx, func(tx *storage.Tx) error {
		t, err := s.findOneTimeTokenTx(ctx, tx, purposeEnroll, token)
		if err != nil {
			return err
		}
		if t.UserID != u.ID {
			return unauthenticated()
		}
		cur, err := s.userTx(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		_, credentialErr := findCredentialTx(ctx, tx, cur.ID, credPassword)
		if credentialErr != nil && !isNoRows(credentialErr) {
			return fmt.Errorf("identity: load credential: %w", credentialErr)
		}
		if err := checkEnrollmentUser(cur, credentialErr == nil); err != nil {
			return err
		}
		now := tx.Now()
		if err := insertCredentialTx(ctx, tx, cur.ID, credPassword, hash, "{}", 0, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE one_time_tokens SET used_at = ? WHERE token_id = ?`, formatTime(now), t.ID); err != nil {
			return fmt.Errorf("identity: consume enrolment token: %w", err)
		}
		if err := revokeUserSessionsTx(ctx, tx, cur.ID, now); err != nil {
			return err
		}
		_, err = s.markUserChanged(ctx, tx, cur, nil, ActionPasswordChanged,
			actor.Actor{Kind: actor.Human, ID: cur.ID})
		return err
	})
	if err != nil {
		return User{}, err
	}
	s.thr.Reset(throttleKey, clientIP)
	return s.User(ctx, u.ID)
}
