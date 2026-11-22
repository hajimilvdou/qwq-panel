// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Role is a built-in role. The values match the Role enum of the public API
// (openapi.yaml: admin, operator, viewer); the read-only role is called "viewer"
// in the API and "readonly" in the implementation plan, so RoleReadonly is an
// alias for RoleViewer.
type Role string

// Built-in roles (ADR-0005 Q7).
const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
	// RoleReadonly is the plan's name for RoleViewer; the public API calls it
	// "viewer".
	RoleReadonly = RoleViewer
)

// Roles lists the built-in roles in descending order of authority.
func Roles() []Role { return []Role{RoleAdmin, RoleOperator, RoleViewer} }

// Valid reports whether r is a built-in role.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	}
	return false
}

// ParseRole validates a role string from a request.
func ParseRole(s string) (Role, error) {
	r := Role(strings.TrimSpace(s))
	if !r.Valid() {
		return "", problem.Validation(problem.Violation{
			Pointer: "/role", Code: "invalid",
			Message: "The role must be one of: admin, operator, viewer.",
		})
	}
	return r, nil
}

// User is a panel user as stored in the users table. Credentials and TOTP
// secrets are never part of this struct (the public User schema has no fields
// for them).
type User struct {
	ID          string
	Username    string
	DisplayName string
	Role        Role
	Disabled    bool
	// MFAEnabled reports that a confirmed TOTP credential exists.
	MFAEnabled bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Revision   int64
}

// Subject is the resource subject used in events and audit records.
func (u User) Subject() string { return "users/" + u.ID }

// Username rules, from the Username schema of the public API.
const (
	MaxUsernameLen    = 64
	MaxDisplayNameLen = 64
)

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// NormalizeUsername returns the canonical login name: trimmed and lower case.
// Comparison and uniqueness are therefore case-insensitive without a database
// collation. Only ASCII letters, digits, '.', '_' and '-' are accepted, which
// keeps the name safe in URLs, logs and audit records.
func NormalizeUsername(s string) (string, error) {
	u := strings.ToLower(strings.TrimSpace(s))
	if u == "" {
		return "", problem.Validation(problem.Violation{
			Pointer: "/username", Code: "required", Message: "A user name is required.",
		})
	}
	if utf8.RuneCountInString(u) > MaxUsernameLen || !usernameRe.MatchString(u) {
		return "", problem.Validation(problem.Violation{
			Pointer: "/username", Code: "invalid",
			Message: "The user name must start with a letter or digit and contain only lower-case letters, digits, '.', '_' and '-' (at most 64 characters).",
		})
	}
	return u, nil
}

// normalizeDisplayName trims and validates a display name. Empty is allowed.
func normalizeDisplayName(s string) (string, error) {
	d := strings.TrimSpace(s)
	if utf8.RuneCountInString(d) > MaxDisplayNameLen {
		return "", problem.Validation(problem.Violation{
			Pointer: "/display_name", Code: "too_long",
			Message: "The display name must be at most 64 characters.",
		})
	}
	for _, r := range d {
		if unicode.IsControl(r) {
			return "", problem.Validation(problem.Violation{
				Pointer: "/display_name", Code: "invalid",
				Message: "The display name must not contain control characters.",
			})
		}
	}
	return d, nil
}

// userColumns is the select list for a User, including the derived mfa_enabled
// flag (a confirmed TOTP credential exists). Keep in sync with scanUser.
const userColumns = `u.user_id, u.username, u.display_name, u.role, u.disabled,
	EXISTS (SELECT 1 FROM credentials c WHERE c.user_id = u.user_id AND c.type = 'totp'),
	u.created_at, u.updated_at, u.revision`

type scanner interface{ Scan(dest ...any) error }

func scanUser(row scanner) (User, error) {
	var u User
	var role string
	var disabled, mfa int
	var created, updated string
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &role, &disabled, &mfa,
		&created, &updated, &u.Revision); err != nil {
		return User{}, err
	}
	u.Role = Role(role)
	u.Disabled = disabled != 0
	u.MFAEnabled = mfa != 0
	var err error
	if u.CreatedAt, err = parseTime(created); err != nil {
		return User{}, fmt.Errorf("identity: user created_at: %w", err)
	}
	if u.UpdatedAt, err = parseTime(updated); err != nil {
		return User{}, fmt.Errorf("identity: user updated_at: %w", err)
	}
	return u, nil
}

// User returns one user by ID.
func (s *Service) User(ctx context.Context, userID string) (User, error) {
	u, err := scanUser(s.db.Reader().QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users u WHERE u.user_id = ?`, userID))
	if isNoRows(err) {
		return User{}, errNotFound("user")
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: load user: %w", err)
	}
	return u, nil
}

// UserByUsername returns one user by canonical login name.
func (s *Service) UserByUsername(ctx context.Context, username string) (User, error) {
	name, err := NormalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	u, err := scanUser(s.db.Reader().QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users u WHERE u.username = ?`, name))
	if isNoRows(err) {
		return User{}, errNotFound("user")
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: load user: %w", err)
	}
	return u, nil
}

// ListUsersInput filters ListUsers. Zero values mean "no filter".
type ListUsersInput struct {
	Role  Role
	After string // user ID cursor: return users with a greater ID
	Limit int    // default and maximum 200
}

// ListUsers returns a page of users ordered by ID (which sorts by creation
// time). It is a read-only query; the gateway applies fields/since_revision.
func (s *Service) ListUsers(ctx context.Context, in ListUsersInput) ([]User, error) {
	if in.Limit <= 0 || in.Limit > 200 {
		in.Limit = 200
	}
	q := `SELECT ` + userColumns + ` FROM users u WHERE 1 = 1`
	args := []any{}
	if in.Role != "" {
		if !in.Role.Valid() {
			return nil, problem.Validation(problem.Violation{Pointer: "/role", Code: "invalid", Message: "Unknown role."})
		}
		q += ` AND u.role = ?`
		args = append(args, string(in.Role))
	}
	if in.After != "" {
		q += ` AND u.user_id > ?`
		args = append(args, in.After)
	}
	q += ` ORDER BY u.user_id LIMIT ?`
	args = append(args, in.Limit)
	rows, err := s.db.Reader().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("identity: list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: scan user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// userTx loads a user inside the caller's write transaction.
func (s *Service) userTx(ctx context.Context, tx *storage.Tx, userID string) (User, error) {
	u, err := scanUser(tx.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users u WHERE u.user_id = ?`, userID))
	if isNoRows(err) {
		return User{}, errNotFound("user")
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: load user: %w", err)
	}
	return u, nil
}

// checkRevision enforces optimistic concurrency (ADR-0004 D2). A zero expected
// revision is a validation error, not a wildcard.
func checkRevision(expected, current int64) error {
	if expected <= 0 {
		return problem.Validation(problem.Violation{
			Pointer: "/expected_revision", Code: "required",
			Message: "expected_revision is required and must be a positive revision.",
		})
	}
	if expected != current {
		return problem.Conflict(storage.Revision(current))
	}
	return nil
}

// activeAdmins counts users who can still approve: enabled administrators.
func activeAdmins(ctx context.Context, tx *storage.Tx) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}

// CreateUserInput describes a new user. PasswordHash comes from
// PreparePassword; when it is empty the user cannot log in until they redeem an
// enrolment link, and CreateUser opens a pending enrolment.
type CreateUserInput struct {
	Username     string
	DisplayName  string
	Role         Role
	PasswordHash string
	// Actor is recorded in the audit record when the transaction has no origin.
	Actor actor.Actor
}

// CreateUserResult is the outcome of CreateUser.
type CreateUserResult struct {
	User User
	// EnrollmentUntil is set when no password was supplied: the end of the
	// pending enrolment CreateUser opened. Its token is never returned, because
	// this result travels through an operation record that every reader of the
	// operation can see (AUTH-06); the link an administrator hands out comes
	// from NewEnrollmentToken, which replaces it.
	EnrollmentUntil time.Time
}

// CreateUser inserts a user in the caller's transaction and records the
// resource.changed event. The operation wrapper (internal/operations) owns the
// operation row and the risk/approval decision.
func (s *Service) CreateUser(ctx context.Context, tx *storage.Tx, in CreateUserInput) (CreateUserResult, error) {
	username, err := NormalizeUsername(in.Username)
	if err != nil {
		return CreateUserResult{}, err
	}
	display, err := normalizeDisplayName(in.DisplayName)
	if err != nil {
		return CreateUserResult{}, err
	}
	if !in.Role.Valid() {
		return CreateUserResult{}, problem.Validation(problem.Violation{
			Pointer: "/role", Code: "invalid", Message: "The role must be one of: admin, operator, viewer.",
		})
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE username = ?`, username).Scan(&exists); err != nil {
		return CreateUserResult{}, fmt.Errorf("identity: check user name: %w", err)
	}
	if exists > 0 {
		return CreateUserResult{}, &problem.Error{
			Code: problem.StateConflict, Detail: "A user with this name already exists.",
		}
	}
	now := tx.Now()
	userID := tx.NewID(ids.User)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users (user_id, username, display_name, role, disabled, created_at, updated_at, revision)
		 VALUES (?, ?, ?, ?, 0, ?, ?, 0)`,
		userID, username, display, string(in.Role), formatTime(now), formatTime(now)); err != nil {
		return CreateUserResult{}, fmt.Errorf("identity: insert user: %w", err)
	}
	if in.PasswordHash != "" {
		if err := insertCredentialTx(ctx, tx, userID, credPassword, in.PasswordHash, "{}", 0, now); err != nil {
			return CreateUserResult{}, err
		}
	}
	seq, err := tx.Changed(ctx, storage.Change{Subject: "users/" + userID, Kind: storage.Created})
	if err != nil {
		return CreateUserResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET revision = ? WHERE user_id = ?`, seq, userID); err != nil {
		return CreateUserResult{}, fmt.Errorf("identity: set revision: %w", err)
	}
	res := CreateUserResult{}
	if in.PasswordHash == "" {
		_, until, err := s.insertOneTimeToken(ctx, tx, purposeEnroll, userID, now)
		if err != nil {
			return CreateUserResult{}, err
		}
		res.EnrollmentUntil = until
	}
	u, err := s.userTx(ctx, tx, userID)
	if err != nil {
		return CreateUserResult{}, err
	}
	res.User = u
	if err := s.auditTx(ctx, tx, AuditRecord{
		Action:  ActionUserCreated,
		Actor:   auditActor(tx, in.Actor),
		Subject: u.Subject(),
		Outcome: OutcomeSuccess,
		Detail:  map[string]string{"role": string(u.Role), "username": u.Username},
	}); err != nil {
		return CreateUserResult{}, err
	}
	return res, nil
}

// UpdateUserInput changes a user. Nil members are left unchanged.
type UpdateUserInput struct {
	UserID           string
	ExpectedRevision int64
	DisplayName      *string
	Role             *Role
	Disabled         *bool
	Actor            actor.Actor
}

// UpdateUser applies a patch in the caller's transaction. Disabling a user
// revokes their sessions; their delegations stop working because authz checks
// the owner's disabled flag on every request.
func (s *Service) UpdateUser(ctx context.Context, tx *storage.Tx, in UpdateUserInput) (User, error) {
	if in.DisplayName == nil && in.Role == nil && in.Disabled == nil {
		return User{}, problem.Validation(problem.Violation{
			Pointer: "/", Code: "empty", Message: "At least one of display_name, role or disabled is required.",
		})
	}
	cur, err := s.userTx(ctx, tx, in.UserID)
	if err != nil {
		return User{}, err
	}
	if err := checkRevision(in.ExpectedRevision, cur.Revision); err != nil {
		return User{}, err
	}
	var pointers []string
	display, role, disabled := cur.DisplayName, cur.Role, cur.Disabled
	if in.DisplayName != nil {
		d, err := normalizeDisplayName(*in.DisplayName)
		if err != nil {
			return User{}, err
		}
		if d != display {
			display = d
			pointers = append(pointers, "/display_name")
		}
	}
	if in.Role != nil {
		if !in.Role.Valid() {
			return User{}, problem.Validation(problem.Violation{
				Pointer: "/role", Code: "invalid", Message: "The role must be one of: admin, operator, viewer.",
			})
		}
		if *in.Role != role {
			role = *in.Role
			pointers = append(pointers, "/role")
		}
	}
	if in.Disabled != nil && *in.Disabled != disabled {
		disabled = *in.Disabled
		pointers = append(pointers, "/disabled")
	}
	// Never remove the last enabled administrator: an installation without one
	// can only be recovered with `qwq recover`.
	if cur.Role == RoleAdmin && !cur.Disabled && (role != RoleAdmin || disabled) {
		n, err := activeAdmins(ctx, tx)
		if err != nil {
			return User{}, fmt.Errorf("identity: count administrators: %w", err)
		}
		if n <= 1 {
			return User{}, &problem.Error{
				Code: problem.StateConflict, Detail: "The last enabled administrator cannot be demoted or disabled.",
			}
		}
	}
	if len(pointers) == 0 {
		return cur, nil
	}
	now := tx.Now()
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET display_name = ?, role = ?, disabled = ?, updated_at = ? WHERE user_id = ?`,
		display, string(role), boolInt(disabled), formatTime(now), cur.ID); err != nil {
		return User{}, fmt.Errorf("identity: update user: %w", err)
	}
	if !cur.Disabled && disabled {
		if err := revokeUserSessionsTx(ctx, tx, cur.ID, now); err != nil {
			return User{}, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE user_id = ?`, cur.ID); err != nil {
			return User{}, fmt.Errorf("identity: clear challenges: %w", err)
		}
	}
	seq, err := tx.Changed(ctx, storage.Change{Subject: cur.Subject(), Kind: storage.Updated, Pointers: pointers})
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET revision = ? WHERE user_id = ?`, seq, cur.ID); err != nil {
		return User{}, fmt.Errorf("identity: set revision: %w", err)
	}
	if err := s.auditTx(ctx, tx, AuditRecord{
		Action:  ActionUserUpdated,
		Actor:   auditActor(tx, in.Actor),
		Subject: cur.Subject(),
		Outcome: OutcomeSuccess,
		Detail:  map[string]string{"role": string(role), "disabled": boolString(disabled)},
	}); err != nil {
		return User{}, err
	}
	return s.userTx(ctx, tx, cur.ID)
}

// DeleteUserInput removes a user.
type DeleteUserInput struct {
	UserID           string
	ExpectedRevision int64
	Actor            actor.Actor
}

// DeleteUser deletes a user in the caller's transaction. Sessions, credentials,
// MFA challenges and delegations disappear through ON DELETE CASCADE. Deleting
// the last enabled administrator fails with STATE_CONFLICT.
func (s *Service) DeleteUser(ctx context.Context, tx *storage.Tx, in DeleteUserInput) error {
	cur, err := s.userTx(ctx, tx, in.UserID)
	if err != nil {
		return err
	}
	if err := checkRevision(in.ExpectedRevision, cur.Revision); err != nil {
		return err
	}
	if cur.Role == RoleAdmin && !cur.Disabled {
		n, err := activeAdmins(ctx, tx)
		if err != nil {
			return fmt.Errorf("identity: count administrators: %w", err)
		}
		if n <= 1 {
			return &problem.Error{
				Code: problem.StateConflict, Detail: "The last enabled administrator cannot be deleted.",
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE user_id = ?`, cur.ID); err != nil {
		return fmt.Errorf("identity: delete user: %w", err)
	}
	if _, err := tx.Changed(ctx, storage.Change{Subject: cur.Subject(), Kind: storage.Deleted}); err != nil {
		return err
	}
	return s.auditTx(ctx, tx, AuditRecord{
		Action:  ActionUserDeleted,
		Actor:   auditActor(tx, in.Actor),
		Subject: cur.Subject(),
		Outcome: OutcomeSuccess,
		Detail:  map[string]string{"username": cur.Username},
	})
}

// ResetPasswordInput sets a new password for a user (administrator reset or the
// result of a completed enrolment).
type ResetPasswordInput struct {
	UserID           string
	ExpectedRevision int64
	PasswordHash     string
	// KeepSessions keeps the user's existing sessions. An administrative reset
	// should revoke them (the default).
	KeepSessions bool
	Actor        actor.Actor
}

// ResetPassword replaces the password credential in the caller's transaction
// and by default revokes the user's sessions. PasswordHash must come from
// PreparePassword.
func (s *Service) ResetPassword(ctx context.Context, tx *storage.Tx, in ResetPasswordInput) (User, error) {
	cur, err := s.userTx(ctx, tx, in.UserID)
	if err != nil {
		return User{}, err
	}
	if err := checkRevision(in.ExpectedRevision, cur.Revision); err != nil {
		return User{}, err
	}
	if in.PasswordHash == "" {
		return User{}, problem.Validation(problem.Violation{
			Pointer: "/password", Code: "required", Message: "A password is required.",
		})
	}
	now := tx.Now()
	if err := upsertPasswordTx(ctx, tx, cur.ID, in.PasswordHash, now); err != nil {
		return User{}, err
	}
	if err := deleteUnusedOneTimeTokensTx(ctx, tx, purposeEnroll, cur.ID); err != nil {
		return User{}, err
	}
	if !in.KeepSessions {
		if err := revokeUserSessionsTx(ctx, tx, cur.ID, now); err != nil {
			return User{}, err
		}
	}
	seq, err := tx.Changed(ctx, storage.Change{Subject: cur.Subject(), Kind: storage.Updated})
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET updated_at = ?, revision = ? WHERE user_id = ?`,
		formatTime(now), seq, cur.ID); err != nil {
		return User{}, fmt.Errorf("identity: set revision: %w", err)
	}
	if err := s.auditTx(ctx, tx, AuditRecord{
		Action:  ActionPasswordReset,
		Actor:   auditActor(tx, in.Actor),
		Subject: cur.Subject(),
		Outcome: OutcomeSuccess,
	}); err != nil {
		return User{}, err
	}
	return s.userTx(ctx, tx, cur.ID)
}

// ErrPrincipalNotFound reports that a user ID has no row; authz treats it as a
// denial.
var ErrPrincipalNotFound = errors.New("identity: principal not found")

// PrincipalRole returns the current role and disabled flag of a user. It is the
// narrow interface authz uses to recompute a delegation's authority on every
// request (ADR-0004 D4) without importing this package.
func (s *Service) PrincipalRole(ctx context.Context, userID string) (role string, disabled bool, err error) {
	return principalRoleRow(s.db.Reader().QueryRowContext(ctx, principalRoleQuery, userID))
}

const principalRoleQuery = `SELECT role, disabled FROM users WHERE user_id = ?`

// PrincipalRoleTx 与真实会话核验共享调用方事务，使账号创建前的撤权立即可见。
// 这里只查询当前角色，不刷新会话、签发身份或执行另一写事务。
func (s *Service) PrincipalRoleTx(ctx context.Context, tx *storage.Tx, userID string) (string, bool, error) {
	if s == nil || ctx == nil || tx == nil {
		return "", false, fmt.Errorf("identity: principal transaction is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	return principalRoleRow(tx.QueryRowContext(ctx, principalRoleQuery, userID))
}

func principalRoleRow(row scanner) (role string, disabled bool, err error) {
	var d int
	err = row.Scan(&role, &d)
	if isNoRows(err) {
		return "", false, ErrPrincipalNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("identity: load principal: %w", err)
	}
	return role, d != 0, nil
}

// auditTx writes one audit record in the caller's transaction.
func (s *Service) auditTx(ctx context.Context, tx *storage.Tx, rec AuditRecord) error {
	if s.audit == nil {
		return nil
	}
	if rec.At.IsZero() {
		rec.At = tx.Now()
	}
	if err := s.audit.Audit(ctx, tx, rec); err != nil {
		return fmt.Errorf("identity: audit: %w", err)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
