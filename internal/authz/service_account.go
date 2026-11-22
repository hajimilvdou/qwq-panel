// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"context"
	"database/sql"
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

// ServiceAccount is an automation credential. It authenticates as
// actor.Kind=service and is limited to its role, minus every human-only action.
// Issuance is not part of the public API draft (openapi securitySchemes
// serviceAccountToken: "issuance is out of scope for this draft"), so the host
// creates one with this package; there is no HTTP route yet.
type ServiceAccount struct {
	ID          string
	Name        string
	Role        Role
	TokenPrefix string
	Disabled    bool
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastUsedAt  time.Time
	Revision    int64
	Scope       *ServiceScope
}

// Subject is the resource subject used in events.
func (s ServiceAccount) Subject() string { return "service_accounts/" + s.ID }

// CreatedServiceAccount carries the token, which is shown only once.
type CreatedServiceAccount struct {
	ServiceAccount
	Token string
}

// CreateServiceAccountInput issues a token for a service account.
type CreateServiceAccountInput struct {
	// Actor must be a human session: a service account can never create one.
	Actor actor.Actor
	Name  string
	Role  Role
	Scope *ServiceScope
}

var serviceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// CreateServiceAccount mints a service-account token in the caller's
// transaction and publishes the resource.changed event.
func (z *Authorizer) CreateServiceAccount(ctx context.Context, tx *storage.Tx, in CreateServiceAccountInput) (CreatedServiceAccount, error) {
	if !in.Actor.IsHumanSession() {
		return CreatedServiceAccount{}, problem.New(problem.PermissionDenied, "Only a human session may create a service account.")
	}
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if name == "" || utf8.RuneCountInString(name) > 64 || !serviceNameRe.MatchString(name) {
		return CreatedServiceAccount{}, problem.Validation(problem.Violation{
			Pointer: "/name", Code: "invalid",
			Message: "The name must start with a letter or digit and contain only lower-case letters, digits, '.', '_' and '-'.",
		})
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return CreatedServiceAccount{}, problem.Validation(problem.Violation{
				Pointer: "/name", Code: "invalid", Message: "The name must not contain control characters.",
			})
		}
	}
	if !in.Role.Valid() {
		return CreatedServiceAccount{}, problem.Validation(problem.Violation{
			Pointer: "/role", Code: "invalid", Message: "The role must be one of: admin, operator, viewer.",
		})
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_accounts WHERE name = ?`, name).Scan(&exists); err != nil {
		return CreatedServiceAccount{}, err
	}
	if exists > 0 {
		return CreatedServiceAccount{}, &problem.Error{
			Code: problem.StateConflict, Detail: "A service account with this name already exists.",
		}
	}
	encodedScope, err := encodeServiceScope(in.Scope, tx.Now())
	if err != nil {
		return CreatedServiceAccount{}, err
	}
	token, digest, prefix, err := mintToken(ServiceTokenPrefix)
	if err != nil {
		return CreatedServiceAccount{}, err
	}
	now := tx.Now()
	id := tx.NewID(ids.Service)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO service_accounts (service_id, name, role, token_hash, token_prefix, disabled,
			created_by, created_at, updated_at, last_used_at, revision, scope_json)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, '', 0, ?)`,
		id, name, string(in.Role), digest, prefix, in.Actor.ID,
		formatTime(now), formatTime(now), encodedScope); err != nil {
		return CreatedServiceAccount{}, err
	}
	seq, err := tx.Changed(ctx, storage.Change{Subject: "service_accounts/" + id, Kind: storage.Created})
	if err != nil {
		return CreatedServiceAccount{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE service_accounts SET revision = ? WHERE service_id = ?`, seq, id); err != nil {
		return CreatedServiceAccount{}, err
	}
	sa, err := z.serviceAccountTx(ctx, tx, id)
	if err != nil {
		return CreatedServiceAccount{}, err
	}
	return CreatedServiceAccount{ServiceAccount: sa, Token: token}, nil
}

// RevokeServiceAccountInput deletes a service account.
type RevokeServiceAccountInput struct {
	Actor            actor.Actor
	ServiceAccountID string
	ExpectedRevision int64
}

// RevokeServiceAccount deletes the account in the caller's transaction; its
// token stops working at once.
func (z *Authorizer) RevokeServiceAccount(ctx context.Context, tx *storage.Tx, in RevokeServiceAccountInput) error {
	if !in.Actor.IsHumanSession() {
		return problem.New(problem.PermissionDenied, "Only a human session may revoke a service account.")
	}
	cur, err := z.serviceAccountTx(ctx, tx, in.ServiceAccountID)
	if err != nil {
		return err
	}
	if err := checkRevision(in.ExpectedRevision, cur.Revision); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM service_accounts WHERE service_id = ?`, cur.ID); err != nil {
		return err
	}
	_, err = tx.Changed(ctx, storage.Change{Subject: cur.Subject(), Kind: storage.Deleted})
	return err
}

// ServiceAccount returns one service account by ID.
func (z *Authorizer) ServiceAccount(ctx context.Context, id string) (ServiceAccount, error) {
	sa, err := scanServiceAccount(z.db.Reader().QueryRowContext(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts WHERE service_id = ?`, id))
	if isNoRows(err) {
		return ServiceAccount{}, problem.New(problem.NotFound, "The service account does not exist.")
	}
	if err != nil {
		return ServiceAccount{}, err
	}
	return sa, nil
}

func (z *Authorizer) serviceAccountTx(ctx context.Context, tx *storage.Tx, id string) (ServiceAccount, error) {
	sa, err := scanServiceAccount(tx.QueryRowContext(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts WHERE service_id = ?`, id))
	if isNoRows(err) {
		return ServiceAccount{}, problem.New(problem.NotFound, "The service account does not exist.")
	}
	if err != nil {
		return ServiceAccount{}, err
	}
	return sa, nil
}

// ServiceAccountByNameTx 读取当前创建事务中的账号，用于精确范围的幂等复用。
// 名称只作为参数绑定；不会签发凭据、刷新使用时间或打开另一事务。
func (z *Authorizer) ServiceAccountByNameTx(ctx context.Context, tx *storage.Tx, name string) (ServiceAccount, error) {
	if z == nil || ctx == nil || tx == nil {
		return ServiceAccount{}, problem.New(problem.Unavailable, "服务账号事务不可用。")
	}
	if err := ctx.Err(); err != nil {
		return ServiceAccount{}, err
	}
	account, err := scanServiceAccount(tx.QueryRowContext(ctx,
		"SELECT "+serviceAccountColumns+" FROM service_accounts WHERE name=?", name))
	if isNoRows(err) {
		return ServiceAccount{}, problem.New(problem.NotFound, "服务账号不存在。")
	}
	return account, err
}

// ListServiceAccounts returns a page of service accounts ordered by ID.
func (z *Authorizer) ListServiceAccounts(ctx context.Context, limit int) ([]ServiceAccount, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := z.db.Reader().QueryContext(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts ORDER BY service_id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceAccount
	for rows.Next() {
		sa, err := scanServiceAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sa)
	}
	return out, rows.Err()
}

// authenticateService resolves a service-account bearer token.
func (z *Authorizer) authenticateService(ctx context.Context, token string) (actor.Actor, error) {
	sa, err := scanServiceAccount(z.db.Reader().QueryRowContext(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts WHERE token_hash = ?`, hashToken(token)))
	if isNoRows(err) {
		return actor.Actor{}, unauthenticated()
	}
	if err != nil {
		return actor.Actor{}, err
	}
	if sa.Disabled {
		return actor.Actor{}, problem.New(problem.PermissionDenied, "The service account is disabled.")
	}
	if sa.Scope != nil {
		if !z.clock.Now().Before(sa.Scope.ExpiresAt) {
			return actor.Actor{}, deny("service scope has expired")
		}
		// 认证只确认创建者仍有效；具体角色交集在目标授权时检查。
		if err := z.authorizeHuman(ctx, actor.Actor{Kind: actor.Human, ID: sa.CreatedBy}, Permission("host.nodes:read")); err != nil {
			return actor.Actor{}, err
		}
	}
	z.touchServiceAccount(ctx, sa, z.clock.Now().UTC())
	return actor.Actor{Kind: actor.Service, ID: sa.ID}, nil
}

func (z *Authorizer) touchServiceAccount(ctx context.Context, sa ServiceAccount, now time.Time) {
	if now.Sub(sa.LastUsedAt) < z.touchInterval {
		return
	}
	err := z.db.Update(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE service_accounts SET last_used_at = ? WHERE service_id = ?`, formatTime(now), sa.ID)
		return err
	})
	if err != nil {
		z.log.WarnContext(ctx, "service account touch failed", "service_id", sa.ID, "error", err)
	}
}

const serviceAccountColumns = `service_id, name, role, token_prefix, disabled, created_by,
	created_at, updated_at, last_used_at, revision, scope_json`

func scanServiceAccount(row scanner) (ServiceAccount, error) {
	var sa ServiceAccount
	var role, created, updated, used string
	var disabled int
	var scope sql.NullString
	if err := row.Scan(&sa.ID, &sa.Name, &role, &sa.TokenPrefix, &disabled, &sa.CreatedBy,
		&created, &updated, &used, &sa.Revision, &scope); err != nil {
		return ServiceAccount{}, err
	}
	sa.Role = Role(role)
	sa.Disabled = disabled != 0
	var err error
	if sa.CreatedAt, err = parseTime(created); err != nil {
		return ServiceAccount{}, err
	}
	if sa.UpdatedAt, err = parseTime(updated); err != nil {
		return ServiceAccount{}, err
	}
	if sa.LastUsedAt, err = parseTime(used); err != nil {
		return ServiceAccount{}, err
	}
	if scope.Valid {
		if sa.Scope, err = decodeServiceScope(scope.String); err != nil {
			return ServiceAccount{}, err
		}
	}
	return sa, nil
}

// scanner is the common Scan interface of *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }
