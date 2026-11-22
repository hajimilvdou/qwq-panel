// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// DefaultTouchInterval throttles last_used_at writes for delegations and
// service accounts.
const DefaultTouchInterval = time.Minute

// PrincipalSource is the narrow view authz needs of the identity domain: the
// current role and the disabled flag of a user. identity.Service.PrincipalRole
// satisfies it without either package importing the other (ADR-0008 §1).
type PrincipalSource interface {
	PrincipalRole(ctx context.Context, userID string) (role string, disabled bool, err error)
}

// Options configure an Authorizer.
type Options struct {
	DB *storage.DB
	// Clock supplies the current time. Required to match DB's clock in tests.
	Clock clock.Clock
	// Logger receives denials caused by internal failures. Optional.
	Logger *slog.Logger
	// Principals resolves the owner of a delegation and the role of a human
	// actor. Required: without it every human and delegation request fails
	// closed.
	Principals PrincipalSource
	// RateLimiter bounds delegation requests. Defaults to a 4096-entry limiter.
	RateLimiter *RateLimiter
	// TouchInterval throttles last_used_at writes.
	TouchInterval time.Duration
}

// Authorizer answers "may this actor do this?" and owns delegations and service
// accounts. It is safe for concurrent use.
type Authorizer struct {
	db            *storage.DB
	clock         clock.Clock
	log           *slog.Logger
	principals    PrincipalSource
	limiter       *RateLimiter
	touchInterval time.Duration
}

// New validates opts and returns an Authorizer.
func New(opts Options) (*Authorizer, error) {
	if opts.DB == nil {
		return nil, errors.New("authz: Options.DB is required")
	}
	if opts.Principals == nil {
		return nil, errors.New("authz: Options.Principals is required")
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.RateLimiter == nil {
		opts.RateLimiter = NewRateLimiter(DefaultRateLimiterEntries, opts.Clock.Now)
	}
	if opts.TouchInterval <= 0 {
		opts.TouchInterval = DefaultTouchInterval
	}
	return &Authorizer{
		db:            opts.DB,
		clock:         opts.Clock,
		log:           opts.Logger,
		principals:    opts.Principals,
		limiter:       opts.RateLimiter,
		touchInterval: opts.TouchInterval,
	}, nil
}

// Authorize returns nil when the actor may perform permission on res, and a
// *problem.Error otherwise:
//
//	PERMISSION_DENIED  the actor lacks the permission, the delegation is
//	                   suspended/expired, or the owner is inactive
//	RATE_LIMITED       the delegation exceeded its per-minute budget
//	VALIDATION_FAILED  the permission string or res.Name is malformed
//
// Human and service actors are checked against their role. A delegation is
// checked against the owner's current role intersected with its policy (the
// action allowlist and the node scope), and consumes its rate limit. The plugin
// capability check is separate (ARCH §10.3).
func (z *Authorizer) Authorize(ctx context.Context, a actor.Actor, permission string, res Resource) error {
	perm, err := ParsePermission(permission)
	if err != nil {
		return err
	}
	if err := checkResource(perm, res); err != nil {
		return err
	}
	switch a.Kind {
	case actor.System:
		// Host components act on their own authority (e.g. the reconciler).
		return nil
	case actor.Human:
		return z.authorizeHuman(ctx, a, perm)
	case actor.AIAgent:
		return z.authorizeDelegation(ctx, a, perm, res)
	case actor.Service:
		return z.authorizeService(ctx, a, perm, res)
	default:
		return deny("unknown actor kind")
	}
}

// IsHumanOnly reports whether a permission is reserved for people (ADR-0004
// D6). A permission that does not parse counts as reserved (fail closed).
func IsHumanOnly(permission string) bool {
	p, err := ParsePermission(permission)
	return err != nil || isHumanOnly(p)
}

// AuthorizeSession checks the AI actor of a native agent session: the current
// role of its owner, minus every human-only permission. The owner is a user or
// a service account; anything else is refused (fail closed).
func (z *Authorizer) AuthorizeSession(ctx context.Context, ownerID, permission string, res Resource) error {
	return z.AuthorizeSessionActor(ctx, "", ownerID, permission, res)
}

// AuthorizeSessionActor 使用真实会话所有者类型校验主体；未知类型直接拒绝。
// 重载操作没有私有类型字段时，仅用合法资源 ID 选择主体表并重查当前权限。
func (z *Authorizer) AuthorizeSessionActor(ctx context.Context, ownerKind actor.Kind, ownerID, permission string, res Resource) error {
	perm, err := ParsePermission(permission)
	if err != nil {
		return err
	}
	if err := checkResource(perm, res); err != nil {
		return err
	}
	if isHumanOnly(perm) {
		return deny("human-only permission")
	}
	if ownerID == "" {
		return deny("agent session owner is empty")
	}
	// ======================== 重载时恢复主体分类 ========================
	// ID 只选择查询入口，不携带权限；显式类型不能与真实资源 ID 不一致。
	if ownerKind == "" {
		switch {
		case ids.Valid(ownerID, ids.User):
			ownerKind = actor.Human
		case ids.Valid(ownerID, ids.Service):
			ownerKind = actor.Service
		}
	}
	switch ownerKind {
	case actor.Human:
		if !ids.Valid(ownerID, ids.User) {
			return deny("agent session human owner has invalid user id")
		}
		return z.authorizeHuman(ctx, actor.Actor{Kind: actor.Human, ID: ownerID}, perm)
	case actor.Service:
		if !ids.Valid(ownerID, ids.Service) {
			return deny("agent session service owner has invalid service id")
		}
		return z.authorizeService(ctx, actor.Actor{Kind: actor.Service, ID: ownerID}, perm, res)
	}
	return deny("agent session owner is not a user or service account")
}

// checkResource refuses a resource name that disagrees with the permission.
func checkResource(perm Permission, res Resource) error {
	if res.Name != "" && res.Name != perm.Resource() {
		return problem.Validation(problem.Violation{
			Pointer: "/permission", Code: "mismatch",
			Message: "The resource does not match the permission's resource.",
		})
	}
	return nil
}

func (z *Authorizer) authorizeHuman(ctx context.Context, a actor.Actor, perm Permission) error {
	if a.ID == "" {
		return deny("empty actor id")
	}
	role, disabled, err := z.principals.PrincipalRole(ctx, a.ID)
	if err != nil {
		return z.fail(ctx, "load principal", err)
	}
	return checkHumanRole(role, disabled, perm)
}

func checkHumanRole(role string, disabled bool, perm Permission) error {
	if disabled {
		return deny("disabled user")
	}
	if !RoleAllows(Role(role), perm) {
		return deny("role does not grant permission")
	}
	return nil
}

func (z *Authorizer) authorizeDelegation(ctx context.Context, a actor.Actor, perm Permission, res Resource) error {
	// Hard rule (ADR-0004 D6): a delegation never approves and never manages
	// principals, whichever role its owner has.
	if isHumanOnly(perm) {
		return deny("human-only permission")
	}
	d, err := z.Delegation(ctx, a.ID)
	if err != nil {
		if problem.HasCode(err, problem.NotFound) {
			return deny("delegation does not exist")
		}
		return err
	}
	if a.OnBehalfOf != "" && a.OnBehalfOf != d.OwnerID {
		return deny("on_behalf_of does not match the delegation owner")
	}
	now := z.clock.Now().UTC()
	switch d.StatusAt(now) {
	case StatusSuspended:
		return problem.New(problem.PermissionDenied, "The delegation is suspended.")
	case StatusExpired:
		return problem.New(problem.PermissionDenied, "The delegation has expired.")
	}
	if ok, wait := z.limiter.Allow(d.ID, int(d.Policy.RequestsPerMinute)); !ok {
		sec := int((wait + time.Second - 1) / time.Second)
		if sec < 1 {
			sec = 1
		}
		return &problem.Error{
			Code:          problem.RateLimited,
			Detail:        "The delegation exceeded its rate limit.",
			RetryAfterSec: sec,
		}
	}
	if !d.Policy.AllowsNode(res.NodeID) {
		return deny("node outside the delegation policy")
	}
	// The policy's action allowlist (ADR-0004 D6). A check that names no action
	// cannot be matched against it, so it is refused rather than let through.
	if len(d.Policy.Actions) > 0 && (res.Action == "" || !d.Policy.AllowsAction(res.Action)) {
		return deny("action outside the delegation policy")
	}
	role, disabled, err := z.principals.PrincipalRole(ctx, d.OwnerID)
	if err != nil {
		return z.fail(ctx, "load delegation owner", err)
	}
	if disabled {
		return deny("delegation owner is disabled")
	}
	if !RoleAllows(Role(role), perm) {
		return deny("owner's role does not grant permission")
	}
	return nil
}

func (z *Authorizer) authorizeService(ctx context.Context, a actor.Actor, perm Permission, res Resource) error {
	if isHumanOnly(perm) {
		return deny("human-only permission")
	}
	sa, err := z.ServiceAccount(ctx, a.ID)
	if err != nil {
		if problem.HasCode(err, problem.NotFound) {
			return deny("service account does not exist")
		}
		return err
	}
	if sa.Disabled {
		return deny("service account is disabled")
	}
	if !RoleAllows(sa.Role, perm) {
		return deny("role does not grant permission")
	}
	if sa.Scope != nil {
		if !sa.Scope.Allows(z.clock.Now(), res) {
			return deny("service scope does not grant target")
		}
		if err := z.authorizeHuman(ctx, actor.Actor{Kind: actor.Human, ID: sa.CreatedBy}, perm); err != nil {
			return err
		}
	}
	return nil
}

// CanApprove reports whether the actor may decide an approval. Only a person
// using a browser session can (ADR-0004 D6); a delegation or service-account
// token never can, no matter which role it carries.
func (z *Authorizer) CanApprove(a actor.Actor) bool { return a.IsHumanSession() }

// CanManagePrincipals reports whether the actor may create users or delegations.
// Like approvals, this is reserved for human sessions.
func (z *Authorizer) CanManagePrincipals(a actor.Actor) bool { return a.IsHumanSession() }

// fail logs an internal failure and denies the request. The response never
// contains the cause.
func (z *Authorizer) fail(ctx context.Context, what string, err error) error {
	z.log.ErrorContext(ctx, "authorization dependency failed", "stage", what, "error", err)
	return deny("authorization unavailable")
}

func deny(reason string) error {
	return &problem.Error{
		Code:   problem.PermissionDenied,
		Detail: "You do not have permission to perform this action.",
		Cause:  errors.New("authz: " + reason),
	}
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

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
