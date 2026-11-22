// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// This file is the only place where two domains meet (ADR-0008 §1). Each
// adapter is deliberately small and has no policy of its own: it translates
// types and delegates the decision to the owning package.

// --- gateway.Authenticator -------------------------------------------------

type authenticator struct {
	identity *identity.Service
	authz    *authz.Authorizer
}

func (a authenticator) Authenticate(ctx context.Context, c gateway.Credentials) (gateway.Principal, error) {
	if c.Session != "" {
		act, sess, err := a.identity.AuthenticateSession(ctx, c.Session)
		if err != nil {
			return gateway.Principal{}, err
		}
		return gateway.Principal{Actor: act, Scheme: gateway.SchemeSession, CSRF: sess.CSRF}, nil
	}
	if c.Bearer != "" {
		act, err := a.authz.AuthenticateBearer(ctx, c.Bearer)
		if err != nil {
			return gateway.Principal{}, err
		}
		scheme := gateway.SchemeDelegation
		if act.Kind == actor.Service {
			scheme = gateway.SchemeService
		}
		return gateway.Principal{Actor: act, Scheme: scheme}, nil
	}
	return gateway.Principal{}, gateway.ErrNoCredentials
}

// --- events.Visibility -----------------------------------------------------

// subjectHead returns the resource collection of an event subject
// ("operations/op_1" -> "operations").
func subjectHead(subject string) string {
	head, _, _ := strings.Cut(subject, "/")
	return head
}

// readPermission maps an event subject to the read permission a caller needs.
// Only host-owned subjects are mapped; unknown subjects are denied. An empty
// permission is the owner-scoped family without a role gate (agent sessions):
// every signed-in principal may read its own, and the role never widens it.
func readPermission(subject string) (authz.Permission, bool) {
	switch subjectHead(subject) {
	case "users":
		return "host.users:read", true
	case "delegations":
		return "host.delegations:read", true
	case "service_accounts":
		return "host.service_accounts:read", true
	case "audit":
		return "host.audit:read", true
	case "operations":
		return "host.operations:read", true
	case "plans":
		return "host.plans:read", true
	case "approvals":
		return "host.approvals:read", true
	case "nodes":
		return "host.nodes:read", true
	case "plugins":
		return "host.plugins:read", true
	case "agent_sessions":
		// Agent sessions are the caller's own chat state; the REST routes
		// deliberately add no RBAC permission on top (internal/api), so the
		// stream must not either (gap 6).
		return "", true
	}
	return "", false
}

// ownerCacheTTL bounds how long a resource owner is cached. Ownership never
// changes, so the TTL only bounds memory, not staleness.
const ownerCacheTTL = time.Minute

type ownerEntry struct {
	owner   actor.Actor
	expires time.Time
}

// visibility decides which journal events a stream subscriber may receive. A
// role permission is necessary but not sufficient: the per-resource rule
// (owns) mirrors the REST read check so the stream never shows more than GET.
type visibility struct {
	identity *identity.Service
	authz    *authz.Authorizer
	clk      clock.Clock

	mu     sync.Mutex
	owners map[string]ownerEntry // event subject -> owner
	// sessionOwner resolves the owner of an agent session for the stream's
	// per-event check; nil (no agent session backend) denies the family. It is
	// installed once at controller assembly, guarded by mu.
	sessionOwner func(ctx context.Context, id string) (actor.Actor, bool)
}

func newVisibility(id *identity.Service, az *authz.Authorizer, clk clock.Clock) *visibility {
	if clk == nil {
		clk = clock.System{}
	}
	return &visibility{identity: id, authz: az, clk: clk, owners: make(map[string]ownerEntry)}
}

// setSessionOwner installs the agent session owner lookup.
func (v *visibility) setSessionOwner(fn func(ctx context.Context, id string) (actor.Actor, bool)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sessionOwner = fn
}

// Allowed implements events.Visibility. It returns false on any lookup error:
// a stream must not leak because the database was briefly unavailable.
func (v *visibility) Allowed(a actor.Actor, e events.Event) bool {
	perm, ok := readPermission(e.Subject)
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	switch a.Kind {
	case actor.System:
		return true
	case actor.Human:
		role, disabled, err := v.identity.PrincipalRole(ctx, a.ID)
		if err != nil || disabled {
			return false
		}
		if perm == "" {
			// Owner-scoped without a role gate: the role never widens the rule,
			// an administrator included.
			return v.owns(ctx, a, "", e)
		}
		return authz.RoleAllows(authz.Role(role), perm) && v.owns(ctx, a, authz.Role(role), e)
	case actor.AIAgent:
		d, err := v.authz.Delegation(ctx, a.ID)
		if err != nil || d.StatusAt(v.clk.Now()) != authz.StatusActive {
			return false
		}
		if e.NodeID != "" && !d.Policy.AllowsNode(e.NodeID) {
			return false
		}
		if perm == "" {
			return v.owns(ctx, a, "", e)
		}
		role, disabled, err := v.identity.PrincipalRole(ctx, d.OwnerID)
		if err != nil || disabled {
			return false
		}
		return authz.RoleAllows(authz.Role(role), perm) && v.owns(ctx, a, "", e)
	case actor.Service:
		sa, err := v.authz.ServiceAccount(ctx, a.ID)
		if err != nil || sa.Disabled {
			return false
		}
		// 事件订阅没有可核验的完整 action/subject 组合，不能让角色扩大精确 scope。
		if sa.Scope != nil {
			return false
		}
		if perm == "" {
			return v.owns(ctx, a, "", e)
		}
		return authz.RoleAllows(sa.Role, perm) && v.owns(ctx, a, "", e)
	default:
		return false
	}
}

// owns is the per-resource half of Allowed, kept apart from the role check so
// that new resource kinds plug in one case here. role is the caller's own
// human role; it is empty for non-human principals, which never get the
// administrator bypass.
func (v *visibility) owns(ctx context.Context, a actor.Actor, role authz.Role, e events.Event) bool {
	switch subjectHead(e.Subject) {
	case "users", "service_accounts", "audit":
		return role == authz.RoleAdmin
	case "operations", "approvals":
		return a.Kind == actor.Human || ownsOperationEvent(a, e)
	case "delegations":
		return role == authz.RoleAdmin || v.ownsDelegationEvent(ctx, a, e)
	case "agent_sessions":
		return v.ownsAgentSessionEvent(ctx, a, e)
	default:
		return true
	}
}

// ownsOperationEvent mirrors operations.canRead: a non-human principal sees
// only the operations it started.
func ownsOperationEvent(a actor.Actor, e events.Event) bool {
	if e.Type != "operation.updated" {
		return false // resource.changed carries no initiator: never pushed to non-humans
	}
	var p struct {
		Actor actor.Actor `json:"actor"`
	}
	return json.Unmarshal(e.Payload, &p) == nil &&
		p.Actor.Kind == a.Kind && p.Actor.ID == a.ID && p.Actor.OnBehalfOf == a.OnBehalfOf
}

// ownsDelegationEvent mirrors the REST owner check of delegations. A deleted
// delegation that was never cached falls back to the event's actor.
func (v *visibility) ownsDelegationEvent(ctx context.Context, a actor.Actor, e events.Event) bool {
	if a.Kind != actor.Human {
		return false
	}
	_, id, _ := strings.Cut(e.Subject, "/")
	owner, ok := v.cachedOwner(ctx, "delegations/"+id, func() (actor.Actor, bool) {
		d, err := v.authz.Delegation(ctx, id)
		if err != nil {
			return actor.Actor{}, false
		}
		return actor.Actor{Kind: actor.Human, ID: d.OwnerID}, true
	})
	if !ok {
		return e.Actor.Kind == string(actor.Human) && e.Actor.ID == a.ID
	}
	return owner.ID == a.ID
}

// ownsAgentSessionEvent mirrors the REST rule of agent sessions (gap 6): the
// events go to the session's owner alone. An administrator is no exception —
// the REST routes add no role check on sessions — and a deleted session is
// gone from the database by the time its delete event dispatches, so that one
// event names its owner through its actor. Any other subject without a live
// owner is dropped.
func (v *visibility) ownsAgentSessionEvent(ctx context.Context, a actor.Actor, e events.Event) bool {
	if a.Kind != actor.Human && a.Kind != actor.Service {
		return false
	}
	_, id, _ := strings.Cut(e.Subject, "/")
	owner, ok := v.sessionOwnerOf(ctx, id)
	if !ok {
		if !isDeleteEvent(e) {
			return false
		}
		owner = actor.Actor{Kind: actor.Kind(e.Actor.Kind), ID: e.Actor.ID}
	}
	return owner.Kind == a.Kind && owner.ID != "" && owner.ID == a.ID
}

// isDeleteEvent reports whether e is the resource.changed of a removal.
func isDeleteEvent(e events.Event) bool {
	if e.Type != "resource.changed" {
		return false
	}
	var p struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(e.Payload, &p) == nil && p.Kind == string(storage.Deleted)
}

// sessionOwnerOf resolves an agent session's owner through the shared TTL
// cache; without an installed lookup (no agent session backend) nothing is
// known.
func (v *visibility) sessionOwnerOf(ctx context.Context, id string) (actor.Actor, bool) {
	v.mu.Lock()
	fn := v.sessionOwner
	v.mu.Unlock()
	if fn == nil {
		return actor.Actor{}, false
	}
	return v.cachedOwner(ctx, "agent_sessions/"+id, func() (actor.Actor, bool) { return fn(ctx, id) })
}

// cachedOwner resolves a subject's owner through a small TTL cache. The
// database lookup runs outside the lock so one slow query cannot stall every
// stream's dispatch.
func (v *visibility) cachedOwner(ctx context.Context, subject string, load func() (actor.Actor, bool)) (actor.Actor, bool) {
	now := v.clk.Now()
	v.mu.Lock()
	ent, hit := v.owners[subject]
	v.mu.Unlock()
	if hit && now.Before(ent.expires) {
		return ent.owner, true
	}
	owner, ok := load()
	if !ok {
		return actor.Actor{}, false
	}
	v.storeOwner(subject, owner)
	return owner, true
}

// storeOwner caches one subject's owner. The sweep on insert is bounded by
// live resources and runs on misses only.
func (v *visibility) storeOwner(subject string, owner actor.Actor) {
	now := v.clk.Now()
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, old := range v.owners {
		if !now.Before(old.expires) {
			delete(v.owners, k)
		}
	}
	v.owners[subject] = ownerEntry{owner: owner, expires: now.Add(ownerCacheTTL)}
}

// --- operations.Catalog ----------------------------------------------------

type catalogAdapter struct{ catalog *catalog.Catalog }

func (a catalogAdapter) Action(id string) (operations.Action, bool) {
	e, ok := a.catalog.Get(id)
	if !ok {
		return operations.Action{}, false
	}
	caps := operationCapabilities(e.Capabilities)
	src := operations.HostSource
	var argsSchema json.RawMessage
	if e.Source == catalog.Plugin {
		src = operations.PluginSource
		// The plugin's request schema is enforced before dispatch (ARCH §5.4).
		// Host routes validate their own bodies.
		argsSchema = e.ArgsSchema
	}
	return operations.Action{
		ArgsSchema:   argsSchema,
		ID:           e.ID,
		Summary:      e.Summary,
		Effect:       e.Effect,
		Risk:         e.DeclaredRisk,
		Mode:         e.Mode,
		Idempotent:   e.Idempotent,
		Plannable:    e.Plannable,
		Capabilities: caps,
		Undo:         e.Undo,
		UIRoute:      e.UIRoute,
		Permission:   e.Permission,
		TimeoutMS:    e.TimeoutMS,
		Source:       src,
		PluginID:     e.PluginID,
		Placement:    e.Placement,
		Operation:    e.Operation,
		APIVersion:   e.APIVersion,

		// ADR-0010 approval metadata travels with the action so the operation
		// manager can decide whether this call needs a user decision.
		Approval:            e.Approval,
		ApprovalSummary:     e.ApprovalSummary,
		ApprovalDescription: e.ApprovalDescription,

		// ADR-0016: the reachability flag the catalog clamped at load time.
		Reachability: e.Reachability,
	}, true
}

// operationCapabilities converts the catalog's capability type to the one the
// operation manager uses. The two are the same pair of strings; the packages
// are peers and do not import each other (ADR-0008 §1).
func operationCapabilities(caps []catalog.Capability) []operations.Capability {
	out := make([]operations.Capability, 0, len(caps))
	for _, c := range caps {
		out = append(out, operations.Capability{Name: c.Name, Scope: c.Scope})
	}
	return out
}

// catalogFloor adapts the capability types so the catalog and operations use
// the same effective-risk rule (ADR-0004 D6).
func catalogFloor(declared, effect string, caps []catalog.Capability) string {
	return operations.RiskFloor(declared, effect, operationCapabilities(caps))
}

// catalogReachability gives the catalog the capability-derived reachability
// rule the operation manager owns (ADR-0016), so an operation that may use a
// lockout capability is clamped when its manifest is loaded.
func catalogReachability(effect string, caps []catalog.Capability) bool {
	return operations.ForcedReachability(effect, operationCapabilities(caps))
}

// --- operations.Authorizer -------------------------------------------------

type authorizerAdapter struct{ authz *authz.Authorizer }

func (a authorizerAdapter) Authorize(ctx context.Context, act actor.Actor, action operations.Action, target operations.Target) error {
	if action.Permission == "" {
		return problem.New(problem.PermissionDenied, "The action has no permission mapping.")
	}
	perm, err := authz.ParsePermission(action.Permission)
	if err != nil {
		return err
	}
	// Defense in depth for manifests below schema 1.2 (ADR-0014): a plugin
	// operation that changes something never counts as read-only, whatever
	// permission it declares. Checking the resource's write action keeps viewers
	// and read-only delegations out.
	if action.PluginID != "" && action.Effect != "read" && manifest.ReadOnlyActions[perm.Action()] {
		if perm, err = authz.ParsePermission(perm.Resource() + ":write"); err != nil {
			return err
		}
	}
	res := authz.Resource{
		Name:    string(perm.Resource()),
		NodeID:  target.NodeID,
		Action:  action.ID,
		Subject: target.Subject,
	}
	// A native agent session has no delegation record: it acts with the RBAC
	// authority of its owner minus every human-only permission, while the
	// operation and the audit rows keep the AI actor (ADR-0010 §5). The owner is
	// session-row data, never a request field, so neither the model nor the
	// owner can widen the session.
	if operations.IsSessionActor(act) {
		return a.authz.AuthorizeSessionActor(ctx, act.OnBehalfOfKind, act.OnBehalfOf, string(perm), res)
	}
	return a.authz.Authorize(ctx, act, string(perm), res)
}

// --- operations.Policy -----------------------------------------------------

type policyAdapter struct{ authz *authz.Authorizer }

func (a policyAdapter) Limits(ctx context.Context, act actor.Actor, action operations.Action, target operations.Target) (operations.Limits, error) {
	// ADR-0010 §2.1: the mode comes from the session or delegation record,
	// never from the request. An agent session carries it on the context
	// (operations.WithPermissionMode); every other caller is safe until the
	// delegation record gets its own mode.
	limits := operations.Limits{
		MaxRisk:            operations.RiskHigh,
		AutoApproveMaxRisk: "low",
		OnApprovalRequired: "queue",
		PermissionMode:     operations.DefaultPermissionMode,
	}
	if mode, ok := operations.PermissionModeFromContext(ctx); ok {
		limits.PermissionMode = mode
	}
	// A native agent session is not a delegation: its permission mode is the
	// session row put on the context by internal/agentsession, and its owner's
	// RBAC role is checked by the authorizer. There is no delegation record to
	// read, and looking one up would deny every tool call (ADR-0010 §5).
	if act.Kind != actor.AIAgent || operations.IsSessionActor(act) {
		return limits, nil
	}
	d, err := a.authz.Delegation(ctx, act.ID)
	if err != nil {
		return operations.Limits{}, problem.New(problem.PermissionDenied, "The delegation is not active.")
	}
	if d.Policy.AutoApproveMaxRisk != "" {
		limits.AutoApproveMaxRisk = d.Policy.AutoApproveMaxRisk
	}
	if d.Policy.OnApprovalRequired != "" {
		limits.OnApprovalRequired = d.Policy.OnApprovalRequired
	}
	return limits, nil
}

// --- operations.Revisions --------------------------------------------------

type revisionsAdapter struct{}

// CurrentRevision reads the revision column of the owning table. Subjects not
// owned by the host have no revision here; host actions that use them as a
// precondition must use a host action that checks them itself.
func (revisionsAdapter) CurrentRevision(ctx context.Context, tx *storage.Tx, subject string) (string, error) {
	table, column, id, ok := revisionTarget(subject)
	if !ok {
		return "", nil
	}
	var rev int64
	err := tx.QueryRowContext(ctx, `SELECT revision FROM `+table+` WHERE `+column+` = ?`, id).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("controller: revision of %s: %w", subject, err)
	}
	return strconv.FormatInt(rev, 10), nil
}

func revisionTarget(subject string) (table, column, id string, ok bool) {
	parts := strings.SplitN(subject, "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", "", false
	}
	switch parts[0] {
	case "users":
		return "users", "user_id", parts[1], true
	case "ai_providers":
		return "ai_providers", "provider_id", parts[1], true
	case "delegations":
		return "delegations", "delegation_id", parts[1], true
	case "service_accounts":
		return "service_accounts", "service_id", parts[1], true
	case "operations":
		return "operations", "operation_id", parts[1], true
	case "plans":
		return "plans", "plan_id", parts[1], true
	case "approvals":
		return "approvals", "approval_id", parts[1], true
	}
	return "", "", "", false
}

// --- identity.Auditor ------------------------------------------------------

// NewAuditor returns the identity auditor backed by the operations audit log.
// It exists for commands such as `qwq recover` that do not build a full
// controller but must still record what they did.
func NewAuditor() identity.Auditor { return auditor{} }

type auditor struct{}

func (auditor) Audit(ctx context.Context, tx *storage.Tx, rec identity.AuditRecord) error {
	var details json.RawMessage
	if len(rec.Detail) > 0 {
		b, err := json.Marshal(rec.Detail)
		if err != nil {
			return err
		}
		details = b
	}
	return operations.Audit(ctx, tx, operations.AuditRecord{
		Actor:   rec.Actor,
		Action:  rec.Action,
		Subject: rec.Subject,
		Outcome: rec.Outcome,
		Details: details,
		At:      rec.At,
	})
}
