// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// Bearer token prefixes. A recognisable prefix lets secret scanners and log
// redaction rules spot a leaked token (openapi.yaml securitySchemes).
const (
	DelegationTokenPrefix = "qwq_dlg_"
	ServiceTokenPrefix    = "qwq_sa_"
	// tokenPrefixLen is how many characters of a token are stored for display
	// (Delegation.token_prefix, maxLength 16 in the public schema).
	tokenPrefixLen = 16
)

// DefaultDelegationTTL is the lifetime of a delegation when the request omits
// ttl_seconds (openapi: 30 days).
const DefaultDelegationTTL = 30 * 24 * time.Hour

// Delegation TTL bounds from the public schema.
const (
	MinDelegationTTL = 300 * time.Second
	MaxDelegationTTL = 90 * 24 * time.Hour
)

// Risk is a RiskLevel of the public API. RiskNone is only meaningful for the
// delegation policy (auto_approve_max_risk: none).
type Risk string

// Risk levels (ADR-0004 D6).
const (
	RiskNone   Risk = "none"
	RiskLow    Risk = "low"
	RiskMedium Risk = "medium"
	RiskHigh   Risk = "high"
)

// Valid reports whether r is a public RiskLevel.
func (r Risk) Valid() bool {
	return r == RiskLow || r == RiskMedium || r == RiskHigh
}

// riskRank orders risks; unknown and unset values rank highest so that a
// corrupt policy cannot auto-approve anything.
func riskRank(r Risk) int {
	switch r {
	case RiskNone:
		return 0
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	}
	return 4
}

// Status is the lifecycle state of a delegation. Revoked delegations are
// deleted, so only these three exist (openapi Delegation.status).
type Status string

// Delegation states.
const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusExpired   Status = "expired"
)

// Valid reports whether s is a settable status.
func (s Status) Valid() bool { return s == StatusActive || s == StatusSuspended }

// Policy is the DelegationPolicy of the public API: an upper bound on what the
// token may do. It is always intersected with the owner's RBAC and with the
// plugin capabilities.
type Policy struct {
	// Actions are allowed action ID patterns; "*" matches one "/"-separated
	// segment. Absent means "every action the owner may run".
	Actions []string `json:"actions,omitempty"`
	// NodeIDs are the allowed nodes. Absent means "every node the owner may
	// access".
	NodeIDs []string `json:"node_ids,omitempty"`
	// AutoApproveMaxRisk is "none" or "low"; medium and high always need
	// approval.
	AutoApproveMaxRisk string `json:"auto_approve_max_risk"`
	// OnApprovalRequired is "queue" (create AWAITING_APPROVAL) or "fail"
	// (return APPROVAL_REQUIRED).
	OnApprovalRequired string `json:"on_approval_required"`
	// RequestsPerMinute is the token's rate limit.
	RequestsPerMinute int32 `json:"requests_per_minute"`
}

// DefaultPolicy returns the documented defaults: low auto-approval, queue,
// 60 requests per minute.
func DefaultPolicy() Policy {
	return Policy{AutoApproveMaxRisk: string(RiskLow), OnApprovalRequired: "queue", RequestsPerMinute: 60}
}

// Normalized fills the defaults into a copy of p.
func (p Policy) Normalized() Policy {
	if p.AutoApproveMaxRisk == "" {
		p.AutoApproveMaxRisk = string(RiskLow)
	}
	if p.OnApprovalRequired == "" {
		p.OnApprovalRequired = "queue"
	}
	if p.RequestsPerMinute == 0 {
		p.RequestsPerMinute = 60
	}
	return p
}

var (
	actionPatternRe = regexp.MustCompile(`^[a-z0-9.*_/-]+$`)
	nodeIDRe        = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
)

// Validate checks the policy against the public schema. It returns
// VALIDATION_FAILED with field violations.
func (p Policy) Validate() error {
	p = p.Normalized()
	var vs []problem.Violation
	if len(p.Actions) > 256 {
		vs = append(vs, problem.Violation{Pointer: "/policy/actions", Code: "too_many", Message: "At most 256 action patterns are allowed."})
	}
	for _, a := range p.Actions {
		if len(a) == 0 || len(a) > 200 || !actionPatternRe.MatchString(a) {
			vs = append(vs, problem.Violation{Pointer: "/policy/actions", Code: "invalid", Message: "An action pattern may contain lower-case letters, digits, '.', '*', '_', '/' and '-'."})
			break
		}
	}
	if len(p.NodeIDs) > 1000 {
		vs = append(vs, problem.Violation{Pointer: "/policy/node_ids", Code: "too_many", Message: "At most 1000 nodes are allowed."})
	}
	for _, n := range p.NodeIDs {
		if len(n) > 64 || !nodeIDRe.MatchString(n) {
			vs = append(vs, problem.Violation{Pointer: "/policy/node_ids", Code: "invalid", Message: "Node IDs are lower-case letters, digits and '-'."})
			break
		}
	}
	switch p.AutoApproveMaxRisk {
	case string(RiskNone), string(RiskLow):
	default:
		vs = append(vs, problem.Violation{Pointer: "/policy/auto_approve_max_risk", Code: "invalid", Message: "The value must be none or low."})
	}
	switch p.OnApprovalRequired {
	case "queue", "fail":
	default:
		vs = append(vs, problem.Violation{Pointer: "/policy/on_approval_required", Code: "invalid", Message: "The value must be queue or fail."})
	}
	if p.RequestsPerMinute < 1 || p.RequestsPerMinute > 600 {
		vs = append(vs, problem.Violation{Pointer: "/policy/requests_per_minute", Code: "out_of_range", Message: "The rate limit must be between 1 and 600 requests per minute."})
	}
	if len(vs) > 0 {
		return problem.Validation(vs...)
	}
	return nil
}

// AllowsNode reports whether the policy permits work on a node. An empty node
// ID means a host-wide resource and is always allowed.
func (p Policy) AllowsNode(nodeID string) bool {
	if nodeID == "" || len(p.NodeIDs) == 0 {
		return true
	}
	for _, n := range p.NodeIDs {
		if n == nodeID {
			return true
		}
	}
	return false
}

// AllowsAction reports whether the policy permits an action ID. An empty action
// list allows every action the owner may run; otherwise each pattern must match
// the action, where "*" matches one "/"-separated segment.
func (p Policy) AllowsAction(actionID string) bool {
	if len(p.Actions) == 0 {
		return true
	}
	for _, pat := range p.Actions {
		if matchActionPattern(pat, actionID) {
			return true
		}
	}
	return false
}

func matchActionPattern(pattern, action string) bool {
	ps := strings.Split(pattern, "/")
	as := strings.Split(action, "/")
	if len(ps) != len(as) {
		return false
	}
	for i := range ps {
		if ps[i] != "*" && ps[i] != as[i] {
			return false
		}
	}
	return true
}

// Covers reports whether p is at least as permissive as q; when it is not, the
// difference is returned as a VALIDATION_FAILED error. It implements the
// "a policy can only be narrowed or replaced" rule of
// DelegationUpdateRequest.
func (p Policy) Covers(q Policy) error {
	p, q = p.Normalized(), q.Normalized()
	var vs []problem.Violation
	if len(q.NodeIDs) > 0 {
		for _, n := range q.NodeIDs {
			if !p.AllowsNode(n) {
				vs = append(vs, problem.Violation{Pointer: "/policy/node_ids", Code: "widened", Message: "A policy can only be narrowed."})
				break
			}
		}
	}
	if len(p.Actions) > 0 {
		if len(q.Actions) == 0 {
			vs = append(vs, problem.Violation{Pointer: "/policy/actions", Code: "widened", Message: "A policy can only be narrowed."})
		} else {
			for _, a := range q.Actions {
				covered := false
				for _, allowed := range p.Actions {
					if matchActionPattern(allowed, a) || allowed == a {
						covered = true
						break
					}
				}
				if !covered {
					vs = append(vs, problem.Violation{Pointer: "/policy/actions", Code: "widened", Message: "A policy can only be narrowed."})
					break
				}
			}
		}
	}
	if riskRank(Risk(q.AutoApproveMaxRisk)) > riskRank(Risk(p.AutoApproveMaxRisk)) {
		vs = append(vs, problem.Violation{Pointer: "/policy/auto_approve_max_risk", Code: "widened", Message: "The auto-approval risk can only be lowered."})
	}
	if q.RequestsPerMinute > p.RequestsPerMinute {
		vs = append(vs, problem.Violation{Pointer: "/policy/requests_per_minute", Code: "widened", Message: "The rate limit can only be lowered."})
	}
	if p.OnApprovalRequired == "fail" && q.OnApprovalRequired == "queue" {
		vs = append(vs, problem.Violation{Pointer: "/policy/on_approval_required", Code: "widened", Message: "queue is weaker than fail."})
	}
	if len(vs) > 0 {
		return problem.Validation(vs...)
	}
	return nil
}

// Delegation is a delegation token as stored. The token itself is never part
// of it: only the SHA-256 and a short prefix exist.
type Delegation struct {
	ID          string
	Label       string
	OwnerID     string
	Policy      Policy
	Status      Status
	TokenPrefix string
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ExpiresAt   time.Time
	LastUsedAt  time.Time
	Revision    int64
}

// Subject is the resource subject used in events.
func (d Delegation) Subject() string { return "delegations/" + d.ID }

// StatusAt returns the effective status, taking the expiry into account. The
// stored status is not rewritten on read; a lazily stored "expired" would turn
// a read into a write.
func (d Delegation) StatusAt(now time.Time) Status {
	if d.Status == StatusSuspended {
		return StatusSuspended
	}
	if !now.Before(d.ExpiresAt) {
		return StatusExpired
	}
	return StatusActive
}

// Created is a freshly issued delegation plus its token, shown only once.
type Created struct {
	Delegation
	Token string
}

const delegationColumns = `delegation_id, owner_id, label, token_prefix, policy, status, created_by,
	created_at, updated_at, expires_at, last_used_at, revision`

func scanDelegation(row scanner) (Delegation, error) {
	var d Delegation
	var policy, status, created, updated, expires, used string
	if err := row.Scan(&d.ID, &d.OwnerID, &d.Label, &d.TokenPrefix, &policy, &status, &d.CreatedBy,
		&created, &updated, &expires, &used, &d.Revision); err != nil {
		return Delegation{}, err
	}
	if err := json.Unmarshal([]byte(policy), &d.Policy); err != nil {
		return Delegation{}, fmt.Errorf("authz: parse delegation policy: %w", err)
	}
	d.Policy = d.Policy.Normalized()
	d.Status = Status(status)
	var err error
	if d.CreatedAt, err = parseTime(created); err != nil {
		return Delegation{}, err
	}
	if d.UpdatedAt, err = parseTime(updated); err != nil {
		return Delegation{}, err
	}
	if d.ExpiresAt, err = parseTime(expires); err != nil {
		return Delegation{}, err
	}
	if d.LastUsedAt, err = parseTime(used); err != nil {
		return Delegation{}, err
	}
	return d, nil
}

// CreateDelegationInput issues a token for the calling human.
type CreateDelegationInput struct {
	// Actor must be a human session (ADR-0004 D6); the owner is the actor.
	Actor  actor.Actor
	Label  string
	Policy Policy
	// TTL defaults to DefaultDelegationTTL and is clamped to the public bounds.
	TTL time.Duration
}

// CreateDelegation mints a delegation token inside the caller's transaction and
// publishes the resource.changed event. The caller (internal/operations) owns
// the operation row and the audit record.
func (z *Authorizer) CreateDelegation(ctx context.Context, tx *storage.Tx, in CreateDelegationInput) (Created, error) {
	if !in.Actor.IsHumanSession() {
		return Created{}, problem.New(problem.PermissionDenied, "Only a human session may create a delegation.")
	}
	label, err := validLabel(in.Label)
	if err != nil {
		return Created{}, err
	}
	policy := in.Policy.Normalized()
	if err := policy.Validate(); err != nil {
		return Created{}, err
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = DefaultDelegationTTL
	}
	if ttl < MinDelegationTTL {
		ttl = MinDelegationTTL
	}
	if ttl > MaxDelegationTTL {
		ttl = MaxDelegationTTL
	}
	token, digest, prefix, err := mintToken(DelegationTokenPrefix)
	if err != nil {
		return Created{}, err
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return Created{}, err
	}
	now := tx.Now()
	id := tx.NewID(ids.Delegation)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO delegations (delegation_id, owner_id, label, token_hash, token_prefix, policy, status,
			created_by, created_at, updated_at, expires_at, last_used_at, revision)
		 VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, '', 0)`,
		id, in.Actor.ID, label, digest, prefix, string(raw), in.Actor.ID,
		formatTime(now), formatTime(now), formatTime(now.Add(ttl))); err != nil {
		return Created{}, fmt.Errorf("authz: insert delegation: %w", err)
	}
	seq, err := tx.Changed(ctx, storage.Change{Subject: "delegations/" + id, Kind: storage.Created})
	if err != nil {
		return Created{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE delegations SET revision = ? WHERE delegation_id = ?`, seq, id); err != nil {
		return Created{}, fmt.Errorf("authz: set revision: %w", err)
	}
	d, err := z.delegationTx(ctx, tx, id)
	if err != nil {
		return Created{}, err
	}
	return Created{Delegation: d, Token: token}, nil
}

// UpdateDelegationInput suspends, resumes or narrows a delegation.
type UpdateDelegationInput struct {
	Actor            actor.Actor
	DelegationID     string
	ExpectedRevision int64
	Status           *Status
	Policy           *Policy
}

// UpdateDelegation applies a patch in the caller's transaction. Suspension takes
// effect for new calls immediately; a running operation is not canceled.
func (z *Authorizer) UpdateDelegation(ctx context.Context, tx *storage.Tx, in UpdateDelegationInput) (Delegation, error) {
	if !in.Actor.IsHumanSession() {
		return Delegation{}, problem.New(problem.PermissionDenied, "Only a human session may manage delegations.")
	}
	if in.Status == nil && in.Policy == nil {
		return Delegation{}, problem.Validation(problem.Violation{
			Pointer: "/", Code: "empty", Message: "At least one of status or policy is required.",
		})
	}
	cur, err := z.delegationTx(ctx, tx, in.DelegationID)
	if err != nil {
		return Delegation{}, err
	}
	if err := z.mayManage(ctx, in.Actor, cur); err != nil {
		return Delegation{}, err
	}
	if err := checkRevision(in.ExpectedRevision, cur.Revision); err != nil {
		return Delegation{}, err
	}
	status, policy := cur.Status, cur.Policy
	if in.Status != nil {
		if !in.Status.Valid() {
			return Delegation{}, problem.Validation(problem.Violation{
				Pointer: "/status", Code: "invalid", Message: "The status must be active or suspended.",
			})
		}
		status = *in.Status
	}
	if in.Policy != nil {
		next := in.Policy.Normalized()
		if err := next.Validate(); err != nil {
			return Delegation{}, err
		}
		if err := cur.Policy.Covers(next); err != nil {
			return Delegation{}, err
		}
		policy = next
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return Delegation{}, err
	}
	now := tx.Now()
	if _, err := tx.ExecContext(ctx,
		`UPDATE delegations SET status = ?, policy = ?, updated_at = ? WHERE delegation_id = ?`,
		string(status), string(raw), formatTime(now), cur.ID); err != nil {
		return Delegation{}, fmt.Errorf("authz: update delegation: %w", err)
	}
	seq, err := tx.Changed(ctx, storage.Change{
		Subject: cur.Subject(), Kind: storage.Updated, Pointers: delegationPointers(cur, status, policy),
	})
	if err != nil {
		return Delegation{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE delegations SET revision = ? WHERE delegation_id = ?`, seq, cur.ID); err != nil {
		return Delegation{}, fmt.Errorf("authz: set revision: %w", err)
	}
	return z.delegationTx(ctx, tx, cur.ID)
}

func delegationPointers(old Delegation, status Status, policy Policy) []string {
	var ps []string
	if old.Status != status {
		ps = append(ps, "/status")
	}
	if !policyEqual(old.Policy, policy) {
		ps = append(ps, "/policy")
	}
	return ps
}

func policyEqual(a, b Policy) bool {
	ja, _ := json.Marshal(a.Normalized())
	jb, _ := json.Marshal(b.Normalized())
	return string(ja) == string(jb)
}

// RevokeDelegationInput deletes a delegation; the token stops working at once.
type RevokeDelegationInput struct {
	Actor            actor.Actor
	DelegationID     string
	ExpectedRevision int64
}

// RevokeDelegation deletes the row in the caller's transaction.
func (z *Authorizer) RevokeDelegation(ctx context.Context, tx *storage.Tx, in RevokeDelegationInput) error {
	if !in.Actor.IsHumanSession() {
		return problem.New(problem.PermissionDenied, "Only a human session may revoke a delegation.")
	}
	cur, err := z.delegationTx(ctx, tx, in.DelegationID)
	if err != nil {
		return err
	}
	if err := z.mayManage(ctx, in.Actor, cur); err != nil {
		return err
	}
	if err := checkRevision(in.ExpectedRevision, cur.Revision); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM delegations WHERE delegation_id = ?`, cur.ID); err != nil {
		return fmt.Errorf("authz: delete delegation: %w", err)
	}
	_, err = tx.Changed(ctx, storage.Change{Subject: cur.Subject(), Kind: storage.Deleted})
	return err
}

// RevokeDelegationsOf deletes every delegation of a user in its own
// transaction. `qwq recover` calls it so a stolen token cannot outlive an
// administrator reset.
func (z *Authorizer) RevokeDelegationsOf(ctx context.Context, ownerID string) (int, error) {
	n := 0
	err := z.db.Update(ctx, func(tx *storage.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT delegation_id, revision FROM delegations WHERE owner_id = ?`, ownerID)
		if err != nil {
			return fmt.Errorf("authz: list delegations: %w", err)
		}
		var ids []string
		for rows.Next() {
			var id string
			var rev int64
			if err := rows.Scan(&id, &rev); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, `DELETE FROM delegations WHERE delegation_id = ?`, id); err != nil {
				return fmt.Errorf("authz: delete delegation: %w", err)
			}
			if _, err := tx.Changed(ctx, storage.Change{Subject: "delegations/" + id, Kind: storage.Deleted}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ListDelegationsInput selects a page of delegations.
type ListDelegationsInput struct {
	// OwnerID filters by owner; empty lists every owner (administrators).
	OwnerID string
	After   string
	Limit   int
}

// ListDelegations returns a page ordered by delegation ID.
func (z *Authorizer) ListDelegations(ctx context.Context, in ListDelegationsInput) ([]Delegation, error) {
	if in.Limit <= 0 || in.Limit > 200 {
		in.Limit = 200
	}
	q := `SELECT ` + delegationColumns + ` FROM delegations WHERE 1 = 1`
	args := []any{}
	if in.OwnerID != "" {
		q += ` AND owner_id = ?`
		args = append(args, in.OwnerID)
	}
	if in.After != "" {
		q += ` AND delegation_id > ?`
		args = append(args, in.After)
	}
	q += ` ORDER BY delegation_id LIMIT ?`
	args = append(args, in.Limit)
	rows, err := z.db.Reader().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("authz: list delegations: %w", err)
	}
	defer rows.Close()
	var out []Delegation
	for rows.Next() {
		d, err := scanDelegation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Delegation returns one delegation by ID.
func (z *Authorizer) Delegation(ctx context.Context, id string) (Delegation, error) {
	d, err := scanDelegation(z.db.Reader().QueryRowContext(ctx,
		`SELECT `+delegationColumns+` FROM delegations WHERE delegation_id = ?`, id))
	if isNoRows(err) {
		return Delegation{}, problem.New(problem.NotFound, "The delegation does not exist.")
	}
	if err != nil {
		return Delegation{}, err
	}
	return d, nil
}

// DelegationTx 在调用方事务读取宿主归属事实，删除后的幂等回放据此保留边界。
func (z *Authorizer) DelegationTx(ctx context.Context, tx *storage.Tx, id string) (Delegation, error) {
	return z.delegationTx(ctx, tx, id)
}

func (z *Authorizer) delegationTx(ctx context.Context, tx *storage.Tx, id string) (Delegation, error) {
	d, err := scanDelegation(tx.QueryRowContext(ctx,
		`SELECT `+delegationColumns+` FROM delegations WHERE delegation_id = ?`, id))
	if isNoRows(err) {
		return Delegation{}, problem.New(problem.NotFound, "The delegation does not exist.")
	}
	if err != nil {
		return Delegation{}, err
	}
	return d, nil
}

// mayManage reports whether the actor may patch or revoke d. The owner can
// always do it; an administrator can do it for any user.
func (z *Authorizer) mayManage(ctx context.Context, a actor.Actor, d Delegation) error {
	return mayManageDelegationOwner(a, d.OwnerID, func() (string, bool, error) {
		return z.principals.PrincipalRole(ctx, a.ID)
	})
}

// ======================== 领域写入与回放复用同一 owner/admin 规则 ========================

func mayManageDelegationOwner(a actor.Actor, ownerID string, roleLookup func() (string, bool, error)) error {
	if ownerID != "" && a.ID == ownerID {
		return nil
	}
	role, disabled, err := roleLookup()
	if err != nil || disabled || Role(role) != RoleAdmin {
		return problem.New(problem.PermissionDenied, "Only the owner or an administrator may manage this delegation.")
	}
	return nil
}

// AuthenticateBearer resolves a delegation or service-account bearer token to
// its actor. A suspended, expired or orphaned token is refused.
func (z *Authorizer) AuthenticateBearer(ctx context.Context, token string) (actor.Actor, error) {
	switch {
	case strings.HasPrefix(token, DelegationTokenPrefix):
		return z.authenticateDelegation(ctx, token)
	case strings.HasPrefix(token, ServiceTokenPrefix):
		return z.authenticateService(ctx, token)
	}
	return actor.Actor{}, unauthenticated()
}

func (z *Authorizer) authenticateDelegation(ctx context.Context, token string) (actor.Actor, error) {
	d, err := scanDelegation(z.db.Reader().QueryRowContext(ctx,
		`SELECT `+delegationColumns+` FROM delegations WHERE token_hash = ?`, hashToken(token)))
	if isNoRows(err) {
		return actor.Actor{}, unauthenticated()
	}
	if err != nil {
		return actor.Actor{}, err
	}
	now := z.clock.Now().UTC()
	switch d.StatusAt(now) {
	case StatusSuspended:
		return actor.Actor{}, problem.New(problem.PermissionDenied, "The delegation is suspended.")
	case StatusExpired:
		return actor.Actor{}, problem.New(problem.PermissionDenied, "The delegation has expired.")
	}
	// Recompute the owner's authority on every request: a disabled or deleted
	// owner invalidates the token immediately (ADR-0004 D4).
	if _, disabled, err := z.principals.PrincipalRole(ctx, d.OwnerID); err != nil || disabled {
		return actor.Actor{}, problem.New(problem.PermissionDenied, "The delegation owner is not active.")
	}
	z.touchDelegation(ctx, d, now)
	return actor.Actor{Kind: actor.AIAgent, ID: d.ID, OnBehalfOf: d.OwnerID}, nil
}

// touchDelegation records last_used_at at most once per TouchInterval. The
// value is status information, not a resource revision, so it deliberately does
// not publish an event or bump the revision.
func (z *Authorizer) touchDelegation(ctx context.Context, d Delegation, now time.Time) {
	if now.Sub(d.LastUsedAt) < z.touchInterval {
		return
	}
	err := z.db.Update(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE delegations SET last_used_at = ? WHERE delegation_id = ?`,
			formatTime(now), d.ID)
		return err
	})
	if err != nil {
		z.log.WarnContext(ctx, "delegation touch failed", "delegation_id", d.ID, "error", err)
	}
}

// mintToken returns prefix + base64url(32 random bytes), its SHA-256 and the
// stored display prefix.
func mintToken(prefix string) (token string, digest []byte, display string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, "", fmt.Errorf("authz: crypto/rand: %w", err)
	}
	token = prefix + base64.RawURLEncoding.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(token))
	display = token
	if len(display) > tokenPrefixLen {
		display = display[:tokenPrefixLen]
	}
	return token, sum[:], display, nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// validLabel trims and validates a delegation label.
func validLabel(s string) (string, error) {
	l := strings.TrimSpace(s)
	if l == "" || utf8.RuneCountInString(l) > 64 {
		return "", problem.Validation(problem.Violation{
			Pointer: "/label", Code: "invalid", Message: "The label must be 1 to 64 characters.",
		})
	}
	for _, r := range l {
		if unicode.IsControl(r) {
			return "", problem.Validation(problem.Violation{
				Pointer: "/label", Code: "invalid", Message: "The label must not contain control characters.",
			})
		}
	}
	return l, nil
}

// checkRevision enforces expected_revision (ADR-0004 D2).
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

// unauthenticated is the single answer to a bad credential.
func unauthenticated() error {
	return problem.New(problem.Unauthenticated, "Authentication required.")
}
