// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Role is a built-in role, identical to the Role enum of the public API. The
// identity package stores the same strings; keeping the constants here lets
// authz decide permissions without importing identity (ADR-0008 §1).
type Role string

// Built-in roles (ADR-0005 Q7).
const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// BuiltinRoles lists the built-in roles in descending order of authority.
func BuiltinRoles() []Role { return []Role{RoleAdmin, RoleOperator, RoleViewer} }

// Valid reports whether r is a built-in role.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	}
	return false
}

// ParseRole validates a role string.
func ParseRole(s string) (Role, error) {
	r := Role(strings.TrimSpace(s))
	switch r {
	case RoleAdmin, RoleOperator, RoleViewer:
		return r, nil
	}
	return "", problem.Validation(problem.Violation{
		Pointer: "/role", Code: "invalid",
		Message: "The role must be one of: admin, operator, viewer.",
	})
}

// roleGrant describes what a built-in role may do.
type roleGrant struct {
	// all grants every permission that is not denied.
	all bool
	// readOnly grants only read-class actions.
	readOnly bool
	// deny patterns override the grant.
	deny []Pattern
}

// roleGrants is the built-in role table:
//
//	admin     every permission (approvals additionally need a human session,
//	          which Authorize enforces separately);
//	operator  日常运维与本人委派；用户、服务账号、审计和全局模型写入由管理员管理；
//	viewer    只读动作与本人账户；不读取管理员专属敏感集合（ADR-0005）。
//
// Every role additionally manages its own account (selfServiceResources).
// Roles are not extensible in P1 (Role is x-qwq-extensible-enum); an unknown
// role grants nothing, so a corrupted row fails closed.
var roleGrants = map[Role]roleGrant{
	RoleAdmin: {all: true},
	RoleOperator: {
		all: true,
		deny: []Pattern{
			"host.users:*",
			"host.service_accounts:*",
			"host.audit:*",
			// Providers define where the whole installation sends model
			// traffic; managing them stays with the administrator (ADR-0017).
			"host.ai_providers:create",
			"host.ai_providers:update",
			"host.ai_providers:delete",
		},
	},
	RoleViewer: {
		readOnly: true,
		deny: []Pattern{
			"host.users:*",
			"host.service_accounts:*",
			"host.audit:*",
		},
	},
}

// allows reports whether the grant covers the permission.
func (g roleGrant) allows(p Permission) bool {
	for _, d := range g.deny {
		if d.Matches(p) {
			return false
		}
	}
	if g.all {
		return true
	}
	if g.readOnly {
		return isReadPermission(p)
	}
	return false
}

// RoleAllows reports whether a built-in role grants the permission, ignoring
// actor kind. Authorize applies the human-only rules on top.
func RoleAllows(role Role, perm Permission) bool {
	g, ok := roleGrants[role]
	if !ok {
		return false
	}
	if selfServiceResources[perm.Resource()] {
		return true
	}
	return g.allows(perm)
}

// UnknownRole reports whether a role string is outside the built-in set. It is
// used by callers that read a role from storage and want to fail closed.
func UnknownRole(role string) bool {
	_, ok := roleGrants[Role(role)]
	return !ok
}
