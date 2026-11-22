// SPDX-License-Identifier: AGPL-3.0-only

package authz

import (
	"regexp"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Permission is "<resource>:<action>", the format of a manifest operation's
// `permission` field (api/manifest/v1/manifest.schema.json) and of the
// x-qwq-action `permission` of host routes.
type Permission string

// permissionRe is the manifest schema pattern, so a permission that passes here
// is also valid in a manifest.
var permissionRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_]*$`)

// ParsePermission validates and returns a permission string. An invalid
// permission is a programming error in the caller (a typo in the action
// catalog), so it is reported as VALIDATION_FAILED rather than silently denied.
func ParsePermission(s string) (Permission, error) {
	if len(s) > 128 || !permissionRe.MatchString(s) {
		return "", problem.Validation(problem.Violation{
			Pointer: "/permission", Code: "invalid",
			Message: "A permission must look like <resource>:<action>, e.g. host.users:create.",
		})
	}
	return Permission(s), nil
}

// Valid reports whether p is well formed.
func (p Permission) Valid() bool {
	s := string(p)
	return len(s) <= 128 && permissionRe.MatchString(s)
}

// Resource returns the part before the colon.
func (p Permission) Resource() string {
	if i := strings.IndexByte(string(p), ':'); i >= 0 {
		return string(p)[:i]
	}
	return string(p)
}

// Action returns the part after the colon.
func (p Permission) Action() string {
	if i := strings.IndexByte(string(p), ':'); i >= 0 {
		return string(p)[i+1:]
	}
	return ""
}

// Pattern matches permissions. A pattern is "*" (everything) or
// "<resource>:<action>" where either segment may be "*" to match any value.
// Segment wildcards only match a whole segment, never a prefix: "host.*" does
// not match "host.users". This keeps a typo from granting more than intended.
type Pattern string

// Matches reports whether the pattern allows perm.
func (p Pattern) Matches(perm Permission) bool {
	pat := string(p)
	if pat == "*" {
		return true
	}
	i := strings.IndexByte(pat, ':')
	j := strings.IndexByte(string(perm), ':')
	if i < 0 || j < 0 {
		return false
	}
	return matchSegment(pat[:i], string(perm[:j])) && matchSegment(pat[i+1:], string(perm[j+1:]))
}

func matchSegment(pattern, value string) bool {
	return pattern == "*" || pattern == value
}

// Resource is the target of an authorization check. Name is the permission's
// resource (host.users, com.example.monitor, …); NodeID scopes the call to one
// managed node and is empty for host-wide resources. A delegation policy with a
// node allowlist only permits the listed nodes. Action is the catalog action ID
// being run (host.users.update, com.example.monitor/scan.run); a delegation
// policy with an action allowlist only permits matching IDs, and refuses a
// check that names no action.
type Resource struct {
	Name   string
	NodeID string
	Action string
	// Subject 是实际资源身份；精确服务作用域不使用 Name 代替它。
	Subject string
}

// isReadPermission reports whether a permission is read-only. The table lives
// in the SDK so manifest validation and authorization cannot drift (ADR-0014).
func isReadPermission(p Permission) bool { return manifest.ReadOnlyActions[p.Action()] }

// humanOnlyResources are managed principals, approvals, a person's own
// account and the global AI providers: only a person using a browser session
// may touch them (ADR-0004 D6; providers per ADR-0017, so a prompt-injected
// agent can never repoint where the installation sends model traffic).
var humanOnlyResources = map[string]bool{
	"host.users":            true,
	"host.delegations":      true,
	"host.service_accounts": true,
	"host.approvals":        true,
	"host.account":          true,
	"host.ai_providers":     true,
}

// selfServiceResources are what every signed-in person manages about
// themself, whichever role they have (a viewer may still rename themself).
// The routes behind them always act on the caller and never take a principal
// from the request, so the grant cannot reach anyone else.
var selfServiceResources = map[string]bool{
	"host.account": true,
}

// humanOnlyActions are approval decisions whatever resource they are spelled
// with.
var humanOnlyActions = map[string]bool{
	"approve": true,
	"reject":  true,
}

// isHumanOnly reports whether a permission is reserved for human sessions.
func isHumanOnly(p Permission) bool {
	if humanOnlyResources[p.Resource()] {
		return true
	}
	return humanOnlyActions[p.Action()]
}
