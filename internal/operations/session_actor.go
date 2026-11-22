// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
)

// SessionActorPrefix is the actor-ID prefix of a native agent session
// (ADR-0010 §5). A session actor is not a delegation: it has no delegation
// record and its authority is the RBAC role of the session owner, which the
// host reads from the session row. Keeping the two apart matters because the
// delegation path also intersects a policy and a node allowlist that a session
// never has.
const SessionActorPrefix = "session:"

// SessionActorID returns the AI actor ID of one agent session.
func SessionActorID(sessionID string) string { return SessionActorPrefix + sessionID }

// IsSessionActor reports whether a is the AI actor of an agent session. The
// actor still carries OnBehalfOf (the session owner) for audit, but no
// delegation exists under its ID; the authorizer and the policy adapter in
// internal/controller branch on this predicate instead of looking one up.
func IsSessionActor(a actor.Actor) bool {
	return a.Kind == actor.AIAgent && strings.HasPrefix(a.ID, SessionActorPrefix) &&
		len(a.ID) > len(SessionActorPrefix)
}
