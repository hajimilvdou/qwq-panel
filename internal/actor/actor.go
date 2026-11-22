// SPDX-License-Identifier: AGPL-3.0-only

// Package actor defines who causes a change (ADR-0004 D4). It is shared by
// identity, authz, operations, events and the gateway, and depends on nothing
// in the host, so those packages can be built in parallel and wired together
// in internal/controller.
package actor

import (
	"context"
	"errors"
)

// Kind of actor; values match the public Actor schema and proto ActorKind.
type Kind string

const (
	Human   Kind = "human"
	AIAgent Kind = "ai_agent"
	Service Kind = "service"
	System  Kind = "system"
)

// Actor is the authenticated principal of a request or operation. It is set by
// the host only; values received from plugins or clients are never trusted.
type Actor struct {
	Kind Kind `json:"kind"`
	// ID is a user ID (human), delegation ID (ai_agent), service-account ID
	// (service) or a host component name (system, e.g. "reconciler").
	ID string `json:"id"`
	// OnBehalfOf is the user or service account whose authority is used, for
	// ai_agent and service.
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
	// OnBehalfOfKind 是宿主从实际会话行读取的主体类型，不属于公开 Actor 契约。
	// 操作重载后该值为空，授权仍需按合法 ID 查询当前主体权限。
	OnBehalfOfKind Kind `json:"-"`
	// SessionID is the web session for human actors; empty otherwise. Only an
	// actor with a session may approve (ADR-0004 D6).
	SessionID string `json:"-"`
	// MFA reports that the session passed a second factor recently enough for
	// destructive approvals.
	MFA bool `json:"-"`
}

// Valid reports whether the actor is well formed.
func (a Actor) Valid() error {
	switch a.Kind {
	case Human, System:
		if a.OnBehalfOf != "" || a.OnBehalfOfKind != "" {
			return errors.New("actor: on_behalf_of is only for ai_agent and service")
		}
	case AIAgent, Service:
		if a.OnBehalfOf == "" && a.Kind == AIAgent {
			return errors.New("actor: ai_agent needs on_behalf_of")
		}
		if a.OnBehalfOfKind != "" && a.OnBehalfOfKind != Human && a.OnBehalfOfKind != Service {
			return errors.New("actor: invalid on_behalf_of_kind")
		}
	default:
		return errors.New("actor: unknown kind")
	}
	if a.ID == "" {
		return errors.New("actor: empty id")
	}
	return nil
}

// IsHumanSession reports whether the actor is a person using a web session:
// the only kind allowed to approve operations (ADR-0004 D6). Reachability
// actions keep no extra protection beyond that grading (ADR-0016).
func (a Actor) IsHumanSession() bool { return a.Kind == Human && a.SessionID != "" }

// SystemActor returns the actor for host-internal work.
func SystemActor(component string) Actor { return Actor{Kind: System, ID: component} }

type ctxKey struct{}

// With returns a context carrying a.
func With(ctx context.Context, a Actor) context.Context { return context.WithValue(ctx, ctxKey{}, a) }

// From returns the actor stored by With.
func From(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(ctxKey{}).(Actor)
	return a, ok
}
