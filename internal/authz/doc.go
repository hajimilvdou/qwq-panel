// SPDX-License-Identifier: AGPL-3.0-only

// Package authz decides whether an actor may perform an action (P1-T4,
// ADR-0004 D4/D6). It owns role permissions, delegation tokens for AI operators
// and service-account tokens (migration 0003).
//
// A permission is "<resource>:<action>" (the same shape as the `permission`
// field of a manifest operation). The effective permission of a request is:
//
//	human    role grants
//	service  role grants, minus the human-only actions
//	ai_agent (owner's current role grants) ∩ (delegation policy) minus the
//	         human-only actions
//
// The owner's role is read on every request through the narrow PrincipalSource
// interface, so demoting or disabling a user takes effect on their delegations
// immediately. Plugin capabilities are a third, independent check performed by
// the plugin runtime (ARCH §10.3); this package never substitutes for it.
//
// The package does not import internal/identity: the host wires
// identity.Service.PrincipalRole into PrincipalSource in internal/controller.
package authz
