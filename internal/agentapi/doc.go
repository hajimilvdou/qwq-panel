// SPDX-License-Identifier: AGPL-3.0-only

// Package agentapi implements the seven AI operator tools of the public API
// (ADR-0004 D8): find_actions, describe_action, read, plan, execute, wait and
// cancel, served under /api/v1/agent/*.
//
// The tools are thin adapters, not a second write path. Every state change goes
// through internal/operations, every authorization decision is taken by
// internal/authz (this package only pre-filters search results with the same
// inputs), and every response body is the schema of api/public/v1/openapi.yaml:
//
//	find_actions     catalog.Find       FindActionsResponse (ActionSummary)
//	describe_action  catalog.Get        ActionDescription (ActionMeta)
//	read             identity, operations, authz   ReadResponse
//	plan             operations.CreatePlan          Plan
//	execute          operations.Run / ExecutePlan   OperationOutcome
//	wait             operations.Wait                OperationOutcome
//	cancel           operations.Cancel              OperationOutcome
//
// Three rules shape the package:
//
//   - Only a delegation bearer token is accepted. The gateway enforces that
//     with AccessDelegation; the handlers check the principal again and load
//     the delegation record so a suspended or expired token is denied even if
//     a route is ever wired differently.
//   - A tool reports what the delegating human may see and do, never more. An
//     action outside the delegation's effective permission is not offered by
//     find_actions, describe_action answers 404 for it (existence is not
//     leaked), and read answers 404 for a subject the caller may not see.
//   - Nothing is truncated silently. find_actions reports truncated, and read
//     reports the limit that cut the response with a hint on how to continue.
//
// All seven tools are POST with a JSON body and always answer 200 on success
// with the state in the body (the execute/wait/cancel tools put the status in
// the OperationOutcome instead of the HTTP status).
package agentapi
