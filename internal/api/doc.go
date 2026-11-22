// SPDX-License-Identifier: AGPL-3.0-only

// Package api registers the host half of the public HTTP API
// (api/public/v1/openapi.yaml) on the gateway.
//
// The package is deliberately thin: it decodes and validates requests with the
// gateway tools, calls the domain packages (identity, authz, operations,
// catalog) and renders their results. It contains no policy of its own, no SQL
// and no timers. Every state change goes through operations (ADR-0004 D1):
//
//   - host actions that the action catalog declares (host.users.create,
//     host.users.update, host.users.delete) are registered as host executors
//     and host planners on operations.Service and reached with Run;
//   - delegation management, authentication and setup are catalog-exempt in the
//     OpenAPI document, so those handlers call the owning domain function in a
//     storage transaction and write an audit row in the same transaction;
//   - plugin package upload, install, update, rollback and configuration are
//     catalog-exempt as well: the HTTP layer stages a package with
//     PluginUploads and calls the optional PluginManager (the updater adapter)
//     directly, because the updater runs its own sagas and transactions;
//   - reads call the domain list/get functions and apply `fields`,
//     `limit`/`cursor` and `since_revision` at the edge.
//
// The gateway owns authentication, CSRF, the credential policy, body limits,
// idempotency-key presence, Origin/Host checks and rate limiting; this package
// never repeats those checks. It does enforce the RBAC permission of a read
// route, because the gateway authenticates but does not authorize.
//
// Register must be called once, before the gateway serves.
package api
