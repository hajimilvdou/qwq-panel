// SPDX-License-Identifier: AGPL-3.0-only

// Package controller assembles the host's services (P1, ADR-0008 §1). It is the
// only package that knows about all domains: it opens the database, constructs
// identity, authz, secrets, TLS, operations, events and the gateway, and adapts
// their narrow interfaces to each other. Domain packages never import each
// other; the adapters that bridge them live here.
//
// The assembly is deliberately explicit and ordered: storage first (migrations
// run before any other service touches the database), then the secret master
// key and TLS material, then identity/authz, then operations (which needs the
// auditor and authorizer), then the event hub, and finally the HTTP gateway.
// Shutdown runs in reverse order with a bounded context.
package controller
