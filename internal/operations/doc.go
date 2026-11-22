// SPDX-License-Identifier: AGPL-3.0-only

// Package operations owns the single write path of the host (ADR-0004 D1,
// ADR-0008 §2): every state change is an Operation created, gated and recorded
// here, so a person clicking in the Shell and an AI agent calling the API go
// through exactly the same code.
//
// The package also owns plans, approvals, effective risk, idempotency keys, the
// audit log and the job workers. It depends only on storage, actor and
// platform; everything it needs from other domains arrives through the narrow
// interfaces in this package (Catalog, Authorizer, Policy, Revisions,
// Dispatcher, Notifier) and is wired together in internal/controller.
//
// Two rules shape the code:
//
//   - A write transaction never makes a network call or calls a plugin
//     (ADR-0008 §3). Host actions run inside the operation transaction; plugin
//     actions are dispatched after the transaction commits and their result is
//     written back in a new one.
//   - Every committed change calls storage.Tx.Changed for each modified
//     resource, and the operation itself is a resource: its revision is the
//     sequence number of its own resource.changed event. Status and progress
//     changes also append an operation.updated event (ADR-0004 D3).
package operations
