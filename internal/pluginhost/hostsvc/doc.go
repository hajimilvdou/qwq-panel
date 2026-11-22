// SPDX-License-Identifier: AGPL-3.0-only

// Package hostsvc serves the Platform ABI Host services to exactly one plugin
// instance over a dedicated Unix domain socket.
//
// Architecture (ADR-0003, review C2/O3): the Agent listens on a per-plugin
// socket and lets the plugin connect to it, so the kernel tells the Agent who
// the caller is. Every accepted connection is authenticated with SO_PEERCRED
// (and SO_PEERPIDFD on Linux >= 6.5) before the HTTP/2 preface is read; a
// connection whose peer the configured PeerVerifier rejects is closed at once.
// The verified pid/uid/gid is put into every request context and is the only
// source of caller identity. Fields a plugin can choose - instance_handle,
// operation_id, trace_id and the actor in a request - are correlation data and
// never authorization inputs; see PeerInfo and PeerFromContext.
//
// The six ABI services are registered on one grpc.Server per Server:
//
//   - HostStateService: per-instance key/value state with optimistic
//     concurrency, stored in one JSON file below StateDir by the built-in
//     fileState, or delegated to a caller-provided StateStore.
//   - HostEventsService: publishes events through a bounded local spool to an
//     EventSink and fans host events out to subscriptions (SubscribeEvents),
//     with a durable ack cursor per subscription.
//   - HostConfigService: read-only current config snapshot.
//   - HostSecretsService: reveal with a dispatched operation_id, audited and
//     rate limited per plugin.
//   - HostAuditService: plugin-written audit records with their own quota.
//   - HostInvokeService: plugin-to-plugin calls, host mediated; the Invoker
//     receives the host-known caller identity, never the plugin's claim.
//
// Errors follow the proto header: gRPC status codes report transport and
// host-side failures while a domain outcome that reached the handler is an
// ErrorDetail in the response (InvokePlugin) or a status code when the message
// has no ErrorDetail field (state conflicts use ABORTED, which the SDK maps to
// REVISION_CONFLICT). See REPORT.md for the complete mapping.
//
// A Server is per plugin instance. A plugin process that serves several
// instances (blue/green candidates) needs one Server per instance because
// every dependency in Config - StateDir, ConfigSource, SecretRevealer - is
// scoped to one instance; the instance_handle in HostCallContext is not
// validated here and must not be used to multiplex instances.
package hostsvc
