// SPDX-License-Identifier: AGPL-3.0-only

// Package supervisor owns the host side of the plugin process lifecycle
// (ADR-0003, ARCH §6.4): it starts and stops a plugin's systemd unit, attaches
// to the plugin socket through a native gRPC connection, derives the process
// generation, runs the per-plugin host channel and tears down every host-side
// registration of an owner.
//
// systemd is the only source of truth for process identity. The supervisor never
// execs a plugin and never signals it while closing a connection; MainPID is
// never cached: every Ensure re-reads the unit state and
// derives
//
//	generation = sha256(unit|MainPID|starttime)[:16]
//
// so an out-of-band restart invalidates the previous instance. Stopping and
// killing go through the unit manager (systemctl stop/kill), which cleans the
// whole cgroup.
//
// The package is deliberately free of systemd, sandbox and host-service
// implementation details. UnitManager is adapted from internal/sandbox and
// HostServer from internal/hostsvc by the host; both are injected in Options.
// It depends on the platform clock and problem packages and on the generated
// Platform ABI client, nothing else.
//
// Log flow: plugin stdout/stderr is not a protocol channel. AttachLogs turns a
// stream the host obtained elsewhere (journald) into rate-limited structured
// records, so a crashing plugin cannot flood the journal.
package supervisor
