// SPDX-License-Identifier: AGPL-3.0-only

// Package abi holds the Platform ABI v1 trial (IMPLEMENTATION-PLAN.md P0-T7, ADR-0007).
//
// The tests drive the generated gRPC code end to end over in-process bufconn
// connections: one connection host -> plugin (PluginService) and one plugin ->
// host (Host services) per plugin process. Host and plugins are small fakes that
// follow the rules written in platform.proto, ARCH §5.4–§5.7, §7 and ADR-0002,
// ADR-0004, ADR-0007, so that gaps in the ABI show up as code that cannot be
// written cleanly. The fakes are not the real host and must not be reused as one.
//
// Scenarios:
//   - noop_test.go: an empty plugin serving two instances; lifecycle, errors,
//     forward compatibility.
//   - invoke_test.go: a controller plugin calling a Core Driver job through
//     HostInvokeService (InvokePlugin, WaitOperation, CancelOperation).
//   - plan_test.go: an AI agent enabling the security baseline
//     (plan -> approve -> execute) with plugin-owned preconditions.
package abi
