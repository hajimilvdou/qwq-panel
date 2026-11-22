// SPDX-License-Identifier: AGPL-3.0-only

// Package updater installs, updates and rolls back plugin versions as
// recoverable sagas, and applies configuration revisions, on one node
// (docs/ARCHITECTURE.md §6.1, §6.3, §6.5).
//
// # Why a saga
//
// Replacing a running plugin is a sequence of effects that cannot share one
// SQLite transaction: the package must be published, a process started, a
// route table switched and the old process drained. The host may be killed
// between any two of them. The updater therefore records one
// plugin_update_sagas row and advances it in short transactions, each one
// written after the effect it describes. Recover reads the unfinished rows and
// either continues a saga that already switched routes or rolls it back;
// every step is idempotent, so recovering twice is harmless (ARCH §6.4).
//
// # Strategies
//
// With overlap (blue-green) the candidate runs next to the old version:
// start, readiness, atomic route switch, old Deactivate, candidate Activate,
// old Stop(drain), old Release, commit. Background work is never duplicated:
// the candidate runs none of it before Activate, and Activate succeeds once.
// The host briefly uses two processes, so the updater first checks memory and
// the manifest's lifecycle.overlap_safe. If either says no, or memory is
// tight, it downgrades to a controlled restart: stop the old version, start
// the candidate, switch routes, activate, and restore the old version if any
// of that fails (ARCH §6.3 "小内存更新").
//
// # Runtime
//
// This package deliberately does not depend on internal/pluginhost/supervisor.
// The host adapts the narrow Runtime interface below (start, attach, ready,
// activate, deactivate, stop, release, health, config and route swap) to the
// P2 supervisor and the sandbox installer; the updater owns the state machine,
// the database, the locks and the transaction boundaries.
//
// # Persistence
//
// plugin_versions stores one row per version (lifecycle status and install
// status are separate axes), plugin_configs is an append-only revision log
// with at most one active row, and plugin_update_sagas is the recovery
// journal with at most one unfinished saga per plugin. Every resource write
// goes through storage.Tx and records its resource.changed revision with
// tx.Changed; every saga step and every configuration outcome also appends an
// audit event with tx.AppendEvent.
package updater
