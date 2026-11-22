// SPDX-License-Identifier: AGPL-3.0-only

// Package identity manages users, built-in roles, password hashing, sessions,
// TOTP and recovery codes, the one-time setup token and progressive login
// backoff (P1-T3, ARCH §4.1.1, ADR-0008).
//
// The package owns the users, credentials, sessions, mfa_challenges and
// one_time_tokens tables (migration 0002). Every change to a user resource runs
// in the caller's *storage.Tx and records a resource.changed event through
// tx.Changed; the authentication flows (login, logout, second factor, session
// touch) only write audit records, because they change session state rather
// than a managed resource (ADR-0008 §2).
//
// Machine keys, TOTP secrets and the audit table are owned by other packages:
// the narrow SecretSealer and Auditor interfaces below keep this package free of
// those dependencies, and internal/controller wires the real implementations.
//
// Timeouts, argon2id parameters and the backoff curve are documented in
// REPORT.md. All time comes from a clock.Clock and all IDs from
// internal/platform/ids, so expiry and ID generation are testable.
package identity
