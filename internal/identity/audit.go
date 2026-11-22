// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Audit outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// Audit actions written by this package. They are stable, dotted names; the
// operations package owns the audit table and prefixes its own records with the
// operation ID.
const (
	ActionSetupCompleted   = "auth.setup_completed"
	ActionSetupTokenIssued = "auth.setup_token_issued"
	ActionLogin            = "auth.login"
	ActionLoginFailed      = "auth.login_failed"
	ActionMFAVerified      = "auth.mfa_verified"
	ActionMFAFailed        = "auth.mfa_failed"
	ActionLogout           = "auth.logout"
	ActionSessionRevoked   = "auth.session_revoked"
	ActionMFAEnabled       = "user.mfa_enabled"
	ActionMFADisabled      = "user.mfa_disabled"
	ActionRecoveryUsed     = "user.recovery_code_used"
	ActionUserCreated      = "user.created"
	ActionUserUpdated      = "user.updated"
	ActionUserDeleted      = "user.deleted"
	ActionPasswordReset    = "user.password_reset"
	ActionPasswordChanged  = "user.password_changed"
	ActionAdminRecovered   = "user.admin_recovered"
)

// AuditRecord is one audit entry. The host's audit table is owned by the
// operations package (P1-T5); this struct is the contract between the two, so
// its fields mirror what the table needs:
//
//	action        stable dotted name (the constants above)
//	actor         who caused it; actor.SystemActor("identity") for failed or
//	              pre-authentication events
//	subject       resource subject (e.g. "users/usr_..."), empty for auth events
//	outcome       "success" or "failure"
//	reason        short machine code for failures ("bad_password", "disabled", ...)
//	client_ip, user_agent  request origin, when known
//	detail        small non-secret facts (never passwords, tokens or secret refs)
//	at            event time from the service clock
type AuditRecord struct {
	Action    string
	Actor     actor.Actor
	Subject   string
	Outcome   string
	Reason    string
	ClientIP  string
	UserAgent string
	Detail    map[string]string
	At        time.Time
}

// Auditor persists one audit record in the caller's transaction. The host
// implements it in internal/operations; tests use a recording fake.
type Auditor interface {
	Audit(ctx context.Context, tx *storage.Tx, rec AuditRecord) error
}
