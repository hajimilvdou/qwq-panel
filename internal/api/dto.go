// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// This file holds the wire DTOs the domain packages do not already shape.
// identity and authz store Go values without JSON tags, and the node, plugin and
// session responses are assembled here, so those are mapped explicitly.
// Operations, plans and approvals already carry the public member names and are
// returned as they are (their timestamps are RFC 3339 in UTC).

// Discriminator values of the Session and MfaChallenge schemas.
const (
	statusAuthenticated = "authenticated"
	statusMFARequired   = "mfa_required"
)

// ts renders a timestamp the way the rest of the host does (RFC 3339, UTC,
// milliseconds); the zero time becomes the empty string and is omitted.
func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return storage.FormatTime(t)
}

// userDTO is the User schema.
type userDTO struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	MFAEnabled  bool   `json:"mfa_enabled"`
	Disabled    bool   `json:"disabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Revision    string `json:"revision"`
}

func newUserDTO(u identity.User) userDTO {
	return userDTO{
		UserID:      u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        string(u.Role),
		MFAEnabled:  u.MFAEnabled,
		Disabled:    u.Disabled,
		CreatedAt:   ts(u.CreatedAt),
		UpdatedAt:   ts(u.UpdatedAt),
		Revision:    storage.Revision(u.Revision),
	}
}

// sessionDTO is the Session schema. The session ID exists only in the cookie.
type sessionDTO struct {
	Status        string  `json:"status"`
	User          userDTO `json:"user"`
	CSRFToken     string  `json:"csrf_token"`
	MFAVerifiedAt string  `json:"mfa_verified_at,omitempty"`
	CreatedAt     string  `json:"created_at"`
	IdleExpiresAt string  `json:"idle_expires_at"`
	ExpiresAt     string  `json:"expires_at"`
}

func newSessionDTO(s identity.Session) sessionDTO {
	return sessionDTO{
		Status:        statusAuthenticated,
		User:          newUserDTO(s.User),
		CSRFToken:     s.CSRF,
		MFAVerifiedAt: ts(s.MFAVerifiedAt),
		CreatedAt:     ts(s.CreatedAt),
		IdleExpiresAt: ts(s.IdleExpiresAt),
		ExpiresAt:     ts(s.ExpiresAt),
	}
}

// mfaChallengeDTO is the MfaChallenge schema.
type mfaChallengeDTO struct {
	Status      string   `json:"status"`
	ChallengeID string   `json:"challenge_id"`
	Methods     []string `json:"methods"`
	ExpiresAt   string   `json:"expires_at"`
}

func newMFAChallengeDTO(c identity.MFAChallenge) mfaChallengeDTO {
	methods := c.Methods
	if methods == nil {
		methods = []string{}
	}
	return mfaChallengeDTO{
		Status:      statusMFARequired,
		ChallengeID: c.ID,
		Methods:     methods,
		ExpiresAt:   ts(c.ExpiresAt),
	}
}

// setupStatus is the SetupStatus schema.
type setupStatus struct {
	Initialized    bool   `json:"initialized"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
}

// delegationDTO is the Delegation schema. The token is never part of it.
type delegationDTO struct {
	DelegationID string       `json:"delegation_id"`
	Label        string       `json:"label"`
	OwnerID      string       `json:"owner_id"`
	Policy       authz.Policy `json:"policy"`
	Status       string       `json:"status"`
	TokenPrefix  string       `json:"token_prefix,omitempty"`
	LastUsedAt   string       `json:"last_used_at,omitempty"`
	CreatedAt    string       `json:"created_at"`
	ExpiresAt    string       `json:"expires_at"`
	Revision     string       `json:"revision"`
}

// newDelegationDTO renders d with its effective status at now: an expired token
// reports `expired` even though the stored status is not rewritten on read.
func newDelegationDTO(d authz.Delegation, now time.Time) delegationDTO {
	return delegationDTO{
		DelegationID: d.ID,
		Label:        d.Label,
		OwnerID:      d.OwnerID,
		Policy:       d.Policy,
		Status:       string(d.StatusAt(now)),
		TokenPrefix:  d.TokenPrefix,
		LastUsedAt:   ts(d.LastUsedAt),
		CreatedAt:    ts(d.CreatedAt),
		ExpiresAt:    ts(d.ExpiresAt),
		Revision:     storage.Revision(d.Revision),
	}
}

// delegationCreatedDTO is the DelegationCreated schema: the delegation plus the
// bearer token, which is returned only by the creating call.
type delegationCreatedDTO struct {
	delegationDTO
	Token string `json:"token"`
}

// nodeDTO is the Node schema. A standalone installation has exactly one node.
type nodeDTO struct {
	NodeID          string `json:"node_id"`
	Name            string `json:"name"`
	Mode            string `json:"mode,omitempty"`
	EnrollmentState string `json:"enrollment_state,omitempty"`
	Status          string `json:"status"`
	LastSeenAt      string `json:"last_seen_at,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	Reported        any    `json:"reported,omitempty"`
	CreatedAt       string `json:"created_at"`
	Revision        string `json:"revision"`
}

// plannedChangeDTO is the PlannedChange schema. The operation manager also keeps
// an optional description of the change; it is not part of the published schema
// yet and is left out here.
type plannedChangeDTO struct {
	Kind       string          `json:"kind"`
	Subject    string          `json:"subject"`
	Pointer    string          `json:"pointer,omitempty"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	Reversible bool            `json:"reversible"`
	Source     string          `json:"source"`
	PluginID   string          `json:"plugin_id,omitempty"`
}

// planDTO is the Plan schema. operations.Plan has the same members but leaves the
// three arrays nil when empty, while the schema requires arrays; this mapping
// also renders the timestamps like the rest of the host.
type planDTO struct {
	PlanID           string                    `json:"plan_id"`
	Action           string                    `json:"action"`
	Target           operations.Target         `json:"target"`
	Args             json.RawMessage           `json:"args,omitempty"`
	ArgsDigest       string                    `json:"args_digest"`
	Plannable        bool                      `json:"plannable"`
	Changes          []plannedChangeDTO        `json:"changes"`
	ChangesTruncated bool                      `json:"changes_truncated,omitempty"`
	Violations       []problem.Violation       `json:"violations"`
	Warnings         []problem.Violation       `json:"warnings"`
	Preconditions    []operations.Precondition `json:"preconditions"`
	EffectiveRisk    string                    `json:"effective_risk"`
	RequiresApproval bool                      `json:"requires_approval"`
	RequiresMFA      bool                      `json:"requires_mfa,omitempty"`
	Executable       bool                      `json:"executable"`
	OperationID      string                    `json:"operation_id,omitempty"`
	CreatedAt        string                    `json:"created_at"`
	ExpiresAt        string                    `json:"expires_at"`
	Revision         string                    `json:"revision"`
}

func newPlanDTO(p *operations.Plan) planDTO {
	out := planDTO{
		PlanID:           p.ID,
		Action:           p.Action,
		Target:           p.Target,
		Args:             secrets.RedactArguments(p.Args),
		ArgsDigest:       p.ArgsDigest,
		Plannable:        p.Plannable,
		Changes:          make([]plannedChangeDTO, 0, len(p.Changes)),
		ChangesTruncated: p.ChangesTruncated,
		Violations:       p.Violations,
		Warnings:         p.Warnings,
		Preconditions:    p.Preconditions,
		EffectiveRisk:    p.EffectiveRisk,
		RequiresApproval: p.RequiresApproval,
		RequiresMFA:      p.RequiresMFA,
		Executable:       p.Executable,
		OperationID:      p.OperationID,
		CreatedAt:        ts(p.CreatedAt),
		ExpiresAt:        ts(p.ExpiresAt),
		Revision:         p.Revision,
	}
	if out.Violations == nil {
		out.Violations = []problem.Violation{}
	}
	if out.Warnings == nil {
		out.Warnings = []problem.Violation{}
	}
	if out.Preconditions == nil {
		out.Preconditions = []operations.Precondition{}
	}
	for _, c := range p.Changes {
		out.Changes = append(out.Changes, plannedChangeDTO{
			Kind: c.Kind, Subject: c.Subject, Pointer: c.Pointer,
			Before: secrets.RedactRefs(c.Before), After: secrets.RedactRefs(c.After), Reversible: c.Reversible,
			Source: c.Source, PluginID: c.PluginID,
		})
	}
	return out
}
