// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// TOTP parameters (RFC 6238, the defaults every authenticator app supports).
const (
	TOTPDigits = 6
	// TOTPPeriod is the time step in seconds.
	TOTPPeriod = 30
	// TOTPSkew accepts the previous and next step, so a slightly wrong device
	// clock still works.
	TOTPSkew = 1
	// TOTPSecretLen is 160 bits, the RFC 4226 recommendation for SHA-1.
	TOTPSecretLen = 20
	// TOTPIssuer is the label shown by authenticator apps.
	TOTPIssuer = "qwq"
)

// totpEncoding is the RFC 4648 base32 alphabet without padding that
// authenticator apps expect in the otpauth URL.
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// PurposeTOTP binds a sealed secret to its use.
const PurposeTOTP = "identity.totp"

// NewTOTPSecret returns a fresh 160-bit TOTP shared secret.
func NewTOTPSecret() ([]byte, error) {
	b := make([]byte, TOTPSecretLen)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("identity: read TOTP secret: %w", err)
	}
	return b, nil
}

// TOTPStep returns the RFC 6238 time step for t.
func TOTPStep(t time.Time) int64 { return t.Unix() / TOTPPeriod }

// TOTPCode returns the 6-digit code of a step (RFC 6238 §5.3, SHA-1).
func TOTPCode(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", TOTPDigits, v%1_000_000)
}

// VerifyTOTP checks code against the steps around now and returns the accepted
// step. minStep rejects a step that was already used, which is how replay of a
// captured code within its window is refused. Only steps greater than minStep
// are accepted.
func VerifyTOTP(secret []byte, code string, now time.Time, minStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return 0, false
	}
	step := TOTPStep(now)
	var accepted int64
	found := false
	for delta := -TOTPSkew; delta <= TOTPSkew; delta++ {
		candidate := step + int64(delta)
		if candidate <= minStep || candidate < 0 {
			continue
		}
		want := TOTPCode(secret, candidate)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && candidate > accepted {
			accepted, found = candidate, true
		}
	}
	return accepted, found
}

// TOTPURL renders the otpauth:// URL an authenticator app scans.
func TOTPURL(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", totpEncoding.EncodeToString(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(TOTPDigits))
	q.Set("period", fmt.Sprint(TOTPPeriod))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Enrollment is a pending TOTP enrolment. The secret is returned once, for the
// QR code and for manual entry; only its sealed reference is stored.
type Enrollment struct {
	// Secret is the base32 secret for manual entry.
	Secret string
	// URL is the otpauth:// URL for the QR code.
	URL string
	// ExpiresAt is when the unconfirmed secret stops being usable.
	ExpiresAt time.Time
	// Revision is the user revision the caller must pass to EnableTOTP.
	Revision int64
}

// pendingTOTP is the data JSON of a totp_pending credential.
type pendingTOTP struct {
	ExpiresAt string `json:"expires_at"`
}

// BeginTOTPEnrollment creates a pending TOTP secret for a user. The user
// resource is untouched until a valid code confirms the secret, so no event is
// published here.
func (s *Service) BeginTOTPEnrollment(ctx context.Context, userID string) (Enrollment, error) {
	if s.sealer == nil {
		return Enrollment{}, problem.New(problem.Unavailable, "Second factors are not configured on this host.")
	}
	u, err := s.User(ctx, userID)
	if err != nil {
		return Enrollment{}, err
	}
	if u.Disabled {
		return Enrollment{}, &problem.Error{Code: problem.StateConflict, Detail: "The user is disabled."}
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		return Enrollment{}, err
	}
	defer clear(secret)
	var expires time.Time
	err = s.update(ctx, func(tx *storage.Tx) error {
		current, err := s.userTx(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		if current.Disabled {
			return problem.New(problem.StateConflict, "The user is disabled.")
		}
		u = current
		now := tx.Now()
		expires = now.Add(s.totpEnrollTTL)
		if err := deleteCredentialsTx(ctx, tx, u.ID, credTOTPPending); err != nil {
			return err
		}
		data, err := json.Marshal(pendingTOTP{ExpiresAt: formatTime(expires)})
		if err != nil {
			return err
		}
		ref, err := s.sealer.SealCredential(ctx, tx, u.ID, PurposeTOTP, secret)
		if err != nil {
			return fmt.Errorf("identity: seal TOTP secret: %w", err)
		}
		return insertCredentialTx(ctx, tx, u.ID, credTOTPPending, ref, string(data), 0, now)
	})
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{
		Secret:    totpEncoding.EncodeToString(secret),
		URL:       TOTPURL(TOTPIssuer, u.Username, secret),
		ExpiresAt: expires,
		Revision:  u.Revision,
	}, nil
}

// EnableTOTPInput confirms a pending TOTP secret and mints recovery codes.
// Actor.MFA must be set (a fresh second factor) when the user already has one.
type EnableTOTPInput struct {
	UserID           string
	ExpectedRevision int64
	Code             string
	Actor            actor.Actor
}

// EnableTOTP verifies the code against the pending secret, promotes it to the
// user's confirmed second factor, generates ten recovery codes and records the
// change. The recovery codes are returned once and only hashes are stored.
func (s *Service) EnableTOTP(ctx context.Context, tx *storage.Tx, in EnableTOTPInput) ([]string, User, error) {
	if s.sealer == nil {
		return nil, User{}, problem.New(problem.Unavailable, "Second factors are not configured on this host.")
	}
	u, err := s.userTx(ctx, tx, in.UserID)
	if err != nil {
		return nil, User{}, err
	}
	if err := checkRevision(in.ExpectedRevision, u.Revision); err != nil {
		return nil, User{}, err
	}
	// Confirming replaces an existing second factor. Holding the session alone
	// must not be enough to swap it for an attacker's secret.
	if u.MFAEnabled && !in.Actor.MFA {
		return nil, User{}, problem.New(problem.MFARequired,
			"Replacing the second factor requires a fresh second factor.")
	}
	pending, err := credentialByTypeTx(ctx, tx, u.ID, credTOTPPending)
	if err != nil {
		if problem.HasCode(err, problem.NotFound) {
			return nil, User{}, &problem.Error{
				Code: problem.StateConflict, Detail: "No second-factor enrolment is in progress.",
			}
		}
		return nil, User{}, err
	}
	var data pendingTOTP
	if err := json.Unmarshal([]byte(pending.Data), &data); err != nil {
		return nil, User{}, fmt.Errorf("identity: parse pending TOTP: %w", err)
	}
	expires, err := parseTime(data.ExpiresAt)
	if err != nil {
		return nil, User{}, fmt.Errorf("identity: pending TOTP expiry: %w", err)
	}
	now := tx.Now()
	if !now.Before(expires) {
		return nil, User{}, &problem.Error{
			Code: problem.StateConflict, Detail: "The enrolment expired; start again.",
		}
	}
	secret, err := s.sealer.OpenCredential(ctx, tx, u.ID, PurposeTOTP, pending.Secret)
	if err != nil {
		return nil, User{}, fmt.Errorf("identity: open TOTP secret: %w", err)
	}
	defer clear(secret)
	step, ok := VerifyTOTP(secret, in.Code, now, 0)
	if !ok {
		return nil, User{}, codeViolation()
	}
	if err := deleteCredentialsTx(ctx, tx, u.ID, credTOTP); err != nil {
		return nil, User{}, err
	}
	// 原地提升保留秘密引用，避免先删除待确认凭据而触发最后引用回收。
	if err := updateCredentialTx(ctx, tx, pending, pending.Secret, "{}", step, now); err != nil {
		return nil, User{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE credentials SET type=? WHERE credential_id=?`, credTOTP, pending.ID); err != nil {
		return nil, User{}, err
	}
	codes, err := s.generateRecoveryCodesTx(ctx, tx, u.ID, now)
	if err != nil {
		return nil, User{}, err
	}
	updated, err := s.markUserChanged(ctx, tx, u, []string{"/mfa_enabled"}, ActionMFAEnabled, in.Actor)
	if err != nil {
		return nil, User{}, err
	}
	return codes, updated, nil
}

// DisableTOTPInput removes a user's second factor. Code must be a valid TOTP or
// recovery code: disabling the second factor is itself a sensitive action.
type DisableTOTPInput struct {
	UserID           string
	ExpectedRevision int64
	Method           string
	Code             string
	Actor            actor.Actor
}

// DisableTOTP deletes the TOTP secret and recovery codes and records the
// change. The caller's session should be rotated after this (the gateway calls
// VerifyMFA/elevation or forces a fresh login for destructive actions).
func (s *Service) DisableTOTP(ctx context.Context, tx *storage.Tx, in DisableTOTPInput) (User, error) {
	u, err := s.userTx(ctx, tx, in.UserID)
	if err != nil {
		return User{}, err
	}
	if err := checkRevision(in.ExpectedRevision, u.Revision); err != nil {
		return User{}, err
	}
	if !u.MFAEnabled {
		return User{}, &problem.Error{Code: problem.StateConflict, Detail: "Second factor authentication is not enabled."}
	}
	ok, _, err := s.verifySecondFactorTx(ctx, tx, u, in.Method, in.Code, tx.Now())
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, codeViolation()
	}
	if err := deleteCredentialsTx(ctx, tx, u.ID, credTOTP, credTOTPPending, credRecovery); err != nil {
		return User{}, err
	}
	return s.markUserChanged(ctx, tx, u, []string{"/mfa_enabled"}, ActionMFADisabled, in.Actor)
}

// verifySecondFactorTx checks a TOTP or recovery code inside the transaction.
// The TOTP path is replay protected through the credential counter; a used
// recovery code is deleted.
func (s *Service) verifySecondFactorTx(ctx context.Context, tx *storage.Tx, u User, method, code string, now time.Time) (ok, recoveryUsed bool, err error) {
	switch method {
	case "totp", "":
		if s.sealer == nil {
			return false, false, problem.New(problem.Unavailable, "Second factors are not configured on this host.")
		}
		cred, err := credentialByTypeTx(ctx, tx, u.ID, credTOTP)
		if err != nil {
			return false, false, err
		}
		secret, err := s.sealer.OpenCredential(ctx, tx, u.ID, PurposeTOTP, cred.Secret)
		if err != nil {
			return false, false, fmt.Errorf("identity: open TOTP secret: %w", err)
		}
		defer clear(secret)
		step, ok := VerifyTOTP(secret, code, now, cred.Counter)
		if !ok {
			return false, false, nil
		}
		if err := updateCredentialTx(ctx, tx, cred, cred.Secret, cred.Data, step, now); err != nil {
			return false, false, err
		}
		return true, false, nil
	case "recovery_code":
		digest := RecoveryCodeHash(code)
		if digest == "" {
			return false, false, nil
		}
		var id string
		err := tx.QueryRowContext(ctx,
			`SELECT credential_id FROM credentials WHERE user_id = ? AND type = ? AND secret = ?`,
			u.ID, credRecovery, digest).Scan(&id)
		if isNoRows(err) {
			return false, false, nil
		}
		if err != nil {
			return false, false, fmt.Errorf("identity: load recovery code: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM credentials WHERE credential_id = ?`, id); err != nil {
			return false, false, fmt.Errorf("identity: consume recovery code: %w", err)
		}
		return true, true, nil
	default:
		return false, false, problem.Validation(problem.Violation{
			Pointer: "/method", Code: "invalid", Message: "The method must be totp or recovery_code.",
		})
	}
}

// markUserChanged bumps a user's revision, publishes the event and writes the
// audit record. It is the shared tail of every user mutation in this package
// that changes publicly visible members.
func (s *Service) markUserChanged(ctx context.Context, tx *storage.Tx, u User, pointers []string, action string, fallback actor.Actor) (User, error) {
	seq, err := tx.Changed(ctx, storage.Change{Subject: u.Subject(), Kind: storage.Updated, Pointers: pointers})
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET updated_at = ?, revision = ? WHERE user_id = ?`,
		formatTime(tx.Now()), seq, u.ID); err != nil {
		return User{}, fmt.Errorf("identity: set revision: %w", err)
	}
	updated, err := s.userTx(ctx, tx, u.ID)
	if err != nil {
		return User{}, err
	}
	if err := s.auditTx(ctx, tx, AuditRecord{
		Action:  action,
		Actor:   auditActor(tx, fallback),
		Subject: u.Subject(),
		Outcome: OutcomeSuccess,
	}); err != nil {
		return User{}, err
	}
	return updated, nil
}

// codeViolation is the uniform answer to a wrong TOTP or recovery code.
func codeViolation() error {
	return problem.Validation(problem.Violation{
		Pointer: "/code", Code: "invalid", Message: "The verification code is not valid.",
	})
}
