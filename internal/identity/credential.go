// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/storage"
)

// Credential types. The table is (type, secret, data) so that WebAuthn and OIDC
// can be added without a schema change (ADR-0005 Q7):
//
//	password      secret = argon2id PHC string
//	totp          secret = sealed secret reference, counter = last accepted step
//	totp_pending  as totp, confirmed by EnableTOTP
//	recovery      secret = hex SHA-256 of the normalised code
//	webauthn      reserved: secret = sealed public key, data = credential metadata
//	oidc          reserved: data = {issuer, subject, email}
const (
	credPassword    = "password"
	credTOTP        = "totp"
	credTOTPPending = "totp_pending"
	credRecovery    = "recovery"
	credWebAuthn    = "webauthn"
	credOIDC        = "oidc"
)

// credential is one row of the credentials table.
type credential struct {
	ID        string
	UserID    string
	Type      string
	Secret    string
	Data      string
	Counter   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

const credentialColumns = `credential_id, user_id, type, secret, data, counter, created_at, updated_at`

func scanCredential(row scanner) (credential, error) {
	var c credential
	var created, updated string
	if err := row.Scan(&c.ID, &c.UserID, &c.Type, &c.Secret, &c.Data, &c.Counter, &created, &updated); err != nil {
		return credential{}, err
	}
	var err error
	if c.CreatedAt, err = parseTime(created); err != nil {
		return credential{}, fmt.Errorf("identity: credential created_at: %w", err)
	}
	if c.UpdatedAt, err = parseTime(updated); err != nil {
		return credential{}, fmt.Errorf("identity: credential updated_at: %w", err)
	}
	return c, nil
}

// insertCredentialTx inserts one credential row in the caller's transaction.
func insertCredentialTx(ctx context.Context, tx *storage.Tx, userID, typ, secret, data string, counter int64, now time.Time) error {
	if data == "" {
		data = "{}"
	}
	if !json.Valid([]byte(data)) {
		return fmt.Errorf("identity: credential data is not JSON")
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO credentials (credential_id, user_id, type, secret, data, counter, created_at, updated_at, revision)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		tx.NewID(ids.Secret), userID, typ, secret, data, counter, formatTime(now), formatTime(now))
	if err != nil {
		return fmt.Errorf("identity: insert credential: %w", err)
	}
	return nil
}

// findCredentialTx loads the single credential of a type for a user and
// returns sql.ErrNoRows when there is none.
func findCredentialTx(ctx context.Context, tx *storage.Tx, userID, typ string) (credential, error) {
	c, err := scanCredential(tx.QueryRowContext(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE user_id = ? AND type = ?`, userID, typ))
	if err != nil {
		return credential{}, err
	}
	return c, nil
}

// credentialByTypeTx loads the single credential of a type for a user,
// reporting NOT_FOUND when there is none.
func credentialByTypeTx(ctx context.Context, tx *storage.Tx, userID, typ string) (credential, error) {
	c, err := findCredentialTx(ctx, tx, userID, typ)
	if isNoRows(err) {
		return credential{}, errNotFound("credential")
	}
	if err != nil {
		return credential{}, fmt.Errorf("identity: load credential: %w", err)
	}
	return c, nil
}

// credentialByType loads a credential outside a write transaction.
func (s *Service) credentialByType(ctx context.Context, userID, typ string) (credential, error) {
	c, err := scanCredential(s.db.Reader().QueryRowContext(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE user_id = ? AND type = ?`, userID, typ))
	if isNoRows(err) {
		return credential{}, errNotFound("credential")
	}
	if err != nil {
		return credential{}, fmt.Errorf("identity: load credential: %w", err)
	}
	return c, nil
}

// hasCredential reports whether a user has a credential of the given type.
func (s *Service) hasCredential(ctx context.Context, userID, typ string) (bool, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM credentials WHERE user_id = ? AND type = ?`, userID, typ).Scan(&n); err != nil {
		return false, fmt.Errorf("identity: count credentials: %w", err)
	}
	return n > 0, nil
}

// updateCredentialTx rewrites the mutable columns of a credential row.
func updateCredentialTx(ctx context.Context, tx *storage.Tx, cred credential, secret, data string, counter int64, now time.Time) error {
	if data == "" {
		data = "{}"
	}
	_, err := tx.ExecContext(ctx,
		`UPDATE credentials SET secret = ?, data = ?, counter = ?, updated_at = ? WHERE credential_id = ?`,
		secret, data, counter, formatTime(now), cred.ID)
	if err != nil {
		return fmt.Errorf("identity: update credential: %w", err)
	}
	return nil
}

// deleteCredentialsTx removes every credential of the given types for a user.
func deleteCredentialsTx(ctx context.Context, tx *storage.Tx, userID string, types ...string) error {
	for _, typ := range types {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM credentials WHERE user_id = ? AND type = ?`, userID, typ); err != nil {
			return fmt.Errorf("identity: delete credential: %w", err)
		}
	}
	return nil
}

// upsertPasswordTx replaces (or creates) the password credential. The caller
// has already hashed the password outside the transaction.
func upsertPasswordTx(ctx context.Context, tx *storage.Tx, userID, hash string, now time.Time) error {
	cred, err := findCredentialTx(ctx, tx, userID, credPassword)
	switch {
	case isNoRows(err):
		return insertCredentialTx(ctx, tx, userID, credPassword, hash, "{}", 0, now)
	case err != nil:
		return fmt.Errorf("identity: load credential: %w", err)
	}
	return updateCredentialTx(ctx, tx, cred, hash, cred.Data, cred.Counter, now)
}

// revokeUserSessionsTx marks every live session of a user as revoked. The
// session rows stay for the audit trail and are pruned with the journal.
func revokeUserSessionsTx(ctx context.Context, tx *storage.Tx, userID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at = ''`,
		formatTime(now), userID); err != nil {
		return fmt.Errorf("identity: revoke sessions: %w", err)
	}
	return nil
}
