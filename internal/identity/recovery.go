// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/storage"
)

// RecoveryCodeCount is how many single-use recovery codes an enrolment mints.
const RecoveryCodeCount = 10

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// newRecoveryCode returns one code formatted as XXXX-XXXX-XXXX-XXXX. Ten bytes
// of entropy (80 bits) make guessing infeasible; the dashes only help humans.
func newRecoveryCode() (string, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("identity: read recovery code: %w", err)
	}
	raw := recoveryEncoding.EncodeToString(b[:])
	parts := make([]string, 0, len(raw)/4)
	for i := 0; i < len(raw); i += 4 {
		parts = append(parts, raw[i:i+4])
	}
	return strings.Join(parts, "-"), nil
}

// normalizeRecoveryCode strips the separators and upper-cases a user-supplied
// code, so "abcd-efgh" and "ABCDEFGH" match.
func normalizeRecoveryCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(s)) {
		if r == '-' || r == ' ' || r == '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// RecoveryCodeHash returns the hex SHA-256 of a normalised recovery code, or ""
// when the input cannot be a code. Recovery codes are one-way hashed, not
// sealed: they are only ever compared, never read back.
func RecoveryCodeHash(code string) string {
	norm := normalizeRecoveryCode(code)
	if len(norm) < 8 || len(norm) > 32 {
		return ""
	}
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// generateRecoveryCodesTx replaces a user's recovery codes with a new set and
// returns the plaintext codes for one-time display.
func (s *Service) generateRecoveryCodesTx(ctx context.Context, tx *storage.Tx, userID string, now time.Time) ([]string, error) {
	if err := deleteCredentialsTx(ctx, tx, userID, credRecovery); err != nil {
		return nil, err
	}
	codes := make([]string, 0, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		if err := insertCredentialTx(ctx, tx, userID, credRecovery, RecoveryCodeHash(code), "{}", 0, now); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}
