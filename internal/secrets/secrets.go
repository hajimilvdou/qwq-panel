// SPDX-License-Identifier: AGPL-3.0-only

// Package secrets stores secret values encrypted at rest and hands out
// references to them.
//
// A value is kept as AES-256-GCM ciphertext in the secrets table; every other
// table, config snapshot, event, audit row and log line only sees the reference
// (sec_…). The additional authenticated data binds a row to its id, owner and
// purpose, so a ciphertext copied into another row or relabelled with another
// purpose fails to decrypt. The master key lives outside the database in
// dataDir/keys (mode 0600) and is backed up separately (ARCH §8.3, ADR-0008 §7).
//
// Writes happen in a storage.Tx supplied by the caller (Put, Delete,
// DeleteOwner), so a resource and the secret it points at are committed
// together; Seal opens its own transaction for callers that only need to
// encrypt a short value (the identity package's SecretSealer).
//
// Values never reach a log: Secret implements slog.LogValuer and fmt.Stringer
// and redacts everything, and the store logs references only.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

const (
	// MaxPlaintext bounds one secret value. Configs live in secrets, so the cap
	// is generous; the request limit is 1 MiB (ARCH §5.4) and a single value
	// never needs more.
	MaxPlaintext = 1 << 20

	// SystemOwner owns values sealed through the owner-less Seal/Open seam,
	// which the identity package's SecretSealer uses. Values that belong to a
	// resource (config snapshots, plugin instances) must use Put with the
	// resource's owner so DeleteOwner can clean them up.
	SystemOwner = "system"

	maxOwnerLen   = 512
	maxPurposeLen = 128
)

// Options configure New.
type Options struct {
	// DB is the host database; required.
	DB *storage.DB
	// Keys is the master key ring; required. Load it with LoadKeyRing.
	Keys *KeyRing
	// Logger receives diagnostics; references only, never values.
	Logger *slog.Logger
}

// Store is the secret store.
type Store struct {
	db   *storage.DB
	keys *KeyRing
	log  *slog.Logger
}

// New returns a store over db and keys.
func New(o Options) (*Store, error) {
	if o.DB == nil {
		return nil, errors.New("secrets: Options.DB is required")
	}
	if o.Keys == nil {
		return nil, errors.New("secrets: Options.Keys is required")
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Store{db: o.DB, keys: o.Keys, log: o.Logger}, nil
}

// Keys returns the key ring, for operators that rotate keys.
func (s *Store) Keys() *KeyRing { return s.keys }

// Put encrypts plaintext and inserts a row owned by owner with the given
// purpose, inside the caller's transaction. It returns the reference to store
// in the resource row.
//
// The caller must commit tx; if the transaction rolls back, the row disappears
// with it and the reference is never stored anywhere.
func (s *Store) Put(ctx context.Context, tx *storage.Tx, owner, purpose string, plaintext []byte) (Ref, error) {
	if tx == nil {
		return "", problem.New(problem.ValidationFailed, "A write transaction is required to store a secret.")
	}
	if err := validateOwner(owner); err != nil {
		return "", err
	}
	if err := validatePurpose(purpose); err != nil {
		return "", err
	}
	if len(plaintext) > MaxPlaintext {
		return "", problem.New(problem.ValidationFailed, "A secret value must be at most %d bytes.", MaxPlaintext)
	}
	return s.put(ctx, tx, owner, purpose, plaintext)
}

// put is Put without argument validation, shared with Seal and ExtractSecrets.
func (s *Store) put(ctx context.Context, tx *storage.Tx, owner, purpose string, plaintext []byte) (Ref, error) {
	key := s.keys.Primary()
	aead, err := s.keys.aead(key.ID)
	if err != nil {
		return "", problem.Wrap(err)
	}
	id := tx.NewID(ids.Secret)
	nonce, ciphertext, err := seal(aead, id, owner, purpose, plaintext)
	if err != nil {
		return "", problem.Wrap(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO secrets
		(id, owner, purpose, key_id, nonce, ciphertext, created_at, revision)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		id, owner, purpose, key.ID, nonce, ciphertext, storage.FormatTime(tx.Now())); err != nil {
		return "", problem.Wrap(err)
	}
	s.log.DebugContext(ctx, "secret stored", "ref", id, "owner", owner, "purpose", purpose, "key_id", key.ID)
	return Ref(id), nil
}

// Seal encrypts plaintext in its own transaction and returns the reference. It
// is the owner-less form of Put, shaped for identity.SecretSealer: values are
// owned by SystemOwner, so callers that can pass an owner (config snapshots,
// plugin instances) should use Put instead.
//
// Because it opens a transaction, Seal must not be called from inside another
// storage write transaction: the host has a single write connection, so nesting
// would deadlock.
func (s *Store) Seal(ctx context.Context, purpose string, plaintext []byte) (string, error) {
	if err := validatePurpose(purpose); err != nil {
		return "", err
	}
	if len(plaintext) > MaxPlaintext {
		return "", problem.New(problem.ValidationFailed, "A secret value must be at most %d bytes.", MaxPlaintext)
	}
	var ref Ref
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		r, err := s.put(ctx, tx, SystemOwner, purpose, plaintext)
		if err != nil {
			return err
		}
		ref = r
		return nil
	})
	if err != nil {
		return "", err
	}
	return string(ref), nil
}

// Reveal decrypts the secret behind ref after checking that it was stored for
// purpose.
//
// The purpose check catches a reference copied into the wrong field (a TOTP
// seed used as a password); the AAD check catches a ciphertext copied into
// another row. A missing row returns NOT_FOUND, a wrong purpose
// PERMISSION_DENIED, and a value that does not authenticate INTERNAL with the
// cause in the log.
func (s *Store) Reveal(ctx context.Context, ref Ref, purpose string) (Secret, error) {
	if err := validatePurpose(purpose); err != nil {
		return Secret{}, err
	}
	if err := checkRef(ref); err != nil {
		return Secret{}, err
	}
	r, err := s.loadRow(ctx, ref)
	if err != nil {
		return Secret{}, err
	}
	if r.purpose != purpose {
		return Secret{}, problem.New(problem.PermissionDenied, "The secret is not available for this purpose.")
	}
	return s.decrypt(ref, r)
}

// RevealOwned decrypts the secret behind ref only when the row was stored for
// owner with purpose. A row of another owner or purpose answers exactly like a
// missing row (NOT_FOUND), so a caller holding a foreign reference cannot even
// learn that it exists.
//
// Use it wherever the reference comes from data a less trusted principal can
// influence (a session row, a plugin request): Reveal only checks the purpose,
// and every holder of a reference can name a purpose.
func (s *Store) RevealOwned(ctx context.Context, ref Ref, owner, purpose string) (Secret, error) {
	return s.RevealOwnedAnyPurpose(ctx, ref, owner, purpose)
}

// RevealOwnedAnyPurpose 仅解密精确 owner 和显式 purpose 白名单匹配的记录。
// 白名单不解释通配符；不匹配与不存在均返回同一个 NOT_FOUND。
func (s *Store) RevealOwnedAnyPurpose(ctx context.Context, ref Ref, owner string, purposes ...string) (Secret, error) {
	if err := validateOwner(owner); err != nil {
		return Secret{}, err
	}
	if err := validatePurposes(purposes); err != nil {
		return Secret{}, err
	}
	if err := checkRef(ref); err != nil {
		return Secret{}, err
	}
	r, err := s.loadRow(ctx, ref)
	if err != nil {
		return Secret{}, err
	}
	if r.owner != owner || !slices.Contains(purposes, r.purpose) {
		return Secret{}, errNotFound()
	}
	return s.decrypt(ref, r)
}

func validatePurposes(purposes []string) error {
	if len(purposes) == 0 {
		return problem.New(problem.ValidationFailed, "At least one permitted secret purpose is required.")
	}
	for _, purpose := range purposes {
		if err := validatePurpose(purpose); err != nil {
			return err
		}
	}
	return nil
}

// Open decrypts the secret behind ref without checking its purpose. It is the
// identity.SecretSealer shape: the caller already knows what the value is for,
// and the row's own purpose still authenticates the ciphertext.
func (s *Store) Open(ctx context.Context, ref string) ([]byte, error) {
	r, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	secret, err := s.open(ctx, r)
	if err != nil {
		return nil, err
	}
	defer secret.Clear()
	return secret.Bytes(), nil
}

// open decrypts a row after validating its reference.
func (s *Store) open(ctx context.Context, ref Ref) (Secret, error) {
	row, err := s.loadRow(ctx, ref)
	if err != nil {
		return Secret{}, err
	}
	return s.decrypt(ref, row)
}

// Delete removes one secret inside the caller's transaction. Deleting a
// reference that does not exist returns NOT_FOUND: a caller that lost track of
// a reference should notice.
func (s *Store) Delete(ctx context.Context, tx *storage.Tx, ref Ref) error {
	if tx == nil {
		return problem.New(problem.ValidationFailed, "A write transaction is required to delete a secret.")
	}
	if err := checkRef(ref); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, string(ref))
	if err != nil {
		return problem.Wrap(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return problem.Wrap(err)
	}
	if n == 0 {
		return errNotFound()
	}
	s.log.DebugContext(ctx, "secret deleted", "ref", string(ref))
	return nil
}

// DeleteOwner removes every secret of owner inside the caller's transaction and
// returns how many rows it deleted. Plugin uninstall calls it with the instance
// owner; deleting nothing is not an error, so cleanup stays idempotent.
func (s *Store) DeleteOwner(ctx context.Context, tx *storage.Tx, owner string) (int64, error) {
	n, err := DeleteOwner(ctx, tx, owner)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		s.log.InfoContext(ctx, "secrets deleted with their owner", "owner", owner, "rows", n)
	}
	return n, nil
}

// rotBatch limits one rotation transaction's work.
const rotBatch = 100

// Rotate re-encrypts rows that are not under the current primary key, one
// transaction per batch, and returns how many rows it rewrote.
//
// Call KeyRing.Rotate first: new values use the new key immediately, and
// Rotate moves the old ones over. Old values stay readable in the meantime
// because retired keys remain in the ring; keep them until KeyUsage reports no
// rows under the old id.
//
// Rotation is an operator action: it opens its own transactions (so it must not
// run inside another one) and should not race with another rotation.
func (s *Store) Rotate(ctx context.Context, batch int) (int64, error) {
	if batch <= 0 {
		batch = rotBatch
	}
	primary := s.keys.Primary()
	var total int64
	for {
		n, err := s.rotateBatch(ctx, primary, batch)
		if err != nil {
			return total, err
		}
		total += n
		if n < int64(batch) {
			break
		}
	}
	if total > 0 {
		s.log.InfoContext(ctx, "secret key rotation finished", "rows", total, "key_id", primary.ID)
	}
	return total, nil
}

// rotateBatch re-encrypts up to batch rows in one write transaction.
func (s *Store) rotateBatch(ctx context.Context, primary Key, batch int) (int64, error) {
	var n int64
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, owner, purpose, key_id, nonce, ciphertext
			FROM secrets WHERE key_id <> ? ORDER BY id LIMIT ?`, primary.ID, batch)
		if err != nil {
			return err
		}
		type row struct {
			id, owner, purpose, keyID string
			nonce, ciphertext         []byte
		}
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.owner, &r.purpose, &r.keyID, &r.nonce, &r.ciphertext); err != nil {
				rows.Close()
				return err
			}
			list = append(list, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		newAEAD, err := s.keys.aead(primary.ID)
		if err != nil {
			return err
		}
		for _, r := range list {
			oldAEAD, err := s.keys.aead(r.keyID)
			if err != nil {
				return err
			}
			plaintext, err := open(oldAEAD, r.nonce, r.ciphertext, r.id, r.owner, r.purpose)
			if err != nil {
				return fmt.Errorf("secrets: rotate %s: %w", r.id, err)
			}
			nonce, ciphertext, err := seal(newAEAD, r.id, r.owner, r.purpose, plaintext)
			clear(plaintext)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE secrets SET key_id = ?, nonce = ?, ciphertext = ? WHERE id = ?`,
				primary.ID, nonce, ciphertext, r.id); err != nil {
				return err
			}
		}
		n = int64(len(list))
		return nil
	})
	if err != nil {
		return 0, problem.Wrap(err)
	}
	return n, nil
}

// KeyUsage counts stored rows per key id, so an operator can decide when a
// retired key may be dropped.
func (s *Store) KeyUsage(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT key_id, COUNT(*) FROM secrets GROUP BY key_id`)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	defer rows.Close()
	usage := make(map[string]int64)
	for rows.Next() {
		var id string
		var n int64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, problem.Wrap(err)
		}
		usage[id] = n
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(err)
	}
	return usage, nil
}

// row is one stored secret as read from the database.
type row struct {
	owner      string
	purpose    string
	keyID      string
	nonce      []byte
	ciphertext []byte
}

// loadRow reads one row through the read pool.
func (s *Store) loadRow(ctx context.Context, ref Ref) (row, error) {
	return scanSecretRow(s.db.Reader().QueryRowContext(ctx, secretRowQuery, string(ref)))
}

// errNotFound is the one answer for a reference without a usable row: a
// missing row and, for RevealOwned, a row of another owner or purpose look the
// same to the caller.
func errNotFound() error { return problem.New(problem.NotFound, "The secret does not exist.") }

// decrypt opens a loaded row.
func (s *Store) decrypt(ref Ref, r row) (Secret, error) {
	aead, err := s.keys.aead(r.keyID)
	if err != nil {
		return Secret{}, problem.Wrap(err)
	}
	plaintext, err := open(aead, r.nonce, r.ciphertext, string(ref), r.owner, r.purpose)
	if err != nil {
		return Secret{}, problem.Wrap(fmt.Errorf("secrets: %s: %w", ref, err))
	}
	return newSecret(plaintext), nil
}

// checkRef validates a typed reference.
func checkRef(ref Ref) error {
	if !ref.Valid() {
		return problem.New(problem.ValidationFailed, "Not a secret reference.")
	}
	return nil
}

// validateOwner checks the owner namespace: a slash-separated path such as
// users/usr_01… or plugins/core.xray/instances/inst_01….
func validateOwner(owner string) error {
	switch {
	case owner == "":
		return problem.New(problem.ValidationFailed, "A secret owner is required.")
	case len(owner) > maxOwnerLen:
		return problem.New(problem.ValidationFailed, "A secret owner must be at most %d bytes.", maxOwnerLen)
	case strings.HasPrefix(owner, "/"), strings.HasSuffix(owner, "/"), strings.Contains(owner, "//"):
		return problem.New(problem.ValidationFailed, "A secret owner must be a slash-separated path without empty segments.")
	case !namespaceChars(owner, true):
		return problem.New(problem.ValidationFailed, "A secret owner may contain letters, digits, '_', '-', '.', ':' and '/'.")
	}
	return nil
}

// validatePurpose checks the purpose label, which is a short stable name such
// as identity.totp or plugin.config.
func validatePurpose(purpose string) error {
	switch {
	case purpose == "":
		return problem.New(problem.ValidationFailed, "A secret purpose is required.")
	case len(purpose) > maxPurposeLen:
		return problem.New(problem.ValidationFailed, "A secret purpose must be at most %d bytes.", maxPurposeLen)
	case !namespaceChars(purpose, false):
		return problem.New(problem.ValidationFailed, "A secret purpose may contain letters, digits, '_', '-', '.', ':'.")
	}
	return nil
}

// namespaceChars reports whether s uses the characters allowed in owners and
// purposes. Owners are paths, so they may also contain '/'.
func namespaceChars(s string, allowSlash bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '-', c == '.', c == ':':
		case c == '/' && allowSlash:
		default:
			return false
		}
	}
	return true
}
