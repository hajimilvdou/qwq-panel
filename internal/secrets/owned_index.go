// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 宿主受控幂等材料索引 ========================

const secretRowQuery = `SELECT owner, purpose, key_id, nonce, ciphertext FROM secrets WHERE id = ?`

type rowScanner interface{ Scan(...any) error }
type ownedQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// FindOwned 仅供宿主以自身计算的 owner/purpose 查找，不对插件或公共接口开放。
// 既有多记录 purpose 明确拒绝歧义，不能任取一条旧配置或其他材料。
func (s *Store) FindOwned(ctx context.Context, owner, purpose string) (Ref, bool, error) {
	if err := validateOwner(owner); err != nil {
		return "", false, err
	}
	if err := validatePurpose(purpose); err != nil {
		return "", false, err
	}
	return findOwned(ctx, s.db.Reader(), owner, purpose)
}

func findOwned(ctx context.Context, query ownedQuerier, owner, purpose string) (Ref, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	rows, err := query.QueryContext(ctx, `SELECT id FROM secrets WHERE owner = ? AND purpose = ? ORDER BY id LIMIT 2`, owner, purpose)
	if err != nil {
		return "", false, problem.Wrap(err)
	}
	defer rows.Close()
	var ref Ref
	count := 0
	for rows.Next() {
		if err := rows.Scan(&ref); err != nil {
			return "", false, problem.Wrap(err)
		}
		count++
		if count > 1 {
			return "", false, problem.New(problem.StateConflict, "Secret owner/purpose is ambiguous.")
		}
	}
	if err := rows.Err(); err != nil {
		return "", false, problem.Wrap(err)
	}
	if count == 0 {
		return "", false, nil
	}
	if err := checkRef(ref); err != nil {
		return "", false, err
	}
	return ref, true, nil
}

// EnsureOwned 复用现有单写事务、AAD、加密与清零。同名称只允许同内容重入，
// 不同内容拒绝覆盖，保证响应丢失后不会替换已经生成的私钥。
func (s *Store) EnsureOwned(ctx context.Context, tx *storage.Tx, owner, purpose string, plaintext []byte) (Ref, error) {
	if tx == nil {
		return "", problem.New(problem.ValidationFailed, "A write transaction is required.")
	}
	if err := validateOwner(owner); err != nil {
		return "", err
	}
	if err := validatePurpose(purpose); err != nil {
		return "", err
	}
	if len(plaintext) > MaxPlaintext {
		return "", problem.New(problem.ValidationFailed, "Secret material is too large.")
	}
	ref, found, err := findOwned(ctx, tx, owner, purpose)
	if err != nil {
		return "", err
	}
	if !found {
		return s.put(ctx, tx, owner, purpose, plaintext)
	}
	stored, err := scanSecretRow(tx.QueryRowContext(ctx, secretRowQuery, string(ref)))
	if err != nil {
		return "", err
	}
	if stored.owner != owner || stored.purpose != purpose {
		return "", errNotFound()
	}
	material, err := s.decrypt(ref, stored)
	if err != nil {
		return "", err
	}
	defer material.Clear()
	oldHash, newHash := sha256.Sum256(material.b), sha256.Sum256(plaintext)
	defer clear(oldHash[:])
	defer clear(newHash[:])
	if subtle.ConstantTimeCompare(oldHash[:], newHash[:]) != 1 {
		return "", problem.New(problem.StateConflict, "Secret owner/purpose already names different content.")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return ref, nil
}

func scanSecretRow(scanner rowScanner) (row, error) {
	var stored row
	err := scanner.Scan(&stored.owner, &stored.purpose, &stored.keyID, &stored.nonce, &stored.ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return row{}, errNotFound()
	}
	if err != nil {
		return row{}, problem.Wrap(err)
	}
	return stored, nil
}
