// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"context"

	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 当前用户凭据的事务边界 ========================

func credentialOwner(tx *storage.Tx, userID, purpose string) (string, error) {
	if tx == nil {
		return "", problem.New(problem.ValidationFailed, "A credential transaction is required.")
	}
	if ids.Check(userID, ids.User) != nil || purpose != "identity.totp" {
		return "", problem.New(problem.ValidationFailed, "The credential secret scope is invalid.")
	}
	return "users/" + userID, nil
}

// SealCredential 在凭据写事务内创建用户所属密文，失败随凭据一起回滚。
func (s *Store) SealCredential(ctx context.Context, tx *storage.Tx, userID, purpose string, plaintext []byte) (string, error) {
	owner, err := credentialOwner(tx, userID, purpose)
	if err != nil {
		return "", err
	}
	ref, err := s.Put(ctx, tx, owner, purpose, plaintext)
	return string(ref), err
}

// OpenCredential 仅读取当前用户实际持有的 TOTP 凭据。
// system owner 兼容旧库，但仍须匹配当前凭据成员与固定用途，不开放通用解密。
func (s *Store) OpenCredential(ctx context.Context, tx *storage.Tx, userID, purpose, rawRef string) ([]byte, error) {
	owner, err := credentialOwner(tx, userID, purpose)
	if err != nil {
		return nil, err
	}
	ref, err := ParseRef(rawRef)
	if err != nil {
		return nil, err
	}
	var member bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM credentials WHERE user_id=? AND secret=? AND type IN ('totp', 'totp_pending')
	)`, userID, rawRef).Scan(&member); err != nil {
		return nil, problem.Wrap(err)
	}
	if !member {
		return nil, errNotFound()
	}
	r, err := scanSecretRow(tx.QueryRowContext(ctx, secretRowQuery, rawRef))
	if err != nil {
		return nil, err
	}
	if r.purpose != purpose || (r.owner != owner && r.owner != SystemOwner) {
		return nil, errNotFound()
	}
	secret, err := s.decrypt(ref, r)
	if err != nil {
		return nil, err
	}
	defer secret.Clear()
	return secret.Bytes(), nil
}
