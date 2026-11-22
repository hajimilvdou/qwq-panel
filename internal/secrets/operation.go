// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

const operationFingerprintPurpose = "operation.fingerprint"

// OperationProtector 复用秘密仓库提取业务参数。指纹密钥独立随机生成并加密保存，
// 在重启和 master key 轮换后保持稳定；不持久化秘密的无密钥摘要。
type OperationProtector struct {
	store *Store
	key   [32]byte
}

func (OperationProtector) String() string   { return "secrets.OperationProtector{[REDACTED]}" }
func (OperationProtector) GoString() string { return "secrets.OperationProtector{[REDACTED]}" }

// NewOperationProtector 加载或原子创建唯一的指纹密钥；不在请求路径生成密钥。
func NewOperationProtector(ctx context.Context, store *Store) (*OperationProtector, error) {
	if store == nil {
		return nil, problem.New(problem.Unavailable, "Operation secret storage is not configured.")
	}
	var ref Ref
	err := store.db.Update(ctx, func(tx *storage.Tx) error {
		var id string
		err := tx.QueryRowContext(ctx, "SELECT id FROM secrets WHERE owner = ? AND purpose = ? ORDER BY created_at, id LIMIT 1", SystemOwner, operationFingerprintPurpose).Scan(&id)
		if err == nil {
			ref = Ref(id)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		defer clear(key[:])
		ref, err = store.put(ctx, tx, SystemOwner, operationFingerprintPurpose, key[:])
		return err
	})
	if err != nil {
		return nil, problem.New(problem.Unavailable, "Operation fingerprint key could not be loaded.")
	}
	secret, err := store.RevealOwned(ctx, ref, SystemOwner, operationFingerprintPurpose)
	if err != nil {
		return nil, problem.New(problem.Unavailable, "Operation fingerprint key could not be opened.")
	}
	defer secret.Clear()
	raw := secret.Bytes()
	defer clear(raw)
	if len(raw) != 32 {
		return nil, problem.New(problem.Unavailable, "Operation fingerprint key is invalid.")
	}
	p := &OperationProtector{store: store}
	copy(p.key[:], raw)
	return p, nil
}

// Fingerprint 给规范化请求生成有用途隔离的幂等摘要，scope 由宿主确定。
func (p *OperationProtector) Fingerprint(scope string, raw []byte) string {
	mac := hmac.New(sha256.New, p.key[:])
	mac.Write([]byte("qwq:operation:arguments:v1\x00"))
	mac.Write([]byte(scope))
	mac.Write([]byte{0})
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

// Protect 用既有 schema walker 提取参数；清理函数只删除本次新建的引用。
// owner/purpose 必须由已验签的 operation 元数据确定。
func (p *OperationProtector) Protect(ctx context.Context, schema, args []byte, owner, purpose string) ([]byte, func(context.Context) error, error) {
	if purpose != "plugin.operation" {
		return nil, nil, problem.New(problem.PermissionDenied, "The operation secret purpose is invalid.")
	}
	protected, extracted, err := p.store.ExtractSecrets(ctx, schema, args, ExtractOptions{Owner: owner, Purpose: purpose})
	if err != nil {
		return nil, nil, err
	}
	cleanup := func(ctx context.Context) error { return p.store.DiscardExtracted(ctx, extracted) }
	return protected, cleanup, nil
}
