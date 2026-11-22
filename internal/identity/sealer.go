// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"

	"github.com/qwq-panel/qwq/internal/storage"
)

// SecretSealer 将用户凭据与密文绑定在调用者事务中；OpenCredential 必须核对
// 当前用户、用途及凭据成员。宿主 Store 复用 AES-GCM 与既有密钥环实现。
type SecretSealer interface {
	SealCredential(ctx context.Context, tx *storage.Tx, userID, purpose string, plaintext []byte) (ref string, err error)
	OpenCredential(ctx context.Context, tx *storage.Tx, userID, purpose, ref string) ([]byte, error)
}
