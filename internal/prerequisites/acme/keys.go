// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 复用 AES-GCM 与受限幂等密钥 ========================

func keyOwner(caller certificates.Caller, certificateID string) (string, error) {
	if !names.ID(caller.OwnerID) || !names.ID(caller.OperationID) || !names.ID(certificateID) {
		return "", fault.New("PERMISSION_DENIED", "ACME 密钥资源身份无效")
	}
	return "plugins/tls.certificates/owners/" + caller.OwnerID + "/certificates/" + certificateID, nil
}
func keyPurpose(attemptID string) string {
	sum := sha256.Sum256([]byte(attemptID))
	return "acme.key." + hex.EncodeToString(sum[:])
}
func accountOwner(caller certificates.Caller, ca certificates.CA) string {
	return "plugins/tls.certificates/owners/" + caller.OwnerID + "/acme/accounts/" + string(ca)
}

func (a *Authority) ensureKey(ctx context.Context, owner, purpose string) (secrets.Ref, crypto.Signer, error) {
	ref, found, err := a.secrets.FindOwned(ctx, owner, purpose)
	if err != nil {
		return "", nil, keyFailure(err)
	}
	if !found {
		key, err := ecdsa.GenerateKey(elliptic.P256(), a.random)
		if err != nil {
			return "", nil, fault.New("KEY_UNAVAILABLE", "ACME 无法生成安全密钥")
		}
		defer clearSigner(key)
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", nil, fault.New("KEY_UNAVAILABLE", "ACME 密钥无法编码")
		}
		defer clear(raw)
		err = a.db.Update(ctx, func(tx *storage.Tx) error {
			var err error
			ref, err = a.secrets.EnsureOwned(ctx, tx, owner, purpose, raw)
			return err
		})
		if err != nil && !problem.HasCode(err, problem.StateConflict) {
			return "", nil, keyFailure(err)
		}
		if err != nil {
			ref, found, err = a.secrets.FindOwned(ctx, owner, purpose)
			if err != nil || !found {
				return "", nil, keyFailure(err)
			}
		}
	}
	key, err := a.readKey(ctx, owner, purpose, ref)
	return ref, key, err
}

func (a *Authority) readKey(ctx context.Context, owner, purpose string, ref secrets.Ref) (crypto.Signer, error) {
	secret, err := a.secrets.RevealOwned(ctx, ref, owner, purpose)
	if err != nil {
		return nil, keyFailure(err)
	}
	defer secret.Clear()
	raw := secret.Bytes()
	defer clear(raw)
	parsed, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, fault.New("STATE_INVALID", "ACME 加密密钥格式无效")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fault.New("STATE_INVALID", "ACME 密钥不是受控 P-256")
	}
	return key, nil
}

func keyPEM(key crypto.Signer) ([]byte, error) {
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fault.New("KEY_UNAVAILABLE", "ACME 密钥无法编码")
	}
	defer clear(raw)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), nil
}

func keyFailure(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fault.New("KEY_UNAVAILABLE", "ACME 受限加密密钥存储不可用")
}

func clearSigner(key crypto.Signer) {
	// 编码缓冲在各调用点清零；Go 不提供覆盖 opaque key 内部副本的公共 API。
	if private, ok := key.(*ecdsa.PrivateKey); ok {
		*private = ecdsa.PrivateKey{}
	}
}
