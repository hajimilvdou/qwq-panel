// SPDX-License-Identifier: AGPL-3.0-only

package privateexport

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
	"golang.org/x/crypto/ssh"
)

// StoreMaterial 在导入公钥之前加密保存私钥，重启后仍复用同一把密钥。
func (s *Service) StoreMaterial(ctx context.Context, call Caller, private []byte, material KeyMaterial) (KeyMaterial, error) {
	if err := validateMaterial(private, material); err != nil {
		return KeyMaterial{}, err
	}
	var saved KeyMaterial
	err := s.opts.DB.Update(ctx, func(tx *storage.Tx) error {
		entry, err := s.producer(ctx, tx, call)
		if err != nil {
			return err
		}
		if entry.Grant.Status == "MATERIALIZED" || entry.Grant.Status == "READY" {
			if entry.material.PublicKey != material.PublicKey || entry.material.Fingerprint != material.Fingerprint {
				return problem.New(problem.PreconditionFailed, "导出已绑定另一份密钥材料")
			}
			saved = entry.material
			return nil
		}
		if entry.Grant.Status != "RESERVED" || entry.operationID != call.OperationID {
			return notFound()
		}
		ref, err := s.opts.Secrets.Put(ctx, tx, secretOwner(call.ExportID), secretPurpose, private)
		if err != nil {
			return err
		}
		material.ExportID, material.Status, material.Revision = call.ExportID, "MATERIALIZED", ""
		raw, err := json.Marshal(material)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE private_exports SET secret_ref=?,material_json=?,status='MATERIALIZED',updated_at=? WHERE export_id=?`, string(ref), string(raw), storage.FormatTime(s.opts.Clock.Now()), call.ExportID); err != nil {
			return err
		}
		if err := audit(ctx, tx, call.Actor, "materialize", call.ExportID, call.OperationID, call.Binding.NodeID); err != nil {
			return err
		}
		saved = material
		return nil
	})
	return saved, problemResult(err)
}

func (s *Service) Finish(ctx context.Context, call Caller, revision string) error {
	if !validRevision(revision) {
		return problem.New(problem.ValidationFailed, "公钥资源版本无效")
	}
	err := s.opts.DB.Update(ctx, func(tx *storage.Tx) error {
		entry, err := s.producer(ctx, tx, call)
		if err != nil {
			return err
		}
		if entry.Grant.Status == "READY" {
			if entry.material.Revision == revision {
				return nil
			}
			return problem.New(problem.PreconditionFailed, "公钥导入版本已变化")
		}
		if entry.Grant.Status != "MATERIALIZED" || entry.secretRef == "" {
			return notFound()
		}
		entry.material.Status, entry.material.Revision = "READY", revision
		raw, err := json.Marshal(entry.material)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE private_exports SET status='READY',material_json=?,updated_at=? WHERE export_id=?`, string(raw), storage.FormatTime(s.opts.Clock.Now()), call.ExportID); err != nil {
			return err
		}
		return audit(ctx, tx, call.Actor, "ready", call.ExportID, call.OperationID, call.Binding.NodeID)
	})
	return problemResult(err)
}

func validateMaterial(private []byte, material KeyMaterial) error {
	invalid := func() error {
		return problem.New(problem.ValidationFailed, "私密材料与公开密钥信息不匹配")
	}
	if len(private) == 0 || len(private) > 64<<10 || len(material.PublicKey) > 16<<10 || material.Type != "ed25519" || material.Bits != 256 {
		return invalid()
	}
	key, err := ssh.ParseRawPrivateKey(private)
	if err != nil {
		return invalid()
	}
	defer clearPrivateKey(key)
	signer, ok := key.(crypto.Signer)
	if !ok {
		return invalid()
	}
	derived, err := ssh.NewPublicKey(signer.Public())
	if err != nil || derived.Type() != ssh.KeyAlgoED25519 {
		return invalid()
	}
	public, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(material.PublicKey))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(public.Marshal(), derived.Marshal()) || ssh.FingerprintSHA256(public) != material.Fingerprint {
		return invalid()
	}
	return nil
}

// 验证器解析出的可变私钥同样清除；原调用方的输入缓冲由调用方掌管。
func clearPrivateKey(key any) {
	switch value := key.(type) {
	case ed25519.PrivateKey:
		clear(value)
	case *ed25519.PrivateKey:
		if value != nil {
			clear(*value)
		}
	case *ecdsa.PrivateKey:
		if value != nil {
			*value = ecdsa.PrivateKey{}
		}
	case *rsa.PrivateKey:
		if value == nil {
			return
		}
		if value.D != nil {
			clear(value.D.Bits())
		}
		for _, prime := range value.Primes {
			if prime != nil {
				clear(prime.Bits())
			}
		}
		if value.Precomputed.Dp != nil {
			clear(value.Precomputed.Dp.Bits())
		}
		if value.Precomputed.Dq != nil {
			clear(value.Precomputed.Dq.Bits())
		}
		if value.Precomputed.Qinv != nil {
			clear(value.Precomputed.Qinv.Bits())
		}
	}
}
