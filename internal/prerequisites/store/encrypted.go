// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 宿主私有、加密且有界的 KV ========================

// EncryptedOptions 只由宿主构造；命名空间不能由插件或 RPC 参数选择。
// 业务公开视图仍在插件 KV，授权事实、原订单和任务状态使用此私有后端。
type EncryptedOptions struct {
	DB         *storage.DB
	Secrets    *secrets.Store
	Namespace  string
	MaxEntries int
	MaxBytes   int64
}

// EncryptedRepository 复用 AES-GCM/AAD 和单写事务，不添加业务核心表。
// 公开 revision 是独立摘要，永远不把内部秘密引用当作 KV 版本返回。
type EncryptedRepository struct {
	db         *storage.DB
	secrets    *secrets.Store
	owner      string
	maxEntries int
	maxBytes   int64
}

var privateKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$`)

const privateValueLimit = secrets.MaxPlaintext - 1024

func NewEncrypted(options EncryptedOptions) (*EncryptedRepository, error) {
	if options.DB == nil || options.Secrets == nil {
		return nil, fault.New("BACKEND_REQUIRED", "宿主私有 KV 需要真实数据库和加密存储")
	}
	switch options.Namespace {
	case "dns", "certificates", "authorizations", "tasks":
	default:
		return nil, fault.New("VALIDATION_FAILED", "宿主私有 KV 命名空间无效")
	}
	if options.MaxEntries == 0 {
		options.MaxEntries = 256
	}
	if options.MaxBytes == 0 {
		options.MaxBytes = 8 << 20
	}
	if options.MaxEntries < 1 || options.MaxEntries > 2048 || options.MaxBytes < 1<<20 || options.MaxBytes > 64<<20 {
		return nil, fault.New("VALIDATION_FAILED", "宿主私有 KV 容量无效")
	}
	return &EncryptedRepository{db: options.DB, secrets: options.Secrets, owner: "host/prerequisites/state/" + options.Namespace, maxEntries: options.MaxEntries, maxBytes: options.MaxBytes}, nil
}

type privateEnvelope struct {
	Version  uint32          `json:"version"`
	Key      string          `json:"key"`
	Revision string          `json:"revision"`
	Value    json.RawMessage `json:"value"`
}

type privateRecord struct {
	envelope  privateEnvelope
	reference secrets.Ref
	raw       []byte
}

func (privateRecord) String() string   { return "store.privateRecord{[REDACTED]}" }
func (privateRecord) GoString() string { return "store.privateRecord{[REDACTED]}" }

func privatePurpose(key string) (string, error) {
	if !privateKeyPattern.MatchString(key) {
		return "", fault.New("VALIDATION_FAILED", "宿主私有 KV 键格式无效")
	}
	sum := sha256.Sum256([]byte(key))
	return "kv." + hex.EncodeToString(sum[:]), nil
}

func privateRevision(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func (r *EncryptedRepository) read(ctx context.Context, key, purpose string) (privateRecord, bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		ref, found, err := r.secrets.FindOwned(ctx, r.owner, purpose)
		if err != nil || !found {
			return privateRecord{}, found, privateStoreFailure(err)
		}
		secret, err := r.secrets.RevealOwned(ctx, ref, r.owner, purpose)
		if err == nil {
			raw := append([]byte(nil), secret.Bytes()...)
			secret.Clear()
			var envelope privateEnvelope
			if len(raw) > secrets.MaxPlaintext || json.Unmarshal(raw, &envelope) != nil || envelope.Version != 1 || envelope.Key != key || !privateRevision(envelope.Revision) || len(envelope.Value) > privateValueLimit || !json.Valid(envelope.Value) {
				clear(raw)
				clear(envelope.Value)
				return privateRecord{}, false, fault.New("STATE_INVALID", "宿主私有 KV 的持久状态无效")
			}
			return privateRecord{envelope: envelope, reference: ref, raw: raw}, true, nil
		}
		if !problem.HasCode(err, problem.NotFound) {
			return privateRecord{}, false, privateStoreFailure(err)
		}
	}
	return privateRecord{}, false, fault.New("REVISION_CONFLICT", "宿主私有 KV 在读取期间已换代")
}

func (r *EncryptedRepository) Get(ctx context.Context, key string) (Entry, bool, error) {
	purpose, err := privatePurpose(key)
	if err != nil {
		return Entry{}, false, err
	}
	record, found, err := r.read(ctx, key, purpose)
	if err != nil || !found {
		return Entry{}, found, err
	}
	defer clear(record.raw)
	return Entry{Value: record.envelope.Value, Revision: record.envelope.Revision}, true, nil
}

// guard 校验读取后的内容仍属于同一条私有记录。EnsureOwned 内部在当前事务
// 重读 AAD 和明文；目标消失时产生的临时插入随 REVISION_CONFLICT 一起回滚。
func (r *EncryptedRepository) guard(ctx context.Context, tx *storage.Tx, purpose string, old privateRecord) error {
	ref, err := r.secrets.EnsureOwned(ctx, tx, r.owner, purpose, old.raw)
	if err != nil {
		return privateStoreFailure(err)
	}
	if ref != old.reference {
		return fault.New("REVISION_CONFLICT", "宿主私有 KV 已被其他事务修改")
	}
	return nil
}

func (r *EncryptedRepository) Put(ctx context.Context, key, expected string, value []byte) (string, error) {
	purpose, err := privatePurpose(key)
	if err != nil {
		return "", err
	}
	if len(value) > privateValueLimit || !json.Valid(value) || (expected != "" && !privateRevision(expected)) {
		return "", fault.New("VALIDATION_FAILED", "宿主私有 KV 值或版本无效")
	}
	old, found, err := r.read(ctx, key, purpose)
	if err != nil {
		return "", err
	}
	defer clear(old.raw)
	defer clear(old.envelope.Value)
	if (found && expected != old.envelope.Revision) || (!found && expected != "") {
		return "", fault.New("REVISION_CONFLICT", "宿主私有 KV 版本已变化")
	}
	var revision string
	err = r.db.Update(ctx, func(tx *storage.Tx) error {
		if found {
			if err := r.guard(ctx, tx, purpose, old); err != nil {
				return err
			}
		}
		sum := sha256.Sum256([]byte(key + "\x00" + expected + "\x00" + tx.NewID(ids.Secret)))
		revision = hex.EncodeToString(sum[:])
		raw, err := json.Marshal(privateEnvelope{Version: 1, Key: key, Revision: revision, Value: value})
		if err != nil || len(raw) > secrets.MaxPlaintext {
			return fault.New("STATE_INVALID", "宿主私有 KV 无法安全编码")
		}
		defer clear(raw)
		var entries int
		var used int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(length(ciphertext)), 0) FROM secrets WHERE owner = ?`, r.owner).Scan(&entries, &used); err != nil {
			return privateStoreFailure(err)
		}
		delta := int64(len(raw) + 16)
		if found {
			delta -= int64(len(old.raw) + 16)
		}
		if (!found && entries >= r.maxEntries) || used+delta > r.maxBytes {
			return fault.New("RESOURCE_EXHAUSTED", "宿主私有 KV 达到容量上限")
		}
		if found {
			if err := r.secrets.Delete(ctx, tx, old.reference); err != nil {
				return privateStoreFailure(err)
			}
		}
		_, err = r.secrets.EnsureOwned(ctx, tx, r.owner, purpose, raw)
		return privateStoreFailure(err)
	})
	if err != nil {
		return "", err
	}
	return revision, nil
}

func (r *EncryptedRepository) Delete(ctx context.Context, key, expected string) error {
	purpose, err := privatePurpose(key)
	if err != nil {
		return err
	}
	if !privateRevision(expected) {
		return fault.New("VALIDATION_FAILED", "宿主私有 KV 删除需要有效版本")
	}
	old, found, err := r.read(ctx, key, purpose)
	if err != nil {
		return err
	}
	defer clear(old.raw)
	defer clear(old.envelope.Value)
	if !found || expected != old.envelope.Revision {
		return fault.New("REVISION_CONFLICT", "宿主私有 KV 版本已变化")
	}
	return r.db.Update(ctx, func(tx *storage.Tx) error {
		if err := r.guard(ctx, tx, purpose, old); err != nil {
			return err
		}
		return privateStoreFailure(r.secrets.Delete(ctx, tx, old.reference))
	})
}

func privateStoreFailure(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if problem.HasCode(err, problem.StateConflict) {
		return fault.New("REVISION_CONFLICT", "宿主私有 KV 并发提交冲突")
	}
	return fault.New("STATE_UNAVAILABLE", "宿主私有 KV 暂不可用")
}

var _ Repository = (*EncryptedRepository)(nil)
