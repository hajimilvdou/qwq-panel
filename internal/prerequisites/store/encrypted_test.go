// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 真实私有 KV / AES-GCM / 事务回归 ========================

func encryptedFixture(t *testing.T, entries int, maxBytes int64) (*store.EncryptedRepository, *storage.DB, *secrets.Store) {
	t.Helper()
	db, vault := testsupport.EncryptedStorage(t, clock.System{})
	repository, err := store.NewEncrypted(store.EncryptedOptions{DB: db, Secrets: vault, Namespace: "authorizations", MaxEntries: entries, MaxBytes: maxBytes})
	if err != nil {
		t.Fatal(err)
	}
	return repository, db, vault
}

func TestEncryptedRepositoryUsesOpaqueRevisionAndPrivateAAD(t *testing.T) {
	r, db, vault := encryptedFixture(t, 0, 0)
	marker := make([]byte, 24)
	if _, err := rand.Read(marker); err != nil {
		t.Fatal(err)
	}
	value, err := json.Marshal(map[string]string{"marker": hex.EncodeToString(marker)})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := r.Put(context.Background(), "policy/one", "", value)
	if err != nil {
		t.Fatal(err)
	}
	entry, found, err := r.Get(context.Background(), "policy/one")
	if err != nil || !found || !bytes.Equal(entry.Value, value) || entry.Revision != revision || len(revision) != 64 {
		t.Fatal("加密 KV 未按原字节或独立版本返回")
	}
	var reference, owner, purpose string
	var ciphertext []byte
	if err := db.Reader().QueryRowContext(context.Background(), `SELECT id, owner, purpose, ciphertext FROM secrets WHERE owner = ?`, "host/prerequisites/state/authorizations").Scan(&reference, &owner, &purpose, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(revision, reference) || bytes.Contains(ciphertext, value) || bytes.Contains(ciphertext, []byte("policy/one")) {
		t.Fatal("KV 版本或密文暴露了内部秘密引用与状态")
	}
	if _, err := vault.RevealOwned(context.Background(), secrets.Ref(reference), "plugins/tls.certificates", purpose); !problem.HasCode(err, problem.PermissionDenied) && !problem.HasCode(err, problem.NotFound) {
		t.Fatal("插件 owner 获得宿主私有授权状态")
	}
	if _, err := r.Put(context.Background(), "policy/one", "", value); fault.Code(err) != "REVISION_CONFLICT" {
		t.Fatal("创建可以覆盖已经存在的私有状态")
	}
	if err := r.Delete(context.Background(), "policy/one", strings.Repeat("0", 64)); fault.Code(err) != "REVISION_CONFLICT" {
		t.Fatal("过时版本可以删除私有状态")
	}
}

func TestEncryptedRepositoryConcurrentCASHasOneWinner(t *testing.T) {
	r, db, vault := encryptedFixture(t, 0, 0)
	other, err := store.NewEncrypted(store.EncryptedOptions{DB: db, Secrets: vault, Namespace: "authorizations"})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := r.Put(context.Background(), "policy/shared", "", []byte(`{"value":0}`))
	if err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			current := r
			if index%2 != 0 {
				current = other
			}
			_, err := current.Put(context.Background(), "policy/shared", revision, []byte(fmt.Sprintf(`{"value":%d}`, index+1)))
			if err == nil {
				winners.Add(1)
			} else if fault.Code(err) != "REVISION_CONFLICT" {
				t.Errorf("并发 CAS 返回非冲突错误：%v", err)
			}
		}(index)
	}
	close(start)
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatal("多个进程视图覆盖了同一私有版本")
	}
}

func TestEncryptedRepositorySharesQuotasAndIsolatesNamespaces(t *testing.T) {
	r, db, vault := encryptedFixture(t, 1, 1<<20)
	other, err := store.NewEncrypted(store.EncryptedOptions{DB: db, Secrets: vault, Namespace: "authorizations", MaxEntries: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := r.Put(context.Background(), "one", "", []byte(`{"value":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Put(context.Background(), "two", "", []byte(`{"value":2}`)); fault.Code(err) != "RESOURCE_EXHAUSTED" {
		t.Fatal("多个私有 KV 实例叠加了条目预算")
	}
	if err := other.Delete(context.Background(), "one", revision); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Put(context.Background(), "two", "", []byte(`{"value":2}`)); err != nil {
		t.Fatal(err)
	}
	isolation, err := store.NewEncrypted(store.EncryptedOptions{DB: db, Secrets: vault, Namespace: "tasks"})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := isolation.Get(context.Background(), "two"); err != nil || found {
		t.Fatal("另一个私有命名空间读取了授权状态")
	}
	large, err := json.Marshal(strings.Repeat("a", 600<<10))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := isolation.Put(context.Background(), "large/one", "", large); err != nil {
		t.Fatal(err)
	}
	limited, err := store.NewEncrypted(store.EncryptedOptions{DB: db, Secrets: vault, Namespace: "tasks", MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Put(context.Background(), "large/two", "", large); fault.Code(err) != "RESOURCE_EXHAUSTED" {
		t.Fatal("私有 KV 越过共享密文字节预算")
	}
}

func TestEncryptedRepositoryInsertFailureRollsBackOldRecord(t *testing.T) {
	r, db, _ := encryptedFixture(t, 0, 0)
	value := []byte(`{"phase":"prepared"}`)
	revision, err := r.Put(context.Background(), "attempt/one", "", value)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), `CREATE TRIGGER reject_private_insert BEFORE INSERT ON secrets WHEN NEW.owner = 'host/prerequisites/state/authorizations' BEGIN SELECT RAISE(ABORT, 'fixture storage failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Put(context.Background(), "attempt/one", revision, []byte(`{"phase":"submitted"}`)); fault.Code(err) != "STATE_UNAVAILABLE" {
		t.Fatal("真实写失败未拒绝私有状态提交")
	}
	entry, found, err := r.Get(context.Background(), "attempt/one")
	if err != nil || !found || entry.Revision != revision || !bytes.Equal(entry.Value, value) {
		t.Fatal("失败事务删除了原始意图或伪造了新版本")
	}
}

func TestEncryptedRepositoryAmbiguityAndCancellationFailClosed(t *testing.T) {
	r, db, vault := encryptedFixture(t, 0, 0)
	revision, err := r.Put(context.Background(), "one", "", []byte(`{"phase":"prepared"}`))
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Put(canceled, "one", revision, []byte(`{"phase":"submitted"}`)); !errors.Is(err, context.Canceled) {
		t.Fatal("取消后的私有状态提交没有停止")
	}
	var purpose string
	if err := db.Reader().QueryRowContext(context.Background(), `SELECT purpose FROM secrets WHERE owner = ?`, "host/prerequisites/state/authorizations").Scan(&purpose); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(context.Background(), func(tx *storage.Tx) error {
		_, err := vault.Put(context.Background(), tx, "host/prerequisites/state/authorizations", purpose, []byte(`{"version":1}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Get(context.Background(), "one"); fault.Code(err) != "REVISION_CONFLICT" {
		t.Fatal("歧义的 owner/purpose 被当作可信授权状态")
	}
}

func TestEncryptedRepositoryRejectsPluginSelectedNamespaceAndInvalidState(t *testing.T) {
	_, db, vault := encryptedFixture(t, 0, 0)
	if _, err := store.NewEncrypted(store.EncryptedOptions{DB: db, Secrets: vault, Namespace: "plugins/tls.certificates"}); err == nil {
		t.Fatal("插件路径可以选择宿主私有命名空间")
	}
	r, err := store.NewEncrypted(store.EncryptedOptions{DB: db, Secrets: vault, Namespace: "tasks"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"../one", "", "a\x00b", strings.Repeat("a", 513)} {
		if _, err := r.Put(context.Background(), key, "", []byte(`{}`)); err == nil {
			t.Fatal("非法私有 KV 键未拒绝")
		}
	}
	if _, err := r.Put(context.Background(), "one", "", []byte(`not-json`)); err == nil {
		t.Fatal("非 JSON 私有状态未拒绝")
	}
}
