// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

type fakeRoots struct{ pool *x509.CertPool }

func (r fakeRoots) Roots(_ context.Context, _ tlsmgr.TrustClass) (*x509.CertPool, error) {
	return r.pool, nil
}

type fakeImportPermissions struct{ expected secrets.Ref }

func (p *fakeImportPermissions) AllowImportKey(_ context.Context, caller Caller, reference secrets.Ref) error {
	if caller.OwnerID != "owner-1" || caller.OperationID != "operation-1" || reference != p.expected {
		return fault.New("PERMISSION_DENIED", "不属当前导入 operation")
	}
	return nil
}

func vaultFixture(t *testing.T, roots *x509.CertPool) (*Vault, *storage.DB, *secrets.Store, *fakeImportPermissions, Caller, *clock.Fake) {
	t.Helper()
	now := clock.NewFake(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	db, secretStore := testsupport.EncryptedStorage(t, now)
	permissions := &fakeImportPermissions{}
	vault, err := NewVault(VaultOptions{DB: db, Secrets: secretStore, Imports: OwnedImportKeys{Secrets: secretStore, Authorizations: permissions}, Roots: fakeRoots{roots}, Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	return vault, db, secretStore, permissions, Caller{OwnerID: "owner-1", OperationID: "operation-1"}, now
}

func TestRealVaultEncryptsAndRecoversOwnedMaterial(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	certificate, err := testsupport.SignedCertificate(now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer certificate.Clear()
	vault, db, _, _, caller, _ := vaultFixture(t, certificate.Roots)
	material, err := tlsmgr.NewMaterial(certificate.Chain, certificate.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	spec := Spec{SANs: []string{"proxy.example.com"}, Purpose: tlsmgr.ServerTLS}
	reference, err := vault.EnsureMaterial(context.Background(), caller, "certificate-1", "attempt-1", material, spec, tlsmgr.PublicTrust)
	if err != nil {
		t.Fatal(err)
	}
	existing, err := vault.Find(context.Background(), caller, "certificate-1", "attempt-1")
	if err != nil || existing.Material != reference {
		t.Fatal("lost result could not recover original material")
	}
	second, err := vault.EnsureMaterial(context.Background(), caller, "certificate-1", "attempt-1", material, spec, tlsmgr.PublicTrust)
	if err != nil || second != reference {
		t.Fatal("idempotent save replaced key")
	}
	metadata, err := vault.Inspect(context.Background(), caller, "certificate-1", reference, spec, tlsmgr.PublicTrust)
	if err != nil || metadata.SANs[0] != "proxy.example.com" {
		t.Fatalf("inspect = %v, %v", metadata, err)
	}
	ref, _, err := parseMaterialLocator(reference)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := db.Reader().QueryRowContext(context.Background(), "SELECT ciphertext FROM secrets WHERE id = ?", string(ref)).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("PRIVATE KEY")) || bytes.Contains(ciphertext, certificate.Key) {
		t.Fatal("material stored in plaintext")
	}
	foreign := caller
	foreign.OwnerID = "owner-2"
	_, err = vault.Inspect(context.Background(), foreign, "certificate-1", reference, spec, tlsmgr.PublicTrust)
	requireCode(t, err, "NOT_FOUND")
	_, err = vault.Inspect(context.Background(), caller, "certificate-2", reference, spec, tlsmgr.PublicTrust)
	requireCode(t, err, "NOT_FOUND")
	if err := vault.Remove(context.Background(), foreign, "certificate-1", reference); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Inspect(context.Background(), caller, "certificate-1", reference, spec, tlsmgr.PublicTrust); err != nil {
		t.Fatal("foreign delete removed owner material")
	}
}

func TestRealVaultImportUsesCurrentOperationOwnerAndPurpose(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	certificate, err := testsupport.SignedCertificate(now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer certificate.Clear()
	vault, db, secretStore, permissions, caller, _ := vaultFixture(t, certificate.Roots)
	raw, err := json.Marshal(string(certificate.Key))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	input, err := json.Marshal(map[string]json.RawMessage{"private_key": raw})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input)
	schema := []byte(`{"type":"object","properties":{"private_key":{"type":"string","writeOnly":true,"x-secret":true}}}`)
	protected, extracted, err := secretStore.ExtractSecrets(context.Background(), schema, input, secrets.ExtractOptions{Owner: "plugins/tls.certificates", Purpose: "plugin.operation"})
	if err != nil {
		t.Fatal(err)
	}
	if len(extracted) != 1 || extracted[0].Pointer != "/private_key" || bytes.Contains(protected, []byte("PRIVATE KEY")) {
		t.Fatal("真实提取没有生成安全私钥引用")
	}
	keyRef := extracted[0].Ref
	permissions.expected = keyRef
	spec := Spec{SANs: []string{"proxy.example.com"}, Purpose: tlsmgr.ServerTLS}
	reference, err := vault.Import(context.Background(), caller, "certificate-1", "import-1", certificate.Chain, string(keyRef), spec, tlsmgr.PublicTrust)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Inspect(context.Background(), caller, "certificate-1", reference, spec, tlsmgr.PublicTrust); err != nil {
		t.Fatal(err)
	}
	other := caller
	other.OperationID = "another-operation"
	_, err = vault.Import(context.Background(), other, "certificate-2", "import-2", certificate.Chain, string(keyRef), spec, tlsmgr.PublicTrust)
	requireCode(t, err, "PERMISSION_DENIED")
	if err := db.Update(context.Background(), func(tx *storage.Tx) error {
		var err error
		keyRef, err = secretStore.Put(context.Background(), tx, "plugins/another", "plugin.operation", raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	permissions.expected = keyRef
	_, err = vault.Import(context.Background(), caller, "certificate-2", "import-3", certificate.Chain, string(keyRef), spec, tlsmgr.PublicTrust)
	requireCode(t, err, "NOT_FOUND")
}

func TestRealVaultConcurrentTestGenerationAndCancellation(t *testing.T) {
	vault, _, _, _, caller, now := vaultFixture(t, nil)
	spec := Spec{SANs: []string{"proxy.example.com"}, Purpose: tlsmgr.TestServerTLS}
	var wait sync.WaitGroup
	refs := make(chan MaterialRef, 8)
	errorsFound := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ref, err := vault.GenerateTest(context.Background(), caller, "certificate-1", "test-1", spec)
			refs <- ref
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(refs)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	var same MaterialRef
	for ref := range refs {
		if same != "" && ref != same {
			t.Fatal("concurrent generation replaced key")
		}
		same = ref
	}
	metadata, err := vault.Inspect(context.Background(), caller, "certificate-1", same, spec, tlsmgr.TestTrust)
	if err != nil || !metadata.NotAfter.Equal(now.Now().Add(24*time.Hour)) {
		t.Fatal("test generation validity was not bounded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = vault.GenerateTest(ctx, caller, "certificate-2", "cancel-1", spec)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
	_, err = vault.Find(context.Background(), caller, "certificate-2", "cancel-1")
	requireCode(t, err, "NOT_FOUND")
}
