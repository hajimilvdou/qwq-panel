// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

const (
	testOwner   = "users/usr_01jtestowner0000000000000"
	testPurpose = "identity.totp"
)

// secretSealer 固定旧 Seal/Open seam；当前 identity 使用带事务的凭据接口。
type secretSealer interface {
	Seal(ctx context.Context, purpose string, plaintext []byte) (ref string, err error)
	Open(ctx context.Context, ref string) ([]byte, error)
}

var _ secretSealer = (*Store)(nil)

func TestPutRevealDelete(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	ref := mustPut(t, s, db, testOwner, testPurpose, []byte("top-secret-value"))

	if !strings.HasPrefix(string(ref), "sec_") {
		t.Fatalf("reference %q does not use the sec_ prefix", ref)
	}
	secret, err := s.Reveal(ctx, ref, testPurpose)
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if got := string(secret.Bytes()); got != "top-secret-value" {
		t.Fatalf("Reveal returned %q", got)
	}
	// Bytes returns a copy: mutating it must not change the stored value.
	b := secret.Bytes()
	b[0] = 'X'
	if got := string(secret.Bytes()); got != "top-secret-value" {
		t.Fatalf("Bytes did not return a copy: %q", got)
	}

	if err := db.Update(ctx, func(tx *storage.Tx) error { return s.Delete(ctx, tx, ref) }); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = s.Reveal(ctx, ref, testPurpose)
	requireCode(t, err, problem.NotFound)
	err = db.Update(ctx, func(tx *storage.Tx) error { return s.Delete(ctx, tx, ref) })
	requireCode(t, err, problem.NotFound)
}

func TestRevealChecksPurpose(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	ref := mustPut(t, s, db, testOwner, testPurpose, []byte("value"))

	_, err := s.Reveal(ctx, ref, "plugin.config")
	requireCode(t, err, problem.PermissionDenied)

	// Reveal with the right purpose still works after the refused attempt.
	if _, err := s.Reveal(ctx, ref, testPurpose); err != nil {
		t.Fatalf("Reveal with the right purpose: %v", err)
	}
}

// TestRevealOwned checks the owner-scoped reveal (AGT-02, reused by PLG-12): a
// value only decrypts for the owner and the purpose it was stored with, and
// every other reference answers exactly like a missing one, so a caller holding
// a foreign reference cannot even learn that it exists.
func TestRevealOwned(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	const (
		owner   = "agent_sessions/sess_01jtestsession000000000000"
		purpose = "agent.native.api_key"
	)
	ref := mustPut(t, s, db, owner, purpose, []byte("sk-owned-value"))
	foreign := mustPut(t, s, db, "plugins/com.example.vpn/instances/default", "plugin.config", []byte("plugin-token"))

	secret, err := s.RevealOwned(ctx, ref, owner, purpose)
	if err != nil {
		t.Fatalf("RevealOwned: %v", err)
	}
	if got := string(secret.Bytes()); got != "sk-owned-value" {
		t.Fatalf("RevealOwned returned %q", got)
	}

	missing := Ref("sec_0123456789abcdefghjkmnpqrs")
	_, errMissing := s.RevealOwned(ctx, missing, owner, purpose)
	requireCode(t, errMissing, problem.NotFound)
	want := problem.From(errMissing)
	cases := []struct {
		name           string
		ref            Ref
		owner, purpose string
	}{
		{"another owner", ref, "agent_sessions/sess_01jtestother00000000000000", purpose},
		{"another purpose", ref, owner, "plugin.config"},
		{"another owner's secret", foreign, owner, purpose},
		{"the right purpose of a foreign secret", foreign, owner, "plugin.config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.RevealOwned(ctx, tc.ref, tc.owner, tc.purpose)
			if p := problem.From(err); p == nil || p.Code != want.Code || p.Detail != want.Detail {
				t.Fatalf("RevealOwned = %v, want the NOT_FOUND of a missing row (%v)", err, errMissing)
			}
			if !got.IsEmpty() {
				t.Fatal("a refused reveal returned secret material")
			}
		})
	}

	// Malformed input is a caller bug, not a lookup.
	_, err = s.RevealOwned(ctx, Ref("not-a-ref"), owner, purpose)
	requireCode(t, err, problem.ValidationFailed)
	_, err = s.RevealOwned(ctx, ref, "", purpose)
	requireCode(t, err, problem.ValidationFailed)
	_, err = s.RevealOwned(ctx, ref, owner, "bad purpose")
	requireCode(t, err, problem.ValidationFailed)

	// The refused attempts did not disturb the owner's own reveal.
	if _, err := s.RevealOwned(ctx, ref, owner, purpose); err != nil {
		t.Fatalf("RevealOwned after refused attempts: %v", err)
	}
}

func TestRevealRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	ref := mustPut(t, s, db, testOwner, testPurpose, []byte("value"))

	_, err := s.Reveal(ctx, Ref("not-a-ref"), testPurpose)
	requireCode(t, err, problem.ValidationFailed)

	_, err = s.Reveal(ctx, ref, "")
	requireCode(t, err, problem.ValidationFailed)

	_, err = s.Reveal(ctx, ref, "bad purpose")
	requireCode(t, err, problem.ValidationFailed)

	_, err = s.Open(ctx, "usr_01jtestowner0000000000000")
	requireCode(t, err, problem.ValidationFailed)
}

func TestLegacySealOpenInterface(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)

	ref, err := s.Seal(ctx, testPurpose, []byte("totp-seed"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !strings.HasPrefix(ref, "sec_") {
		t.Fatalf("Seal returned %q, want a sec_ reference", ref)
	}
	plaintext, err := s.Open(ctx, ref)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plaintext) != "totp-seed" {
		t.Fatalf("Open returned %q", plaintext)
	}

	// The owner-less seam stores values under the system owner so that a plugin
	// instance cleanup can never delete them by accident.
	var owner string
	if err := db.Reader().QueryRowContext(ctx, `SELECT owner FROM secrets WHERE id = ?`, ref).Scan(&owner); err != nil {
		t.Fatalf("read owner: %v", err)
	}
	if owner != SystemOwner {
		t.Fatalf("Seal stored owner %q, want %q", owner, SystemOwner)
	}

	// Rotating keys must not break values sealed before the rotation.
	if _, err := s.Keys().Rotate(); err != nil {
		t.Fatalf("Rotate key: %v", err)
	}
	if _, err := s.Rotate(ctx, 10); err != nil {
		t.Fatalf("Rotate rows: %v", err)
	}
	plaintext, err = s.Open(ctx, ref)
	if err != nil {
		t.Fatalf("Open after rotation: %v", err)
	}
	if string(plaintext) != "totp-seed" {
		t.Fatalf("Open after rotation returned %q", plaintext)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	ref := mustPut(t, s, db, testOwner, testPurpose, []byte("value"))

	var ciphertext []byte
	if err := db.Reader().QueryRowContext(ctx, `SELECT ciphertext FROM secrets WHERE id = ?`, ref).Scan(&ciphertext); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0x01
	execSQL(t, db, `UPDATE secrets SET ciphertext = ? WHERE id = ?`, ciphertext, string(ref))

	_, err := s.Reveal(ctx, ref, testPurpose)
	requireCode(t, err, problem.Internal)
}

func TestCiphertextCannotMoveBetweenRows(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	first := mustPut(t, s, db, testOwner, testPurpose, []byte("first-value"))
	second := mustPut(t, s, db, testOwner, testPurpose, []byte("second-value"))

	// Copy row one's nonce and ciphertext into row two: the id in the AAD no
	// longer matches, so the value must not decrypt.
	var nonce, ciphertext []byte
	if err := db.Reader().QueryRowContext(ctx, `SELECT nonce, ciphertext FROM secrets WHERE id = ?`, first).Scan(&nonce, &ciphertext); err != nil {
		t.Fatalf("read row: %v", err)
	}
	execSQL(t, db, `UPDATE secrets SET nonce = ?, ciphertext = ? WHERE id = ?`, nonce, ciphertext, string(second))

	_, err := s.Reveal(ctx, second, testPurpose)
	requireCode(t, err, problem.Internal)

	// A relabelled purpose must not decrypt either, even without the purpose
	// check that Reveal performs.
	execSQL(t, db, `UPDATE secrets SET purpose = ? WHERE id = ?`, "plugin.config", string(first))
	if _, err := s.Open(ctx, string(first)); !problem.HasCode(err, problem.Internal) {
		t.Fatalf("Open after relabelling the purpose: %v", err)
	}
}

func TestWrongKeyFails(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	ref := mustPut(t, s, db, testOwner, testPurpose, []byte("value"))

	ring := s.Keys()
	oldID := ring.Primary().ID
	rotated, err := ring.Rotate()
	if err != nil {
		t.Fatalf("Rotate key: %v", err)
	}
	// Encrypt the value under the new key but label the row with the old key id:
	// decryption picks the wrong key and the tag check fails.
	aead, err := ring.aead(rotated.ID)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	nonce, ciphertext, err := seal(aead, string(ref), testOwner, testPurpose, []byte("value"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	execSQL(t, db, `UPDATE secrets SET key_id = ?, nonce = ?, ciphertext = ? WHERE id = ?`, oldID, nonce, ciphertext, string(ref))

	_, err = s.Reveal(ctx, ref, testPurpose)
	requireCode(t, err, problem.Internal)
}

func TestMissingRetiredKeyFails(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	ref := mustPut(t, s, db, testOwner, testPurpose, []byte("value"))

	ring := s.Keys()
	oldID := ring.Primary().ID
	if _, err := ring.Rotate(); err != nil {
		t.Fatalf("Rotate key: %v", err)
	}
	if err := ring.DropRetired(oldID); err != nil {
		t.Fatalf("DropRetired: %v", err)
	}
	_, err := s.Reveal(ctx, ref, testPurpose)
	requireCode(t, err, problem.Internal)
	if !strings.Contains(err.Error(), "not in the key ring") {
		t.Fatalf("error does not name the missing key: %v", err)
	}
}

func TestDeleteOwner(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	keep := mustPut(t, s, db, "users/usr_other", testPurpose, []byte("keep"))
	mustPut(t, s, db, testOwner, testPurpose, []byte("a"))
	mustPut(t, s, db, testOwner, "plugin.config", []byte("b"))

	var deleted int64
	err := db.Update(ctx, func(tx *storage.Tx) error {
		n, err := s.DeleteOwner(ctx, tx, testOwner)
		deleted = n
		return err
	})
	if err != nil {
		t.Fatalf("DeleteOwner: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("DeleteOwner deleted %d rows, want 2", deleted)
	}
	if _, err := s.Reveal(ctx, keep, testPurpose); err != nil {
		t.Fatalf("unrelated secret was deleted: %v", err)
	}
	// Deleting nothing is not an error: cleanup must be idempotent.
	err = db.Update(ctx, func(tx *storage.Tx) error {
		n, err := s.DeleteOwner(ctx, tx, testOwner)
		if n != 0 {
			t.Fatalf("second DeleteOwner deleted %d rows", n)
		}
		return err
	})
	if err != nil {
		t.Fatalf("second DeleteOwner: %v", err)
	}
}

func TestPutValidation(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)

	cases := []struct {
		name    string
		owner   string
		purpose string
		size    int
	}{
		{"empty owner", "", testPurpose, 1},
		{"absolute owner", "/users/usr_01jtestowner0000000000000", testPurpose, 1},
		{"trailing slash", "users/", testPurpose, 1},
		{"double slash", "users//usr", testPurpose, 1},
		{"bad owner character", "users/usr 01", testPurpose, 1},
		{"long owner", "users/" + strings.Repeat("a", maxOwnerLen), testPurpose, 1},
		{"empty purpose", testOwner, "", 1},
		{"purpose with slash", testOwner, "plugin/config", 1},
		{"long purpose", testOwner, strings.Repeat("p", maxPurposeLen+1), 1},
		{"oversize value", testOwner, testPurpose, MaxPlaintext + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := db.Update(ctx, func(tx *storage.Tx) error {
				_, err := s.Put(ctx, tx, tc.owner, tc.purpose, make([]byte, tc.size))
				return err
			})
			requireCode(t, err, problem.ValidationFailed)
		})
	}

	err := db.Update(ctx, func(tx *storage.Tx) error {
		_, err := s.Put(ctx, nil, testOwner, testPurpose, []byte("x"))
		return err
	})
	requireCode(t, err, problem.ValidationFailed)

	if _, err := s.Seal(ctx, "bad purpose", []byte("x")); err == nil {
		t.Fatal("Seal accepted a purpose with a space")
	}
	var count int
	if err := db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("validation failures stored %d rows", count)
	}
}

func TestRotateReencryptsInBatches(t *testing.T) {
	ctx := context.Background()
	s, db, dataDir := newTestStore(t)

	refs := make([]Ref, 0, 5)
	for i := range 5 {
		refs = append(refs, mustPut(t, s, db, testOwner, testPurpose, fmt.Appendf(nil, "value-%d", i)))
	}
	oldID := s.Keys().Primary().ID
	rotated, err := s.Keys().Rotate()
	if err != nil {
		t.Fatalf("Rotate key: %v", err)
	}

	// One row per transaction, to prove a batch boundary does not lose or
	// double-process rows.
	n, err := s.Rotate(ctx, 2)
	if err != nil {
		t.Fatalf("Rotate rows: %v", err)
	}
	if n != int64(len(refs)) {
		t.Fatalf("Rotate rewrote %d rows, want %d", n, len(refs))
	}
	usage, err := s.KeyUsage(ctx)
	if err != nil {
		t.Fatalf("KeyUsage: %v", err)
	}
	if usage[rotated.ID] != int64(len(refs)) || usage[oldID] != 0 {
		t.Fatalf("KeyUsage after rotation = %v", usage)
	}
	for i, ref := range refs {
		secret, err := s.Reveal(ctx, ref, testPurpose)
		if err != nil {
			t.Fatalf("Reveal %d after rotation: %v", i, err)
		}
		if got, want := string(secret.Bytes()), fmt.Sprintf("value-%d", i); got != want {
			t.Fatalf("Reveal %d = %q, want %q", i, got, want)
		}
	}

	// A restart between the key rotation and the row rotation must still work:
	// the old key is on disk as a retired key.
	ring, err := LoadKeyRing(dataDir)
	if err != nil {
		t.Fatalf("reload key ring: %v", err)
	}
	if got := ring.Primary().ID; got != rotated.ID {
		t.Fatalf("reloaded primary key %s, want %s", got, rotated.ID)
	}
	if ids := ring.Retired(); len(ids) != 1 || ids[0] != oldID {
		t.Fatalf("reloaded retired keys %v, want [%s]", ids, oldID)
	}
	restarted, err := New(Options{DB: db, Keys: ring})
	if err != nil {
		t.Fatalf("New after restart: %v", err)
	}
	if _, err := restarted.Reveal(ctx, refs[0], testPurpose); err != nil {
		t.Fatalf("Reveal with the reloaded key ring: %v", err)
	}
}

func TestRotateWithNoStaleRows(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	mustPut(t, s, db, testOwner, testPurpose, []byte("value"))

	n, err := s.Rotate(ctx, 0)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if n != 0 {
		t.Fatalf("Rotate without a new key rewrote %d rows", n)
	}
}

func TestConcurrentSealAndOpen(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)

	const workers = 8
	refs := make([]string, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ref, err := s.Seal(ctx, testPurpose, fmt.Appendf(nil, "value-%d", i))
			if err != nil {
				t.Errorf("Seal: %v", err)
				return
			}
			refs[i] = ref
		}()
	}
	wg.Wait()
	for i, ref := range refs {
		if ref == "" {
			t.Fatalf("worker %d produced no reference", i)
		}
		got, err := s.Open(ctx, ref)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if want := fmt.Sprintf("value-%d", i); string(got) != want {
			t.Fatalf("Open = %q, want %q", got, want)
		}
	}
}

func TestSecretsTableHasNoPlaintext(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	plaintext := []byte("plaintext-must-not-appear")
	ref := mustPut(t, s, db, testOwner, testPurpose, plaintext)

	var row []byte
	rows, err := db.Reader().QueryContext(ctx, `SELECT id || owner || purpose || key_id || hex(nonce) || hex(ciphertext) || created_at FROM secrets WHERE id = ?`, ref)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&row); err != nil {
			t.Fatalf("scan: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if bytes.Contains(row, plaintext) {
		t.Fatalf("stored row contains the plaintext: %q", row)
	}
}
