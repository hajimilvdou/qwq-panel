// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

const materialOwner = "plugins/tls.certificates/owners/owner-1/certificates/certificate-1"
const materialPurpose = "certificate.material.attempt-1"

func ensureMaterial(t *testing.T, s *Store, db *storage.DB, value string) Ref {
	t.Helper()
	var ref Ref
	if err := db.Update(context.Background(), func(tx *storage.Tx) error {
		var err error
		ref, err = s.EnsureOwned(context.Background(), tx, materialOwner, materialPurpose, []byte(value))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestEnsureOwnedResponseLossFindsSameMaterial(t *testing.T) {
	s, db, _ := newTestStore(t)
	first := ensureMaterial(t, s, db, "test-material")
	found, exists, err := s.FindOwned(context.Background(), materialOwner, materialPurpose)
	if err != nil || !exists || found != first {
		t.Fatalf("owned lookup = %v, %v", exists, err)
	}
	second := ensureMaterial(t, s, db, "test-material")
	if first != second {
		t.Fatal("same attempt replaced existing material")
	}
	var inTransaction Ref
	if err := db.Update(context.Background(), func(tx *storage.Tx) error {
		one, err := s.EnsureOwned(context.Background(), tx, materialOwner, "certificate.material.attempt-2", []byte("same"))
		if err != nil {
			return err
		}
		inTransaction, err = s.EnsureOwned(context.Background(), tx, materialOwner, "certificate.material.attempt-2", []byte("same"))
		if inTransaction != one {
			t.Fatal("same transaction created duplicate material")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureOwnedDifferentContentAndRollback(t *testing.T) {
	s, db, _ := newTestStore(t)
	first := ensureMaterial(t, s, db, "first")
	err := db.Update(context.Background(), func(tx *storage.Tx) error {
		_, err := s.EnsureOwned(context.Background(), tx, materialOwner, materialPurpose, []byte("different"))
		return err
	})
	requireCode(t, err, problem.StateConflict)
	secret, err := s.RevealOwned(context.Background(), first, materialOwner, materialPurpose)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Clear()
	if string(secret.Bytes()) != "first" {
		t.Fatal("conflict changed material")
	}
	rollback := errors.New("rollback")
	err = db.Update(context.Background(), func(tx *storage.Tx) error {
		if _, err := s.EnsureOwned(context.Background(), tx, materialOwner, "certificate.material.rollback", []byte("orphan")); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if _, found, err := s.FindOwned(context.Background(), materialOwner, "certificate.material.rollback"); err != nil || found {
		t.Fatal("rolled-back material survived")
	}
}

func TestEnsureOwnedConcurrentSameAndDifferentContents(t *testing.T) {
	s, db, _ := newTestStore(t)
	for _, different := range []bool{false, true} {
		purpose := "certificate.material.concurrent-same"
		if different {
			purpose = "certificate.material.concurrent-different"
		}
		var wait sync.WaitGroup
		results := make(chan error, 8)
		refs := make(chan Ref, 8)
		for index := 0; index < 8; index++ {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				value := "shared"
				if different && index%2 != 0 {
					value = "other"
				}
				var ref Ref
				err := db.Update(context.Background(), func(tx *storage.Tx) error {
					var err error
					ref, err = s.EnsureOwned(context.Background(), tx, materialOwner, purpose, []byte(value))
					return err
				})
				if err == nil {
					refs <- ref
				}
				results <- err
			}(index)
		}
		wait.Wait()
		close(results)
		close(refs)
		var reference Ref
		for ref := range refs {
			if reference != "" && ref != reference {
				t.Fatal("concurrent save created duplicate rows")
			}
			reference = ref
		}
		conflicts := 0
		for err := range results {
			if err != nil {
				requireCode(t, err, problem.StateConflict)
				conflicts++
			}
		}
		if (different && conflicts != 4) || (!different && conflicts != 0) {
			t.Fatalf("conflicts = %d", conflicts)
		}
	}
}

func TestFindOwnedRejectsAmbiguousExistingRowsAndForeignScopes(t *testing.T) {
	s, db, _ := newTestStore(t)
	first := mustPut(t, s, db, materialOwner, materialPurpose, []byte("first"))
	if _, exists, err := s.FindOwned(context.Background(), "plugins/another", materialPurpose); err != nil || exists {
		t.Fatal("foreign owner saw material")
	}
	if _, exists, err := s.FindOwned(context.Background(), materialOwner, "plugin.config"); err != nil || exists {
		t.Fatal("foreign purpose saw material")
	}
	if _, err := s.RevealOwned(context.Background(), first, "plugins/another", materialPurpose); !problem.HasCode(err, problem.NotFound) {
		t.Fatal("foreign owner revealed material")
	}
	mustPut(t, s, db, materialOwner, materialPurpose, []byte("second"))
	_, _, err := s.FindOwned(context.Background(), materialOwner, materialPurpose)
	requireCode(t, err, problem.StateConflict)
	err = db.Update(context.Background(), func(tx *storage.Tx) error {
		_, err := s.EnsureOwned(context.Background(), tx, materialOwner, materialPurpose, []byte("first"))
		return err
	})
	requireCode(t, err, problem.StateConflict)
}

func TestOwnedMaterialCancellationWritesNothing(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.FindOwned(ctx, materialOwner, materialPurpose); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled lookup continued")
	}
	err := db.Update(context.Background(), func(tx *storage.Tx) error {
		_, err := s.EnsureOwned(ctx, tx, materialOwner, materialPurpose, []byte("cancelled"))
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled write continued")
	}
	if _, found, err := s.FindOwned(context.Background(), materialOwner, materialPurpose); err != nil || found {
		t.Fatal("cancelled material was committed")
	}
}
