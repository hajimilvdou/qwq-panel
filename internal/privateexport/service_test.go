// SPDX-License-Identifier: AGPL-3.0-only

package privateexport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	"golang.org/x/crypto/ssh"
)

type testFixture struct {
	service     *Service
	db          *storage.DB
	secrets     *secrets.Store
	clock       *clock.Fake
	user, other actor.Actor
	request     CreateRequest
	revoked     atomic.Bool
}

func fixture(t *testing.T) *testFixture {
	t.Helper()
	root := t.TempDir()
	f := &testFixture{clock: clock.NewFake(time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC))}
	db, err := storage.Open(t.Context(), storage.Options{Path: filepath.Join(root, "qwq.db"), Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	f.db = db
	t.Cleanup(func() { _ = db.Close() })
	keys, err := secrets.LoadKeyRing(root)
	if err != nil {
		t.Fatal(err)
	}
	f.secrets, err = secrets.New(secrets.Options{DB: db, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	generator := ids.New(f.clock.Now)
	f.user = actor.Actor{Kind: actor.Human, ID: generator.New(ids.User), SessionID: generator.New(ids.Session)}
	f.other = actor.Actor{Kind: actor.Human, ID: generator.New(ids.User), SessionID: generator.New(ids.Session)}
	err = db.Update(t.Context(), func(tx *storage.Tx) error {
		stamp, expires := storage.FormatTime(f.clock.Now()), storage.FormatTime(f.clock.Now().Add(time.Hour))
		for index, principal := range []actor.Actor{f.user, f.other} {
			name := "alice"
			if index == 1 {
				name = "bob"
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO users(user_id,username,role,created_at,updated_at) VALUES (?,?,'admin',?,?)`, principal.ID, name, stamp, stamp); err != nil {
				return err
			}
			digest := []byte(principal.SessionID)
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO sessions(session_id,user_id,token_hash,csrf_token,created_at,last_seen_at,idle_expires_at,expires_at,client_ip)
				VALUES (?,?,?,'TEST-ONLY-csrf',?,?,?,?,'192.0.2.1')`, principal.SessionID, principal.ID, digest, stamp, stamp, expires, expires); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f.request = CreateRequest{Action: "security.keys.generate", PluginID: "security.basic", InstanceID: "default", NodeID: "local", Purpose: SSHPrivateKey, Subject: "account/alice/keys"}
	f.service, err = New(Options{DB: db, Secrets: f.secrets, Clock: f.clock, Authorize: func(context.Context, actor.Actor, CreateRequest) error {
		if f.revoked.Load() {
			return problem.New(problem.PermissionDenied, "TEST-ONLY permission revoked")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func makeMaterial(t *testing.T) ([]byte, KeyMaterial) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "qwq generated")
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(block)
	clear(block.Bytes)
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return raw, KeyMaterial{PublicKey: string(ssh.MarshalAuthorizedKey(key)), Fingerprint: ssh.FingerprintSHA256(key), Type: "ed25519", Bits: 256}
}

func prepare(t *testing.T, f *testFixture) (Caller, []byte) {
	t.Helper()
	grant, err := f.service.Create(t.Context(), f.user, f.request)
	if err != nil {
		t.Fatal(err)
	}
	call := Caller{ExportID: grant.ID, Binding: f.request, Actor: actor.Actor{Kind: actor.Human, ID: f.user.ID}, OperationID: ids.New(nil).New(ids.Operation)}
	if _, err := f.service.Reserve(t.Context(), call); err != nil {
		t.Fatal(err)
	}
	raw, material := makeMaterial(t)
	if _, err := f.service.StoreMaterial(t.Context(), call, raw, material); err != nil {
		t.Fatal(err)
	}
	return call, raw
}

func TestPrivateExportIsSessionBoundAndOneTime(t *testing.T) {
	f := fixture(t)
	call, raw := prepare(t, f)
	defer clear(raw)
	if err := f.service.Finish(t.Context(), call, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Consume(t.Context(), f.other, call.ExportID); err == nil {
		t.Fatal("foreign owner consumed export")
	}
	otherSession := f.user
	otherSession.SessionID = f.other.SessionID
	if _, err := f.service.Consume(t.Context(), otherSession, call.ExportID); err == nil {
		t.Fatal("foreign human session consumed export")
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range 12 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			secret, err := f.service.Consume(context.Background(), f.user, call.ExportID)
			if err == nil {
				defer secret.Clear()
				value := secret.Bytes()
				defer clear(value)
				if !bytes.Equal(value, raw) {
					t.Error("wrong private export material")
				}
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatal("private material was not consumed exactly once")
	}
	var count int
	if err := f.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM secrets WHERE purpose='private.export'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("consumed private ciphertext retained")
	}
}

func TestMaterialSurvivesRestartAndPublicJSONContainsNoSecret(t *testing.T) {
	f := fixture(t)
	call, raw := prepare(t, f)
	defer clear(raw)
	restarted, err := New(Options{DB: f.db, Secrets: f.secrets, Clock: f.clock, Authorize: func(context.Context, actor.Actor, CreateRequest) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	material, err := restarted.Reserve(t.Context(), call)
	if err != nil || material.PublicKey == "" {
		t.Fatal("interrupted material could not be reused")
	}
	encoded, err := json.Marshal(material)
	if err != nil || bytes.Contains(encoded, raw) || strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(encoded), "sec_") {
		t.Fatal("private material or internal secret reference escaped public output")
	}
	var stored string
	if err := f.db.Reader().QueryRowContext(t.Context(), `SELECT material_json FROM private_exports WHERE export_id=?`, call.ExportID).Scan(&stored); err != nil || strings.Contains(stored, "PRIVATE KEY") {
		t.Fatal("plaintext PEM persisted in export metadata")
	}
	if err := restarted.Finish(t.Context(), call, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredRevokedAndForeignProducerExportsAreRejected(t *testing.T) {
	f := fixture(t)
	call, raw := prepare(t, f)
	defer clear(raw)
	foreign := call
	foreign.Binding.PluginID = "other.plugin"
	if _, err := f.service.Reserve(t.Context(), foreign); err == nil {
		t.Fatal("foreign producer claimed grant")
	}
	foreign = call
	foreign.OperationID = ids.New(nil).New(ids.Operation)
	if _, err := f.service.Reserve(t.Context(), foreign); err == nil {
		t.Fatal("different operation reused reservation")
	}
	if err := f.service.Finish(t.Context(), call, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	f.revoked.Store(true)
	if _, err := f.service.Consume(t.Context(), f.user, call.ExportID); err == nil {
		t.Fatal("revoked authorization consumed private material")
	}
	f.revoked.Store(false)
	f.clock.Advance(6 * time.Minute)
	if _, err := f.service.Consume(t.Context(), f.user, call.ExportID); err == nil {
		t.Fatal("expired grant consumed private material")
	}
	if _, err := f.service.Create(t.Context(), f.user, f.request); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM secrets WHERE purpose='private.export'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired private ciphertext not reclaimed")
	}
}

func TestSessionDeletionCleansPrivateCiphertext(t *testing.T) {
	f := fixture(t)
	_, raw := prepare(t, f)
	clear(raw)
	if err := f.db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM sessions WHERE session_id=?`, f.user.SessionID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM secrets WHERE purpose='private.export'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("session deletion left an orphan private ciphertext")
	}
}
