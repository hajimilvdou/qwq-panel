// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/storage"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 真实 SQLite 快照与 HostSvc 逐次认证 ========================

func beginCredentialSaga(t *testing.T, tokens controller.PluginTokens, pluginID, sagaID string) {
	t.Helper()
	if err := tokens.DB.Update(t.Context(), func(tx *storage.Tx) error {
		now := storage.FormatTime(tx.Now())
		_, err := tx.ExecContext(t.Context(), `INSERT INTO plugin_update_sagas
			(saga_id, plugin_id, from_version, to_version, mode, strategy, state, step, error, created_at, updated_at)
			VALUES (?, ?, '1.0.0', '2.0.0', 'update', 'restart', 'RUNNING', 'install', '', ?, ?)`, sagaID, pluginID, now, now)
		if err != nil {
			return err
		}
		return tokens.BeginRotationTx(t.Context(), tx, pluginID)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDualTokenWindow(t *testing.T) {
	db, err := storage.Open(t.Context(), storage.Options{Path: filepath.Join(t.TempDir(), "credentials.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tokens := controller.PluginTokens{DB: db}
	previous := "TEST-ONLY-" + strings.Repeat("a", 34)
	first := "TEST-ONLY-" + strings.Repeat("b", 34)
	current := "TEST-ONLY-" + strings.Repeat("c", 34)
	foreign := "TEST-ONLY-" + strings.Repeat("d", 34)
	put := func(pluginID, token string) {
		t.Helper()
		if err := tokens.Put(t.Context(), pluginID, []byte(token)); err != nil {
			t.Fatal(err)
		}
	}
	put("alpha", previous)
	put("beta", foreign)
	ts := startServer(t, func(cfg *hostsvc.Config) {
		cfg.PluginID = "alpha"
		cfg.TokenDigests = func(ctx context.Context) ([][]byte, error) { return tokens.Digests(ctx, "alpha") }
	})
	call := func(values ...string) error {
		ctx, cancel := rpcContext(t)
		defer cancel()
		for _, value := range values {
			ctx = metadata.AppendToOutgoingContext(ctx, pluginsdk.HostTokenMetadataKey, value)
		}
		_, err := ts.State().GetState(ctx, &platformv1.GetStateRequest{Context: callContext(), Key: "k"})
		return err
	}
	wantOK(t, call(previous), "initial current token")
	beginCredentialSaga(t, tokens, "alpha", "sag_alpha_window")
	put("alpha", first)
	wantOK(t, call(previous), "previous token during rotation")
	wantOK(t, call(first), "candidate token during rotation")
	put("alpha", current)
	wantOK(t, call(previous), "original token after repeated issue")
	wantOK(t, call(current), "latest candidate token")
	for _, values := range [][]string{nil, {foreign}, {first}, {previous, current}} {
		wantCode(t, call(values...), codes.Unauthenticated, "foreign, retired, missing or duplicate token")
	}
	if err := db.Update(t.Context(), func(tx *storage.Tx) error {
		if err := tokens.FinishRotationTx(t.Context(), tx, "alpha"); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `UPDATE plugin_update_sagas SET state = 'COMMITTED' WHERE saga_id = 'sag_alpha_window'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	wantOK(t, call(current), "committed current token")
	wantCode(t, call(previous), codes.Unauthenticated, "previous token after commit")
	beginCredentialSaga(t, tokens, "alpha", "sag_alpha_failed")
	put("alpha", first)
	if err := db.Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE plugin_update_sagas SET state = 'FAILED' WHERE saga_id = 'sag_alpha_failed'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	beginCredentialSaga(t, tokens, "beta", "sag_beta_window")
	wantOK(t, call(first), "failed saga retains only its current token")
	wantCode(t, call(current), codes.Unauthenticated, "foreign running saga must not reopen alpha's previous slot")
}

func TestDualTokenBadSnapshots(t *testing.T) {
	good := "TEST-ONLY-" + strings.Repeat("e", 34)
	digest := sha256.Sum256([]byte(good))
	for _, test := range []struct {
		name     string
		snapshot [][]byte
		err      error
	}{
		{name: "empty"},
		{name: "third", snapshot: [][]byte{digest[:], digest[:], digest[:]}},
		{name: "invalid", snapshot: [][]byte{digest[:], {1}}},
		{name: "storage", err: errors.New("TEST-ONLY-storage-failure")},
	} {
		t.Run(test.name, func(t *testing.T) {
			ts := startServer(t, func(cfg *hostsvc.Config) {
				cfg.TokenDigests = func(context.Context) ([][]byte, error) { return test.snapshot, test.err }
			})
			ctx, cancel := rpcContext(t)
			defer cancel()
			ctx = metadata.AppendToOutgoingContext(ctx, pluginsdk.HostTokenMetadataKey, good)
			_, err := ts.State().GetState(ctx, &platformv1.GetStateRequest{Context: callContext(), Key: "k"})
			wantCode(t, err, codes.Unauthenticated, "invalid credential snapshot")
		})
	}
}

func TestDualTokenPeerGate(t *testing.T) {
	good := "TEST-ONLY-" + strings.Repeat("f", 34)
	digest := sha256.Sum256([]byte(good))
	b := newBundle()
	b.peer.deny = true
	ts := startServerWith(t, b, func(cfg *hostsvc.Config) {
		cfg.TokenDigests = func(context.Context) ([][]byte, error) { return [][]byte{digest[:], digest[:]}, nil }
	})
	ctx, cancel := rpcContext(t)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, pluginsdk.HostTokenMetadataKey, good)
	_, err := ts.Secrets().RevealSecret(ctx, &platformv1.RevealSecretRequest{Context: callContext(), SecretRef: "sec_abc"})
	if err == nil || len(b.secrets.callsSnapshot()) != 0 {
		t.Fatal("a matching token snapshot bypassed the mandatory peer verification")
	}
}
