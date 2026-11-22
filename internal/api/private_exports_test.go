// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/privateexport"
	"golang.org/x/crypto/ssh"
)

func privateExportEnv(t *testing.T) (*env, *privateexport.Service) {
	t.Helper()
	var exports *privateexport.Service
	e := newEnvWith(t, func(deps *api.Deps) {
		var err error
		exports, err = privateexport.New(privateexport.Options{DB: deps.DB, Secrets: deps.Secrets, Clock: deps.Clock, NodeID: deps.NodeID, Authorize: func(context.Context, actor.Actor, privateexport.CreateRequest) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		deps.PrivateExports = exports
	})
	return e, exports
}

func preparedExport(t *testing.T, e *env, exports *privateexport.Service, auth auth) (privateexport.Grant, []byte) {
	t.Helper()
	binding := privateexport.CreateRequest{Action: "security.keys.generate", PluginID: "security.basic", InstanceID: "default", NodeID: "local", Purpose: privateexport.SSHPrivateKey, Subject: "account/alice/keys"}
	body, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	var grant privateexport.Grant
	e.do(auth.sign(http.MethodPost, "/api/v1/private-exports", string(body))).expect(t, http.StatusCreated).decode(t, &grant)
	call := privateexport.Caller{ExportID: grant.ID, Binding: binding, Actor: actor.Actor{Kind: actor.Human, ID: auth.userID}, OperationID: ids.New(nil).New(ids.Operation)}
	if _, err := exports.Reserve(t.Context(), call); err != nil {
		t.Fatal(err)
	}
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
	material := privateexport.KeyMaterial{PublicKey: string(ssh.MarshalAuthorizedKey(key)), Fingerprint: ssh.FingerprintSHA256(key), Type: "ed25519", Bits: 256}
	if _, err := exports.StoreMaterial(t.Context(), call, raw, material); err != nil {
		t.Fatal(err)
	}
	if err := exports.Finish(t.Context(), call, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	return grant, raw
}

func TestPrivateExportHttpIsOriginalSessionOnlyAndBinaryOnce(t *testing.T) {
	e, exports := privateExportEnv(t)
	owner := e.setupAdmin(adminUser)
	grant, raw := preparedExport(t, e, exports, owner)
	defer clear(raw)
	path := "/api/v1/private-exports/" + grant.ID + "/consume"
	secondSession := e.login(adminUser, adminPass)
	e.do(secondSession.sign(http.MethodPost, path, "")).expect(t, http.StatusNotFound)
	missingCSRF := owner.sign(http.MethodPost, path, "")
	missingCSRF.Header.Del("X-CSRF-Token")
	e.do(missingCSRF).expect(t, http.StatusForbidden)
	response := e.do(owner.sign(http.MethodPost, path, ""))
	defer clear(response.body)
	if response.status != http.StatusOK || response.header.Get("Content-Type") != "application/octet-stream" || response.header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(response.header.Get("Content-Disposition"), "attachment;") || !bytes.Equal(response.body, raw) {
		t.Fatal("private export was not a controlled binary download")
	}
	e.do(owner.sign(http.MethodPost, path, "")).expect(t, http.StatusNotFound)
}

func TestPrivateExportHttpCancelAndMissingSession(t *testing.T) {
	e, exports := privateExportEnv(t)
	owner := e.setupAdmin(adminUser)
	grant, raw := preparedExport(t, e, exports, owner)
	clear(raw)
	path := "/api/v1/private-exports/" + grant.ID
	e.do(newRequest(http.MethodDelete, path, "")).expect(t, http.StatusUnauthorized)
	e.do(owner.sign(http.MethodDelete, path, "")).expect(t, http.StatusNoContent)
	e.do(owner.sign(http.MethodPost, path+"/consume", "")).expect(t, http.StatusNotFound)
}
